//! Training loop, tensor conversion helpers, and batched inference.

use anyhow::Result;
use ndarray::{Array1, Array2};
use tch::{nn, nn::OptimizerConfig, Device, Kind, Tensor};
use tracing::info;

use super::model::{CnnLstm, CnnLstmConfig};

/// Hyperparameters for the training loop.
#[derive(Debug, Clone)]
pub struct TrainerConfig {
    pub batch_size: i64,
    pub epochs: i64,
    pub learning_rate: f64,
    pub patience: i64,
    pub lr_decay_factor: f64,
    pub lr_decay_patience: i64,
    pub lr_floor: f64,
}

impl Default for TrainerConfig {
    fn default() -> Self {
        Self {
            batch_size: 512,
            epochs: 50,
            learning_rate: 1e-3,
            patience: 5,
            lr_decay_factor: 0.5,
            lr_decay_patience: 3,
            lr_floor: 1e-6,
        }
    }
}

/// Metrics collected during training.
#[derive(Debug, Clone)]
pub struct TrainMetrics {
    pub train_losses: Vec<f64>,
    pub val_losses: Vec<f64>,
    pub val_accuracies: Vec<f64>,
    pub best_epoch: i64,
    pub best_val_loss: f64,
}

// ---------------------------------------------------------------------------
// Tensor conversion helpers
// ---------------------------------------------------------------------------

/// Convert an ndarray Array2<f64> to a tch Tensor (Float / f32) on the given device.
pub fn ndarray_to_tensor(arr: &Array2<f64>, device: Device) -> Tensor {
    let (rows, cols) = (arr.nrows() as i64, arr.ncols() as i64);
    let data: Vec<f32> = arr.iter().map(|&v| v as f32).collect();
    Tensor::from_slice(&data)
        .reshape([rows, cols])
        .to_device(device)
}

/// Convert an ndarray Array1<usize> of labels to a tch Tensor (Int64) on the given device.
pub fn labels_to_tensor(labels: &Array1<usize>, device: Device) -> Tensor {
    let data: Vec<i64> = labels.iter().map(|&v| v as i64).collect();
    Tensor::from_slice(&data).to_device(device)
}

/// Convert logits tensor to ndarray Array1<usize> predictions (argmax).
pub fn tensor_to_predictions(logits: &Tensor) -> Array1<usize> {
    let preds: Vec<i64> = logits.argmax(1, false).to_kind(Kind::Int64).into();
    Array1::from(preds.into_iter().map(|v| v as usize).collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// Training
// ---------------------------------------------------------------------------

/// Train a CNN+LSTM model, returning the VarStore (with best weights) and metrics.
pub fn train_model(
    model_cfg: &CnnLstmConfig,
    trainer_cfg: &TrainerConfig,
    x_train: &Tensor,
    y_train: &Tensor,
    x_val: &Tensor,
    y_val: &Tensor,
    device: Device,
) -> Result<(nn::VarStore, TrainMetrics)> {
    let mut vs = nn::VarStore::new(device);
    let model = CnnLstm::new(&vs.root(), model_cfg);
    let mut opt = nn::Adam::default().build(&vs, trainer_cfg.learning_rate)?;

    let n_train = x_train.size()[0];
    let n_batches = (n_train + trainer_cfg.batch_size - 1) / trainer_cfg.batch_size;

    let mut train_losses = Vec::new();
    let mut val_losses = Vec::new();
    let mut val_accuracies = Vec::new();

    let mut best_val_loss = f64::MAX;
    let mut best_epoch: i64 = 0;
    let mut epochs_no_improve: i64 = 0;
    let mut lr_no_improve: i64 = 0;
    let mut current_lr = trainer_cfg.learning_rate;

    // Save best weights to a temp file
    let best_weights = std::env::temp_dir().join(format!(
        "cnn_lstm_best_{}.pt",
        std::process::id()
    ));

    info!(
        "training: {} samples, {} batches/epoch, device={:?}",
        n_train, n_batches, device
    );

    for epoch in 0..trainer_cfg.epochs {
        // --- Shuffle ---
        let perm = Tensor::randperm(n_train, (Kind::Int64, device));
        let x_shuffled = x_train.index_select(0, &perm);
        let y_shuffled = y_train.index_select(0, &perm);

        // --- Train epoch ---
        let mut epoch_loss = 0.0_f64;
        for b in 0..n_batches {
            let start = b * trainer_cfg.batch_size;
            let len = std::cmp::min(trainer_cfg.batch_size, n_train - start);

            let xb = x_shuffled.narrow(0, start, len);
            let yb = y_shuffled.narrow(0, start, len);

            let logits = model.forward_t(&xb, true);
            let loss = logits.cross_entropy_for_logits(&yb);

            opt.backward_step(&loss);
            epoch_loss += f64::try_from(&loss).unwrap_or(0.0);
        }
        let avg_train_loss = epoch_loss / n_batches as f64;
        train_losses.push(avg_train_loss);

        // --- Validate ---
        let (val_loss, val_acc) = tch::no_grad(|| {
            let val_logits = batched_forward(&model, x_val, trainer_cfg.batch_size, false);
            let vl = val_logits.cross_entropy_for_logits(y_val);
            let preds = val_logits.argmax(1, false);
            let correct = preds.eq_tensor(y_val).to_kind(Kind::Float).sum(Kind::Float);
            let acc = f64::try_from(&correct).unwrap_or(0.0) / x_val.size()[0] as f64;
            (f64::try_from(&vl).unwrap_or(0.0), acc)
        });
        val_losses.push(val_loss);
        val_accuracies.push(val_acc);

        info!(
            "epoch {}/{}: train_loss={:.4}, val_loss={:.4}, val_acc={:.4}, lr={:.2e}",
            epoch + 1,
            trainer_cfg.epochs,
            avg_train_loss,
            val_loss,
            val_acc,
            current_lr,
        );

        // --- Early stopping + LR decay ---
        if val_loss < best_val_loss {
            best_val_loss = val_loss;
            best_epoch = epoch;
            epochs_no_improve = 0;
            lr_no_improve = 0;
            vs.save(&best_weights).ok();
        } else {
            epochs_no_improve += 1;
            lr_no_improve += 1;

            // Reduce LR on plateau
            if lr_no_improve >= trainer_cfg.lr_decay_patience && current_lr > trainer_cfg.lr_floor {
                current_lr = (current_lr * trainer_cfg.lr_decay_factor).max(trainer_cfg.lr_floor);
                opt.set_lr(current_lr);
                lr_no_improve = 0;
                info!("reducing learning rate to {:.2e}", current_lr);
            }

            if epochs_no_improve >= trainer_cfg.patience {
                info!(
                    "early stopping at epoch {} (best epoch {})",
                    epoch + 1,
                    best_epoch + 1
                );
                break;
            }
        }
    }

    // Reload best weights
    if best_weights.exists() {
        vs.load(&best_weights).ok();
        std::fs::remove_file(&best_weights).ok();
    }

    info!(
        "best epoch: {}, val_loss={:.4}, val_acc={:.4}",
        best_epoch + 1,
        best_val_loss,
        val_accuracies.get(best_epoch as usize).copied().unwrap_or(0.0),
    );

    let metrics = TrainMetrics {
        train_losses,
        val_losses,
        val_accuracies,
        best_epoch,
        best_val_loss,
    };

    Ok((vs, metrics))
}

// ---------------------------------------------------------------------------
// Batched inference
// ---------------------------------------------------------------------------

/// Run forward pass in batches (no_grad context expected by caller).
fn batched_forward(model: &CnnLstm, x: &Tensor, batch_size: i64, train: bool) -> Tensor {
    let n = x.size()[0];
    if n <= batch_size {
        return model.forward_t(x, train);
    }

    let mut outputs = Vec::new();
    let mut start = 0i64;
    while start < n {
        let len = std::cmp::min(batch_size, n - start);
        let xb = x.narrow(0, start, len);
        outputs.push(model.forward_t(&xb, train));
        start += len;
    }
    Tensor::cat(&outputs, 0)
}

/// Batched prediction returning ndarray labels.
pub fn batched_predict(
    vs: &nn::VarStore,
    model_cfg: &CnnLstmConfig,
    x: &Tensor,
    batch_size: i64,
) -> Array1<usize> {
    let model = CnnLstm::new(&vs.root(), model_cfg);
    tch::no_grad(|| {
        let logits = batched_forward(&model, x, batch_size, false);
        tensor_to_predictions(&logits)
    })
}
