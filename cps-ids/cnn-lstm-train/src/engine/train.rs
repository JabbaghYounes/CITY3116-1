//! Training orchestrator for CNN+LSTM IDS classification.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tch::Device;
use tracing::info;

use crate::preprocess::{
    load_cicids2017, load_nsl_kdd, load_unsw_nb15, merge_datasets, smote, DatasetSplit,
    MinMaxScaler,
};

use super::evaluate::{evaluate, print_report, ClassificationReport};
use super::model::CnnLstmConfig;
use super::trainer::{
    batched_predict, labels_to_tensor, ndarray_to_tensor, train_model, TrainMetrics, TrainerConfig,
};

#[derive(Debug, Clone)]
pub enum DatasetSource {
    NslKdd {
        train_path: PathBuf,
        test_path: PathBuf,
    },
    CicIds2017 {
        csv_dir: PathBuf,
    },
    UnswNb15 {
        data_path: PathBuf,
        label_path: PathBuf,
    },
    Combined {
        nsl_train: PathBuf,
        nsl_test: PathBuf,
        cicids_dir: PathBuf,
        unsw_data: PathBuf,
        unsw_label: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct TrainConfig {
    pub model_output: PathBuf,
    pub scaler_output: PathBuf,
    pub report_output: PathBuf,
    pub use_smote: bool,
    pub smote_target: usize,
    pub trainer: TrainerConfig,
    pub lstm_hidden: i64,
    pub lstm_layers: i64,
    pub dropout: f64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            model_output: PathBuf::from("data/models/cnn_lstm_model.pt"),
            scaler_output: PathBuf::from("data/models/scaler.json"),
            report_output: PathBuf::from("results/evaluation_report.json"),
            use_smote: true,
            smote_target: 0,
            trainer: TrainerConfig::default(),
            lstm_hidden: 128,
            lstm_layers: 2,
            dropout: 0.3,
        }
    }
}

#[derive(Debug)]
pub struct TrainResult {
    pub report: ClassificationReport,
    pub metrics: TrainMetrics,
    pub n_features: usize,
    pub n_train_samples: usize,
}

pub fn load_dataset(source: &DatasetSource) -> Result<DatasetSplit> {
    match source {
        DatasetSource::NslKdd {
            train_path,
            test_path,
        } => {
            info!("Loading NSL-KDD dataset");
            load_nsl_kdd(train_path, test_path)
        }
        DatasetSource::CicIds2017 { csv_dir } => {
            info!("Loading CIC-IDS2017 dataset");
            load_cicids2017(csv_dir)
        }
        DatasetSource::UnswNb15 {
            data_path,
            label_path,
        } => {
            info!("Loading UNSW-NB15 dataset");
            load_unsw_nb15(data_path, label_path)
        }
        DatasetSource::Combined {
            nsl_train,
            nsl_test,
            cicids_dir,
            unsw_data,
            unsw_label,
        } => {
            info!("Loading combined dataset (NSL-KDD + CIC-IDS2017 + UNSW-NB15)");
            let nsl = load_nsl_kdd(nsl_train, nsl_test)?;
            let cic = load_cicids2017(cicids_dir)?;
            let unsw = load_unsw_nb15(unsw_data, unsw_label)?;
            merge_datasets(&[("nsl", &nsl), ("cic", &cic), ("unsw", &unsw)])
        }
    }
}

pub fn run_training(source: DatasetSource, config: TrainConfig) -> Result<TrainResult> {
    let split = load_dataset(&source)?;

    let n_classes = split.label_names.len();
    let n_features = split.x_train.ncols();

    info!(
        "Dataset loaded: {} train, {} val, {} test, {} features, {} classes",
        split.x_train.nrows(),
        split.x_val.nrows(),
        split.x_test.nrows(),
        n_features,
        n_classes,
    );

    // Normalize
    let mut scaler = MinMaxScaler::new();
    let x_train_scaled = scaler.fit_transform(&split.x_train);
    let x_val_scaled = scaler.transform(&split.x_val);
    let x_test_scaled = scaler.transform(&split.x_test);

    // Optional SMOTE
    let (x_train_final, y_train_final) = if config.use_smote {
        let target = if config.smote_target == 0 {
            let dist = crate::preprocess::dataset::class_distribution(&split.y_train);
            *dist.values().max().unwrap_or(&1000)
        } else {
            config.smote_target
        };
        info!("applying SMOTE with target_count={}", target);
        let (aug_x, aug_y) = smote(&x_train_scaled, &split.y_train, target, 5);
        info!("after SMOTE: {} samples", aug_x.nrows());
        (aug_x, aug_y)
    } else {
        (x_train_scaled.clone(), split.y_train.clone())
    };

    let n_train_samples = x_train_final.nrows();

    // Select device
    let device = Device::cuda_if_available();
    info!("using device: {:?}", device);

    // Convert to tensors
    info!("converting data to tensors...");
    let x_train_t = ndarray_to_tensor(&x_train_final, device);
    let y_train_t = labels_to_tensor(&y_train_final, device);
    let x_val_t = ndarray_to_tensor(&x_val_scaled, device);
    let y_val_t = labels_to_tensor(&split.y_val, device);
    let x_test_t = ndarray_to_tensor(&x_test_scaled, device);

    // Model config
    let model_cfg = CnnLstmConfig {
        n_features: n_features as i64,
        n_classes: n_classes as i64,
        lstm_hidden: config.lstm_hidden,
        lstm_layers: config.lstm_layers,
        dropout: config.dropout,
        ..Default::default()
    };

    info!(
        "CNN+LSTM: {} features, {} classes, hidden={}, layers={}, dropout={}",
        n_features, n_classes, config.lstm_hidden, config.lstm_layers, config.dropout,
    );

    // Train
    let (vs, metrics) = train_model(
        &model_cfg,
        &config.trainer,
        &x_train_t,
        &y_train_t,
        &x_val_t,
        &y_val_t,
        device,
    )?;

    // Evaluate on test set
    info!(
        "evaluating on test set ({} samples)...",
        split.x_test.nrows()
    );
    let preds = batched_predict(&vs, &model_cfg, &x_test_t, config.trainer.batch_size);
    let report = evaluate(&split.y_test, &preds, n_classes);

    println!("\n=== CNN+LSTM Test Results ===");
    print_report(&report, &split.label_names);

    // Save model, scaler, and report
    info!("saving artifacts...");

    if let Some(parent) = config.model_output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.report_output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    vs.save(&config.model_output)
        .context("failed to save model weights")?;
    info!("  model saved to {}", config.model_output.display());

    scaler
        .save(&config.scaler_output)
        .context("failed to save scaler")?;
    info!("  scaler saved to {}", config.scaler_output.display());

    let report_json = serde_json::json!({
        "cnn_lstm": report,
        "training_metrics": {
            "best_epoch": metrics.best_epoch + 1,
            "best_val_loss": metrics.best_val_loss,
            "final_val_accuracy": metrics.val_accuracies.last().copied().unwrap_or(0.0),
            "train_losses": metrics.train_losses,
            "val_losses": metrics.val_losses,
            "val_accuracies": metrics.val_accuracies,
        },
        "model_config": {
            "n_features": n_features,
            "n_classes": n_classes,
            "lstm_hidden": config.lstm_hidden,
            "lstm_layers": config.lstm_layers,
            "dropout": config.dropout,
            "batch_size": config.trainer.batch_size,
            "learning_rate": config.trainer.learning_rate,
        },
        "dataset": format!("{:?}", source),
        "n_train_samples": n_train_samples,
    });
    std::fs::write(
        &config.report_output,
        serde_json::to_string_pretty(&report_json)?,
    )?;
    info!("  report saved to {}", config.report_output.display());

    info!("training complete.");

    Ok(TrainResult {
        report,
        metrics,
        n_features,
        n_train_samples,
    })
}
