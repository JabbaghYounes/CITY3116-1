mod engine;
mod preprocess;

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use engine::train::{run_training, DatasetSource, TrainConfig};
use engine::trainer::TrainerConfig;

#[derive(Parser, Debug)]
#[command(name = "train-cnn-lstm")]
#[command(about = "CNN+LSTM IDS model training (tch-rs / libtorch)")]
struct Args {
    /// Dataset to use: nsl-kdd, cicids2017, unsw-nb15, combined
    #[arg(short, long)]
    dataset: String,

    /// NSL-KDD training file path
    #[arg(long)]
    nsl_train: Option<PathBuf>,

    /// NSL-KDD test file path
    #[arg(long)]
    nsl_test: Option<PathBuf>,

    /// CIC-IDS2017 CSV directory
    #[arg(long)]
    cicids_dir: Option<PathBuf>,

    /// UNSW-NB15 Data.csv path
    #[arg(long)]
    unsw_data: Option<PathBuf>,

    /// UNSW-NB15 Label.csv path
    #[arg(long)]
    unsw_label: Option<PathBuf>,

    /// Output directory for model and reports
    #[arg(short, long, default_value = "data/models")]
    output_dir: PathBuf,

    /// Disable SMOTE oversampling
    #[arg(long, default_value_t = false)]
    no_smote: bool,

    /// SMOTE target count per class (0 = auto)
    #[arg(long, default_value_t = 0)]
    smote_target: usize,

    /// Training batch size
    #[arg(long, default_value_t = 512)]
    batch_size: i64,

    /// Max training epochs
    #[arg(long, default_value_t = 50)]
    epochs: i64,

    /// Learning rate
    #[arg(long, default_value_t = 0.001)]
    learning_rate: f64,

    /// Early stopping patience (epochs)
    #[arg(long, default_value_t = 5)]
    patience: i64,

    /// LSTM hidden size
    #[arg(long, default_value_t = 128)]
    lstm_hidden: i64,

    /// LSTM number of layers
    #[arg(long, default_value_t = 2)]
    lstm_layers: i64,

    /// Dropout rate
    #[arg(long, default_value_t = 0.3)]
    dropout: f64,

    /// Number of rayon threads for data loading (0 = auto)
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cnn_lstm_train=info".parse()?)
                .add_directive("train_cnn_lstm=info".parse()?),
        )
        .init();

    let args = Args::parse();

    // Configure rayon thread pool for data loading
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .ok();
        info!("rayon thread pool: {} threads", args.threads);
    } else {
        info!(
            "rayon thread pool: {} threads (auto)",
            rayon::current_num_threads()
        );
    }

    info!("CNN+LSTM IDS Model Training");
    info!("Dataset: {}", args.dataset);
    info!("Output dir: {}", args.output_dir.display());

    let source = match args.dataset.as_str() {
        "nsl-kdd" => {
            let train = args
                .nsl_train
                .ok_or_else(|| anyhow::anyhow!("--nsl-train required for nsl-kdd dataset"))?;
            let test = args
                .nsl_test
                .ok_or_else(|| anyhow::anyhow!("--nsl-test required for nsl-kdd dataset"))?;
            DatasetSource::NslKdd {
                train_path: train,
                test_path: test,
            }
        }
        "cicids2017" => {
            let dir = args
                .cicids_dir
                .ok_or_else(|| anyhow::anyhow!("--cicids-dir required for cicids2017 dataset"))?;
            DatasetSource::CicIds2017 { csv_dir: dir }
        }
        "unsw-nb15" => {
            let data = args
                .unsw_data
                .ok_or_else(|| anyhow::anyhow!("--unsw-data required for unsw-nb15 dataset"))?;
            let label = args
                .unsw_label
                .ok_or_else(|| anyhow::anyhow!("--unsw-label required for unsw-nb15 dataset"))?;
            DatasetSource::UnswNb15 {
                data_path: data,
                label_path: label,
            }
        }
        "combined" => {
            let nsl_train = args
                .nsl_train
                .ok_or_else(|| anyhow::anyhow!("--nsl-train required for combined dataset"))?;
            let nsl_test = args
                .nsl_test
                .ok_or_else(|| anyhow::anyhow!("--nsl-test required for combined dataset"))?;
            let cicids_dir = args
                .cicids_dir
                .ok_or_else(|| anyhow::anyhow!("--cicids-dir required for combined dataset"))?;
            let unsw_data = args
                .unsw_data
                .ok_or_else(|| anyhow::anyhow!("--unsw-data required for combined dataset"))?;
            let unsw_label = args
                .unsw_label
                .ok_or_else(|| anyhow::anyhow!("--unsw-label required for combined dataset"))?;
            DatasetSource::Combined {
                nsl_train,
                nsl_test,
                cicids_dir,
                unsw_data,
                unsw_label,
            }
        }
        other => anyhow::bail!(
            "unknown dataset: '{}'. Expected: nsl-kdd, cicids2017, unsw-nb15, combined",
            other
        ),
    };

    let config = TrainConfig {
        model_output: args.output_dir.join("cnn_lstm_model.pt"),
        scaler_output: args.output_dir.join("scaler.json"),
        report_output: args.output_dir.join("evaluation_report.json"),
        use_smote: !args.no_smote,
        smote_target: args.smote_target,
        trainer: TrainerConfig {
            batch_size: args.batch_size,
            epochs: args.epochs,
            learning_rate: args.learning_rate,
            patience: args.patience,
            ..Default::default()
        },
        lstm_hidden: args.lstm_hidden,
        lstm_layers: args.lstm_layers,
        dropout: args.dropout,
    };

    let result = run_training(source, config)?;

    println!("\n========================================");
    println!("CNN+LSTM Training Summary");
    println!("========================================");
    println!("Features:       {}", result.n_features);
    println!("Train samples:  {}", result.n_train_samples);
    println!("Best epoch:     {}", result.metrics.best_epoch + 1);
    println!("Best val loss:  {:.4}", result.metrics.best_val_loss);
    println!("Test Accuracy:  {:.4}", result.report.accuracy);
    println!("Test Macro-F1:  {:.4}", result.report.macro_f1);
    println!("Test FPR:       {:.4}", result.report.fpr);
    println!("========================================");

    Ok(())
}
