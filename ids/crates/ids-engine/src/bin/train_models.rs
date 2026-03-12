//! CLI for training IDS models on different datasets.
//!
//! # Examples
//!
//! ```bash
//! # Model A: NSL-KDD only
//! cargo run --release -p ids-engine --bin train_models -- \
//!     --dataset nsl-kdd \
//!     --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \
//!     --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \
//!     --output-dir data/models/model-a
//!
//! # Model B: CIC-IDS2017 only
//! cargo run --release -p ids-engine --bin train_models -- \
//!     --dataset cicids2017 \
//!     --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
//!     --output-dir data/models/model-b
//!
//! # Model C: UNSW-NB15 only
//! cargo run --release -p ids-engine --bin train_models -- \
//!     --dataset unsw-nb15 \
//!     --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \
//!     --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \
//!     --output-dir data/models/model-c
//!
//! # Model D: All three combined
//! cargo run --release -p ids-engine --bin train_models -- \
//!     --dataset combined \
//!     --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \
//!     --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \
//!     --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
//!     --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \
//!     --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \
//!     --output-dir data/models/model-d
//! ```

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use ids_engine::train::{run_training, DatasetSource, TrainConfig};

#[derive(Parser, Debug)]
#[command(name = "train_models")]
#[command(about = "Train IDS models on one or more intrusion detection datasets")]
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

    /// Output directory for models and reports
    #[arg(short, long, default_value = "data/models")]
    output_dir: PathBuf,

    /// Disable SMOTE oversampling
    #[arg(long, default_value_t = false)]
    no_smote: bool,

    /// SMOTE target count per class (0 = auto)
    #[arg(long, default_value_t = 0)]
    smote_target: usize,

    /// Isolation Forest tree count
    #[arg(long, default_value_t = 100)]
    iforest_trees: usize,

    /// Isolation Forest subsample size
    #[arg(long, default_value_t = 256)]
    iforest_sample_size: usize,

    /// Isolation Forest contamination rate
    #[arg(long, default_value_t = 0.05)]
    iforest_contamination: f64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ids_preprocess=info".parse()?)
                .add_directive("ids_engine=info".parse()?),
        )
        .init();

    let args = Args::parse();

    info!("Training IDS models");
    info!("Dataset: {}", args.dataset);
    info!("Output dir: {}", args.output_dir.display());

    // Build dataset source
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

    // Build training config
    let config = TrainConfig {
        rf_output: args.output_dir.join("random_forest.json"),
        iforest_output: args.output_dir.join("isolation_forest.json"),
        scaler_output: args.output_dir.join("scaler.json"),
        report_output: args.output_dir.join("evaluation_report.json"),
        use_smote: !args.no_smote,
        smote_target: args.smote_target,
        iforest_trees: args.iforest_trees,
        iforest_sample_size: args.iforest_sample_size,
        iforest_contamination: args.iforest_contamination,
    };

    // Run training
    let result = run_training(source, config)?;

    println!("\n========================================");
    println!("Training Summary");
    println!("========================================");
    println!("Features:       {}", result.n_features);
    println!("Train samples:  {}", result.n_train_samples);
    println!("RF Accuracy:    {:.4}", result.rf_report.accuracy);
    println!("RF Macro-F1:    {:.4}", result.rf_report.macro_f1);
    println!("Ensemble Acc:   {:.4}", result.ensemble_report.accuracy);
    println!("Ensemble F1:    {:.4}", result.ensemble_report.macro_f1);
    println!("========================================");

    Ok(())
}
