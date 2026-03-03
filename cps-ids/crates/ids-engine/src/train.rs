//! Training orchestrator for multi-dataset IDS model training.
//!
//! Supports four model variants:
//! - **Model A**: NSL-KDD only
//! - **Model B**: CIC-IDS2017 only
//! - **Model C**: UNSW-NB15 only
//! - **Model D**: All three combined (union with zero-padding)

use anyhow::{Context, Result};
use ndarray::{Array1, Axis};
use std::path::PathBuf;
use tracing::info;

use ids_preprocess::{
    load_cicids2017, load_nsl_kdd, load_unsw_nb15, merge_datasets, smote, DatasetSplit,
    MinMaxScaler,
};

use crate::ensemble::EnsembleDetector;
use crate::evaluate::{evaluate, print_report, ClassificationReport};
use crate::isolation_forest::IsolationForest;
use crate::random_forest::RFModel;

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Which dataset(s) to use for training.
#[derive(Debug, Clone)]
pub enum DatasetSource {
    /// NSL-KDD only (Model A).
    NslKdd {
        train_path: PathBuf,
        test_path: PathBuf,
    },
    /// CIC-IDS2017 only (Model B).
    CicIds2017 { csv_dir: PathBuf },
    /// UNSW-NB15 only (Model C).
    UnswNb15 {
        data_path: PathBuf,
        label_path: PathBuf,
    },
    /// All three combined (Model D).
    Combined {
        nsl_train: PathBuf,
        nsl_test: PathBuf,
        cicids_dir: PathBuf,
        unsw_data: PathBuf,
        unsw_label: PathBuf,
    },
}

/// Configuration for a training run.
#[derive(Debug, Clone)]
pub struct TrainConfig {
    pub rf_output: PathBuf,
    pub iforest_output: PathBuf,
    pub scaler_output: PathBuf,
    pub report_output: PathBuf,
    pub use_smote: bool,
    /// SMOTE target count per class (0 = auto: use majority class count).
    pub smote_target: usize,
    pub iforest_trees: usize,
    pub iforest_sample_size: usize,
    pub iforest_contamination: f64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            rf_output: PathBuf::from("data/models/random_forest.json"),
            iforest_output: PathBuf::from("data/models/isolation_forest.json"),
            scaler_output: PathBuf::from("data/models/scaler.json"),
            report_output: PathBuf::from("results/evaluation_report.json"),
            use_smote: true,
            smote_target: 0,
            iforest_trees: 100,
            iforest_sample_size: 256,
            iforest_contamination: 0.05,
        }
    }
}

/// Result of a training run.
#[derive(Debug)]
pub struct TrainResult {
    pub rf_report: ClassificationReport,
    pub iforest_report: ClassificationReport,
    pub ensemble_report: ClassificationReport,
    pub n_features: usize,
    pub n_train_samples: usize,
}

// ---------------------------------------------------------------------------
// Dataset loading
// ---------------------------------------------------------------------------

/// Load the dataset based on the source configuration.
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

// ---------------------------------------------------------------------------
// Training pipeline
// ---------------------------------------------------------------------------

/// Run the full training pipeline: load, preprocess, train, evaluate, save.
pub fn run_training(source: DatasetSource, config: TrainConfig) -> Result<TrainResult> {
    // 1. Load dataset
    let split = load_dataset(&source)?;

    let n_classes = split.label_names.len();
    let n_features = split.x_train.ncols();

    info!(
        "Dataset loaded: {} train, {} val, {} test, {} features, {} classes",
        split.x_train.nrows(),
        split.x_val.nrows(),
        split.x_test.nrows(),
        n_features,
        n_classes
    );

    // 2. Normalize
    let mut scaler = MinMaxScaler::new();
    let x_train_scaled = scaler.fit_transform(&split.x_train);
    let _x_val_scaled = scaler.transform(&split.x_val);
    let x_test_scaled = scaler.transform(&split.x_test);

    // 3. Optional SMOTE
    let (x_train_final, y_train_final) = if config.use_smote {
        let target = if config.smote_target == 0 {
            let dist = ids_preprocess::dataset::class_distribution(&split.y_train);
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

    // 4. Train Random Forest
    info!("training Random Forest ({} samples, {} features)...", n_train_samples, n_features);
    let rf = RFModel::train(&x_train_final, &y_train_final)?;

    // 5. Train Isolation Forest (on normal samples only)
    info!("training Isolation Forest...");
    let normal_indices: Vec<usize> = y_train_final
        .iter()
        .enumerate()
        .filter(|(_, &l)| l == 0)
        .map(|(i, _)| i)
        .collect();
    let x_normal = x_train_final.select(Axis(0), &normal_indices);
    info!("IForest training on {} normal samples", x_normal.nrows());
    let iforest = IsolationForest::fit(
        &x_normal,
        config.iforest_trees,
        config.iforest_sample_size,
        config.iforest_contamination,
    );

    // 6. Evaluate on test set
    info!("evaluating models on test set ({} samples)...", x_test_scaled.nrows());

    // RF evaluation
    let rf_preds = rf.predict(&x_test_scaled)?;
    let rf_report = evaluate(&split.y_test, &rf_preds, n_classes);
    println!("\n=== Random Forest ===");
    print_report(&rf_report, &split.label_names);

    // IForest evaluation (binary: normal vs anomaly)
    let if_scores = iforest.anomaly_scores(&x_test_scaled);
    let if_preds: Array1<usize> = if_scores.mapv(|s| if s >= 0.5 { 1 } else { 0 });
    let y_test_binary: Array1<usize> = split.y_test.mapv(|l| if l == 0 { 0 } else { 1 });
    let iforest_report = evaluate(&y_test_binary, &if_preds, 2);
    let binary_labels = vec!["Normal".to_string(), "Attack".to_string()];
    println!("\n=== Isolation Forest (binary: Normal vs Attack) ===");
    print_report(&iforest_report, &binary_labels);

    // Ensemble evaluation
    let ensemble = EnsembleDetector::default();
    let rf_probs = rf.predict_proba(&x_test_scaled)?;
    let ensemble_preds = ensemble.predict(&rf_probs, &if_scores, n_classes);
    let ensemble_report = evaluate(&split.y_test, &ensemble_preds, n_classes);
    println!("\n=== Ensemble (RF + IForest) ===");
    print_report(&ensemble_report, &split.label_names);

    // 7. Save models and report
    info!("saving models...");

    if let Some(parent) = config.rf_output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.report_output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    rf.save(&config.rf_output)?;
    info!("  RF model saved to {}", config.rf_output.display());

    iforest.save(&config.iforest_output)?;
    info!("  IForest model saved to {}", config.iforest_output.display());

    scaler
        .save(&config.scaler_output)
        .context("failed to save scaler")?;
    info!("  Scaler saved to {}", config.scaler_output.display());

    // Save evaluation report as JSON
    let report_json = serde_json::json!({
        "random_forest": rf_report,
        "isolation_forest": iforest_report,
        "ensemble": ensemble_report,
        "dataset": format!("{:?}", source),
        "n_features": n_features,
        "n_train_samples": n_train_samples,
    });
    std::fs::write(
        &config.report_output,
        serde_json::to_string_pretty(&report_json)?,
    )?;
    info!("  Report saved to {}", config.report_output.display());

    info!("training complete.");

    Ok(TrainResult {
        rf_report,
        iforest_report,
        ensemble_report,
        n_features,
        n_train_samples,
    })
}
