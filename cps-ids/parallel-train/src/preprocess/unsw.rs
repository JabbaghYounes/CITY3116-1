use anyhow::{Context, Result};
use ndarray::{Array1, Array2, Axis};
use rand::seq::SliceRandom;
use std::path::Path;
use tracing::info;

use crate::preprocess::dataset::{label_names, DatasetSplit};

const NUM_FEATURES: usize = 76;

const FEATURE_NAMES: &[&str] = &[
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWR Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "FWD Init Win Bytes",
    "Bwd Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
];

fn unsw_attack_category(label: usize) -> usize {
    match label {
        0 => 0,
        3 | 6 => 1,
        1 | 5 | 7 => 2,
        4 | 9 => 3,
        2 | 8 => 4,
        other => {
            tracing::warn!(label = other, "unknown UNSW-NB15 label; mapping to Probe");
            2
        }
    }
}

fn sanitize_f64(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

pub fn load_unsw_nb15(data_path: &Path, label_path: &Path) -> Result<DatasetSplit> {
    info!("loading UNSW-NB15 features from {}", data_path.display());
    info!("loading UNSW-NB15 labels from {}", label_path.display());

    let mut label_reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_path(label_path)
        .with_context(|| format!("failed to open {}", label_path.display()))?;

    let raw_labels: Vec<usize> = label_reader
        .records()
        .enumerate()
        .map(|(i, r)| {
            let record = r.with_context(|| format!("Label.csv line {}", i + 2))?;
            let val: usize = record[0]
                .trim()
                .parse()
                .with_context(|| format!("Label.csv line {}: invalid integer", i + 2))?;
            Ok(unsw_attack_category(val))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut data_reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .flexible(true)
        .from_path(data_path)
        .with_context(|| format!("failed to open {}", data_path.display()))?;

    let mut features: Vec<Vec<f64>> = Vec::with_capacity(raw_labels.len());

    for (i, result) in data_reader.records().enumerate() {
        let row = result.with_context(|| format!("Data.csv line {}", i + 2))?;

        if row.len() < NUM_FEATURES {
            anyhow::bail!(
                "Data.csv line {}: expected >= {} fields, got {}",
                i + 2,
                NUM_FEATURES,
                row.len()
            );
        }

        let feat: Vec<f64> = (0..NUM_FEATURES)
            .map(|j| sanitize_f64(row[j].trim().parse::<f64>().unwrap_or(0.0)))
            .collect();
        features.push(feat);
    }

    anyhow::ensure!(
        features.len() == raw_labels.len(),
        "Data.csv has {} rows but Label.csv has {} rows",
        features.len(),
        raw_labels.len()
    );

    let n = features.len();
    info!("loaded {} UNSW-NB15 records", n);

    let flat: Vec<f64> = features.into_iter().flatten().collect();
    let x_all = Array2::from_shape_vec((n, NUM_FEATURES), flat)
        .context("failed to build UNSW-NB15 feature matrix")?;
    let y_all = Array1::from(raw_labels);

    let mut indices: Vec<usize> = (0..n).collect();
    {
        let mut rng = rand::thread_rng();
        indices.shuffle(&mut rng);
    }
    let train_end = (n as f64 * 0.70).round() as usize;
    let val_end = (n as f64 * 0.82).round() as usize;

    let train_idx = &indices[..train_end];
    let val_idx = &indices[train_end..val_end];
    let test_idx = &indices[val_end..];

    let x_train = x_all.select(Axis(0), train_idx);
    let y_train = y_all.select(Axis(0), train_idx);
    let x_val = x_all.select(Axis(0), val_idx);
    let y_val = y_all.select(Axis(0), val_idx);
    let x_test = x_all.select(Axis(0), test_idx);
    let y_test = y_all.select(Axis(0), test_idx);

    let feature_names: Vec<String> = FEATURE_NAMES.iter().map(|s| s.to_string()).collect();

    info!(
        "UNSW-NB15 ready: train={}, val={}, test={}, features={}",
        x_train.nrows(),
        x_val.nrows(),
        x_test.nrows(),
        NUM_FEATURES
    );

    Ok(DatasetSplit {
        x_train,
        y_train,
        x_val,
        y_val,
        x_test,
        y_test,
        feature_names,
        label_names: label_names(),
    })
}
