use anyhow::{Context, Result};
use ndarray::{Array1, Array2, Axis};
use rand::seq::SliceRandom;
use std::path::Path;
use tracing::info;

use crate::preprocess::dataset::{label_names, DatasetSplit};

const NUM_FEATURES: usize = 78;

const FEATURE_NAMES: &[&str] = &[
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
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
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
];

fn cicids_attack_category(label: &str) -> usize {
    let label = label.trim();
    match label {
        "BENIGN" => 0,
        "DDoS" | "DoS Hulk" | "DoS GoldenEye" | "DoS slowloris" | "DoS Slowhttptest" => 1,
        "PortScan" => 2,
        "FTP-Patator" | "SSH-Patator" | "Bot" | "Heartbleed" => 3,
        "Infiltration" => 4,
        other => {
            if other.starts_with("Web Attack") {
                3
            } else {
                tracing::warn!(label = other, "unknown CIC-IDS2017 label; mapping to Probe");
                2
            }
        }
    }
}

fn clean_numeric(s: &str) -> f64 {
    let s = s.trim();
    match s.to_lowercase().as_str() {
        "nan" | "infinity" | "inf" | "-infinity" | "-inf" => 0.0,
        _ => s.parse::<f64>().unwrap_or(0.0),
    }
}

fn sanitize_f64(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

fn load_single_csv(path: &Path) -> Result<(Vec<Vec<f64>>, Vec<usize>)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("failed to open CIC-IDS2017 CSV: {}", path.display()))?;

    let mut features = Vec::new();
    let mut labels = Vec::new();
    let mut skipped = 0usize;

    for (line_no, result) in reader.records().enumerate() {
        let row = result.with_context(|| {
            format!("failed to read line {} of {}", line_no + 2, path.display())
        })?;

        if row.len() < NUM_FEATURES + 1 {
            skipped += 1;
            continue;
        }

        let feat: Vec<f64> = (0..NUM_FEATURES)
            .map(|i| sanitize_f64(clean_numeric(&row[i])))
            .collect();

        let label_str = row[NUM_FEATURES].trim();
        let label = cicids_attack_category(label_str);

        features.push(feat);
        labels.push(label);
    }

    if skipped > 0 {
        tracing::warn!(path = %path.display(), skipped, "skipped malformed rows");
    }

    Ok((features, labels))
}

pub fn load_cicids2017(csv_dir: &Path) -> Result<DatasetSplit> {
    let file_names = [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ];

    let mut all_features: Vec<Vec<f64>> = Vec::new();
    let mut all_labels: Vec<usize> = Vec::new();

    for name in &file_names {
        let path = csv_dir.join(name);
        info!("loading CIC-IDS2017 file: {}", path.display());
        let (feats, labs) = load_single_csv(&path)?;
        info!("  loaded {} records from {}", feats.len(), name);
        all_features.extend(feats);
        all_labels.extend(labs);
    }

    info!("total CIC-IDS2017 records: {}", all_features.len());

    let n = all_features.len();
    let flat: Vec<f64> = all_features.into_iter().flatten().collect();
    let x_all = Array2::from_shape_vec((n, NUM_FEATURES), flat)
        .context("failed to build CIC-IDS2017 feature matrix")?;
    let y_all = Array1::from(all_labels);

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
        "CIC-IDS2017 ready: train={}, val={}, test={}, features={}",
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
