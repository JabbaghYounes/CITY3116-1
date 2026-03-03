use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

use crate::encode::OneHotEncoder;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A fully pre-processed train / validation / test split ready for model
/// consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSplit {
    pub x_train: Array2<f64>,
    pub y_train: Array1<usize>,
    pub x_val: Array2<f64>,
    pub y_val: Array1<usize>,
    pub x_test: Array2<f64>,
    pub y_test: Array1<usize>,
    /// Human-readable name for every feature column.
    pub feature_names: Vec<String>,
    /// Human-readable label for each class index (0..N).
    pub label_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// NSL-KDD column names (41 features)
// ---------------------------------------------------------------------------

const NSL_KDD_COLUMNS: &[&str] = &[
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
];

/// Indices of the three categorical columns.
const CAT_PROTOCOL: usize = 1;
const CAT_SERVICE: usize = 2;
const CAT_FLAG: usize = 3;

// ---------------------------------------------------------------------------
// Attack-type -> category mapping (comprehensive NSL-KDD)
// ---------------------------------------------------------------------------

fn attack_category(label: &str) -> usize {
    // Strip any trailing period that some dataset variants include.
    let label = label.trim().trim_end_matches('.');

    match label.to_lowercase().as_str() {
        // Normal
        "normal" => 0,

        // DoS attacks
        "back" | "land" | "neptune" | "pod" | "smurf" | "teardrop" | "apache2" | "udpstorm"
        | "processtable" | "mailbomb" | "worm" => 1,

        // Probe attacks
        "satan" | "ipsweep" | "nmap" | "portsweep" | "mscan" | "saint" => 2,

        // R2L (Remote-to-Local) attacks
        "guess_passwd" | "ftp_write" | "imap" | "phf" | "multihop" | "warezmaster"
        | "warezclient" | "spy" | "xlock" | "xsnoop" | "snmpguess" | "snmpgetattack"
        | "httptunnel" | "sendmail" | "named" | "worm_sendmail" | "sendmail_dictionary" => 3,

        // U2R (User-to-Root) attacks
        "buffer_overflow" | "loadmodule" | "rootkit" | "perl" | "sqlattack" | "xterm" | "ps"
        | "httptunnel_u2r" => 4,

        // Fallback — unknown attack labels are mapped to the nearest
        // reasonable category.  For safety default to Probe (2) which is the
        // broadest reconnaissance category.
        other => {
            tracing::warn!(label = other, "unknown NSL-KDD attack label; mapping to Probe");
            2
        }
    }
}

/// Canonical label names in class-index order.
pub fn label_names() -> Vec<String> {
    vec![
        "Normal".to_string(),
        "DoS".to_string(),
        "Probe".to_string(),
        "R2L".to_string(),
        "U2R".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Raw record parsing
// ---------------------------------------------------------------------------

/// A single raw row from the NSL-KDD CSV (41 features + label + difficulty).
struct RawRecord {
    /// The 41 feature values as strings (categorical ones are still strings).
    features: Vec<String>,
    /// Attack label string (e.g. "normal", "neptune", ...).
    label: String,
    // difficulty is read but not stored — we only need the label.
}

/// Parse a single NSL-KDD CSV file and return all raw records.
fn read_csv(path: &Path) -> Result<Vec<RawRecord>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .trim(csv::Trim::All)
        .from_path(path)
        .with_context(|| format!("failed to open NSL-KDD CSV: {}", path.display()))?;

    let mut records = Vec::new();
    for (line_no, result) in reader.records().enumerate() {
        let row = result.with_context(|| {
            format!(
                "failed to read line {} of {}",
                line_no + 1,
                path.display()
            )
        })?;

        // Expected: 41 features + label + difficulty = 43 fields.
        if row.len() < 43 {
            anyhow::bail!(
                "{}:{}: expected at least 43 fields, got {}",
                path.display(),
                line_no + 1,
                row.len()
            );
        }

        let features: Vec<String> = row.iter().take(41).map(|s| s.to_string()).collect();
        let label = row[41].to_string();
        // row[42] is difficulty — intentionally ignored.

        records.push(RawRecord { features, label });
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Build one-hot encoders for the three categorical columns, fitted on the
/// training data only.
fn fit_encoders(train_records: &[RawRecord]) -> [OneHotEncoder; 3] {
    let mut enc_proto = OneHotEncoder::new();
    let mut enc_service = OneHotEncoder::new();
    let mut enc_flag = OneHotEncoder::new();

    let proto_vals: Vec<String> = train_records
        .iter()
        .map(|r| r.features[CAT_PROTOCOL].clone())
        .collect();
    let service_vals: Vec<String> = train_records
        .iter()
        .map(|r| r.features[CAT_SERVICE].clone())
        .collect();
    let flag_vals: Vec<String> = train_records
        .iter()
        .map(|r| r.features[CAT_FLAG].clone())
        .collect();

    enc_proto.fit(&proto_vals);
    enc_service.fit(&service_vals);
    enc_flag.fit(&flag_vals);

    [enc_proto, enc_service, enc_flag]
}

/// Convert a set of raw records into (features_matrix, labels_vector) using
/// the supplied encoders.
///
/// Numeric features are parsed as `f64`.  The three categorical columns are
/// replaced by their one-hot expansions.
fn encode_records(
    records: &[RawRecord],
    encoders: &[OneHotEncoder; 3],
) -> Result<(Array2<f64>, Array1<usize>)> {
    if records.is_empty() {
        anyhow::bail!("encode_records called with zero records");
    }

    // Figure out final width:
    // 41 original cols - 3 categorical + sum(one-hot widths).
    let numeric_cols = 41 - 3; // 38 numeric features
    let onehot_width: usize = encoders.iter().map(|e| e.num_categories()).sum();
    let total_cols = numeric_cols + onehot_width;

    let n_rows = records.len();
    let mut flat: Vec<f64> = Vec::with_capacity(n_rows * total_cols);
    let mut labels: Vec<usize> = Vec::with_capacity(n_rows);

    let cat_indices: [usize; 3] = [CAT_PROTOCOL, CAT_SERVICE, CAT_FLAG];

    for rec in records {
        // Numeric features (skip categorical columns).
        for (j, val_str) in rec.features.iter().enumerate() {
            if cat_indices.contains(&j) {
                continue;
            }
            let v: f64 = val_str.parse().unwrap_or(0.0);
            flat.push(v);
        }

        // One-hot encodings (in order: protocol, service, flag).
        for (enc_idx, &col_idx) in cat_indices.iter().enumerate() {
            let onehot = encoders[enc_idx].transform(&rec.features[col_idx]);
            flat.extend(onehot);
        }

        labels.push(attack_category(&rec.label));
    }

    let features = Array2::from_shape_vec((n_rows, total_cols), flat)
        .context("failed to build feature matrix from flat vector")?;
    let labels = Array1::from(labels);

    Ok((features, labels))
}

/// Build human-readable feature names to match the column layout produced by
/// `encode_records`.
fn build_feature_names(encoders: &[OneHotEncoder; 3]) -> Vec<String> {
    let cat_indices: [usize; 3] = [CAT_PROTOCOL, CAT_SERVICE, CAT_FLAG];
    let mut names = Vec::new();

    // Numeric columns first (preserving original order, skipping categoricals).
    for (j, &col_name) in NSL_KDD_COLUMNS.iter().enumerate() {
        if cat_indices.contains(&j) {
            continue;
        }
        names.push(col_name.to_string());
    }

    // Then one-hot expansions.
    let cat_names = ["protocol_type", "service", "flag"];
    for (enc_idx, &prefix) in cat_names.iter().enumerate() {
        for cat in encoders[enc_idx].category_names() {
            names.push(format!("{}_{}", prefix, cat));
        }
    }

    names
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the NSL-KDD dataset from the standard train and test CSV files.
///
/// Each file is expected to contain **no header row** with 43 comma-separated
/// fields per line (41 features + attack label + difficulty level).
///
/// The training set is further split into 82% train / 18% validation.  The
/// test set is kept intact.
///
/// Categorical features (`protocol_type`, `service`, `flag`) are one-hot
/// encoded.  Encoders are fitted **only** on the training data.
pub fn load_nsl_kdd(train_path: &Path, test_path: &Path) -> Result<DatasetSplit> {
    info!("loading NSL-KDD training data from {}", train_path.display());
    let train_records = read_csv(train_path)?;
    info!("loading NSL-KDD test data from {}", test_path.display());
    let test_records = read_csv(test_path)?;

    info!(
        "parsed {} training records, {} test records",
        train_records.len(),
        test_records.len()
    );

    // Fit one-hot encoders on training data only.
    let encoders = fit_encoders(&train_records);
    info!(
        "one-hot encoder widths: protocol={}, service={}, flag={}",
        encoders[0].num_categories(),
        encoders[1].num_categories(),
        encoders[2].num_categories()
    );

    // Encode all records.
    let (x_full_train, y_full_train) = encode_records(&train_records, &encoders)?;
    let (x_test, y_test) = encode_records(&test_records, &encoders)?;

    // Split training set 82% / 18%.
    let n = x_full_train.nrows();
    let mut indices: Vec<usize> = (0..n).collect();
    {
        let mut rng = rand::thread_rng();
        indices.shuffle(&mut rng);
    }
    let split_point = (n as f64 * 0.82).round() as usize;
    let train_idx = &indices[..split_point];
    let val_idx = &indices[split_point..];

    let x_train = x_full_train.select(ndarray::Axis(0), train_idx);
    let y_train = y_full_train.select(ndarray::Axis(0), train_idx);
    let x_val = x_full_train.select(ndarray::Axis(0), val_idx);
    let y_val = y_full_train.select(ndarray::Axis(0), val_idx);

    let feature_names = build_feature_names(&encoders);

    info!(
        "dataset ready: train={}, val={}, test={}, features={}",
        x_train.nrows(),
        x_val.nrows(),
        x_test.nrows(),
        feature_names.len()
    );

    // Sanity check.
    assert_eq!(x_train.ncols(), feature_names.len());
    assert_eq!(x_test.ncols(), feature_names.len());

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

// ---------------------------------------------------------------------------
// Class-distribution helper (useful for logging / balancing decisions)
// ---------------------------------------------------------------------------

/// Return a map from class index to count.
pub fn class_distribution(labels: &Array1<usize>) -> HashMap<usize, usize> {
    let mut dist = HashMap::new();
    for &l in labels.iter() {
        *dist.entry(l).or_insert(0) += 1;
    }
    dist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_category_mapping() {
        assert_eq!(attack_category("normal"), 0);
        assert_eq!(attack_category("normal."), 0);
        assert_eq!(attack_category("neptune"), 1);
        assert_eq!(attack_category("smurf"), 1);
        assert_eq!(attack_category("satan"), 2);
        assert_eq!(attack_category("nmap"), 2);
        assert_eq!(attack_category("guess_passwd"), 3);
        assert_eq!(attack_category("warezclient"), 3);
        assert_eq!(attack_category("buffer_overflow"), 4);
        assert_eq!(attack_category("rootkit"), 4);
    }

    #[test]
    fn test_label_names() {
        let names = label_names();
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "Normal");
        assert_eq!(names[4], "U2R");
    }
}
