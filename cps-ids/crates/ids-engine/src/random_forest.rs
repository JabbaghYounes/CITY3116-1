//! Random Forest classifier wrapper around smartcore.
//!
//! Provides an ergonomic ndarray-based interface for training, prediction, and
//! model persistence. Internally converts between ndarray types and smartcore's
//! `DenseMatrix<f64>` / `Vec<i32>`.

use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use smartcore::ensemble::random_forest_classifier::{
    RandomForestClassifier, RandomForestClassifierParameters,
};
use smartcore::linalg::basic::matrix::DenseMatrix;
use std::path::Path;
use tracing::info;

// ---------------------------------------------------------------------------
// Conversions: ndarray <-> smartcore
// ---------------------------------------------------------------------------

fn array2_to_dense(a: &Array2<f64>) -> DenseMatrix<f64> {
    let rows: Vec<Vec<f64>> = a.rows().into_iter().map(|r| r.to_vec()).collect();
    DenseMatrix::from_2d_vec(&rows)
}

fn labels_usize_to_i32(y: &Array1<usize>) -> Vec<i32> {
    y.iter().map(|&v| v as i32).collect()
}

fn labels_i32_to_usize(v: &[i32]) -> Array1<usize> {
    Array1::from_vec(v.iter().map(|&x| x as usize).collect())
}

type SmartcoreRF = RandomForestClassifier<f64, i32, DenseMatrix<f64>, Vec<i32>>;

// ---------------------------------------------------------------------------
// Persistable model wrapper
// ---------------------------------------------------------------------------

/// Wrapper that persists the training data so the model can be reconstructed.
/// smartcore types do not implement Serialize, so we store the raw data and
/// retrain on load. For a university assignment this is acceptable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFModel {
    train_x: Vec<Vec<f64>>,
    train_y: Vec<i32>,
    pub n_classes: usize,
    pub n_features: usize,
}

impl RFModel {
    /// Train a new Random Forest.
    ///
    /// * `x` — feature matrix (n_samples x n_features)
    /// * `y` — class labels encoded as `usize`
    pub fn train(x: &Array2<f64>, y: &Array1<usize>) -> Result<Self> {
        let n_features = x.ncols();
        let n_classes = *y.iter().max().unwrap_or(&0) + 1;

        info!(
            samples = x.nrows(),
            features = n_features,
            classes = n_classes,
            "Training Random Forest (n_trees=100, max_depth=20)"
        );

        let dm = array2_to_dense(x);
        let yv = labels_usize_to_i32(y);

        // Validate that training succeeds
        let _model = Self::fit_internal(&dm, &yv)?;

        // Store training data for persistence
        let train_x: Vec<Vec<f64>> = x.rows().into_iter().map(|r| r.to_vec()).collect();

        Ok(Self {
            train_x,
            train_y: yv,
            n_classes,
            n_features,
        })
    }

    /// Predict class labels for the given feature matrix.
    pub fn predict(&self, x: &Array2<f64>) -> Result<Array1<usize>> {
        let model = self.rebuild_model()?;
        let dm = array2_to_dense(x);
        let preds: Vec<i32> = model
            .predict(&dm)
            .map_err(|e| anyhow::anyhow!("RF predict failed: {e}"))?;
        Ok(labels_i32_to_usize(&preds))
    }

    /// Estimate class probabilities (one-hot approximation with smoothing).
    pub fn predict_proba(&self, x: &Array2<f64>) -> Result<Array2<f64>> {
        let labels = self.predict(x)?;
        let n = labels.len();
        let nc = self.n_classes;
        let smoothing = 0.01;
        let mut proba = Array2::<f64>::from_elem((n, nc), smoothing / nc as f64);
        for (i, &cls) in labels.iter().enumerate() {
            if cls < nc {
                proba[[i, cls]] += 1.0 - smoothing;
            }
        }
        for mut row in proba.rows_mut() {
            let s: f64 = row.iter().sum();
            if s > 0.0 {
                row.mapv_inplace(|v| v / s);
            }
        }
        Ok(proba)
    }

    /// Persist the model (training data) to disk as JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string(self).context("Failed to serialise RFModel")?;
        std::fs::write(path, json).context("Failed to write RF model file")?;
        info!(?path, "Random Forest model saved");
        Ok(())
    }

    /// Load a previously saved model from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path).context("Failed to read RF model file")?;
        let model: Self = serde_json::from_str(&json).context("Failed to deserialise RFModel")?;
        info!(?path, "Random Forest model loaded");
        Ok(model)
    }

    // ------ internal ------

    fn fit_internal(dm: &DenseMatrix<f64>, yv: &[i32]) -> Result<SmartcoreRF> {
        let params = RandomForestClassifierParameters::default()
            .with_n_trees(100)
            .with_max_depth(20)
            .with_min_samples_split(2)
            .with_min_samples_leaf(1)
            .with_seed(42);

        SmartcoreRF::fit(dm, &yv.to_vec(), params)
            .map_err(|e| anyhow::anyhow!("RF training failed: {e}"))
    }

    fn rebuild_model(&self) -> Result<SmartcoreRF> {
        let dm = DenseMatrix::from_2d_vec(&self.train_x);
        Self::fit_internal(&dm, &self.train_y)
    }
}
