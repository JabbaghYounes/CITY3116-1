use anyhow::{Context, Result};
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Min-max normaliser that scales each feature to [0, 1].
///
/// For each feature column j the transform is:
///
/// ```text
///   x'[i,j] = (x[i,j] - min_j) / (max_j - min_j)
/// ```
///
/// When `max_j == min_j` (constant feature) the column is mapped to 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinMaxScaler {
    /// Per-feature minimum values (length = num_features).
    pub min: Vec<f64>,
    /// Per-feature maximum values (length = num_features).
    pub max: Vec<f64>,
    /// Whether `fit` has been called at least once.
    fitted: bool,
}

impl MinMaxScaler {
    /// Create a new, unfitted scaler.
    pub fn new() -> Self {
        Self {
            min: Vec::new(),
            max: Vec::new(),
            fitted: false,
        }
    }

    /// Compute per-feature min and max from the supplied data matrix.
    ///
    /// `data` has shape (n_samples, n_features).
    pub fn fit(&mut self, data: &Array2<f64>) {
        let ncols = data.ncols();
        self.min = vec![f64::INFINITY; ncols];
        self.max = vec![f64::NEG_INFINITY; ncols];

        for row in data.rows() {
            for (j, &val) in row.iter().enumerate() {
                if val < self.min[j] {
                    self.min[j] = val;
                }
                if val > self.max[j] {
                    self.max[j] = val;
                }
            }
        }
        self.fitted = true;
    }

    /// Scale each feature to [0, 1] using previously fitted min/max.
    ///
    /// # Panics
    ///
    /// Panics if `fit` has not been called, or if the number of columns in
    /// `data` does not match the fitted dimensionality.
    pub fn transform(&self, data: &Array2<f64>) -> Array2<f64> {
        assert!(self.fitted, "MinMaxScaler has not been fitted yet");
        assert_eq!(
            data.ncols(),
            self.min.len(),
            "column count mismatch: expected {}, got {}",
            self.min.len(),
            data.ncols()
        );

        let (nrows, ncols) = data.dim();
        let mut result = Array2::<f64>::zeros((nrows, ncols));
        for i in 0..nrows {
            for j in 0..ncols {
                let range = self.max[j] - self.min[j];
                if range.abs() < f64::EPSILON {
                    result[[i, j]] = 0.0;
                } else {
                    result[[i, j]] = (data[[i, j]] - self.min[j]) / range;
                }
            }
        }
        result
    }

    /// Convenience: fit on the data then immediately transform it.
    pub fn fit_transform(&mut self, data: &Array2<f64>) -> Array2<f64> {
        self.fit(data);
        self.transform(data)
    }

    /// Serialise the scaler parameters to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialise MinMaxScaler")?;
        fs::write(path, json).context("failed to write scaler file")?;
        Ok(())
    }

    /// Load scaler parameters from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path).context("failed to read scaler file")?;
        let scaler: Self =
            serde_json::from_str(&json).context("failed to deserialise MinMaxScaler")?;
        Ok(scaler)
    }
}

impl Default for MinMaxScaler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn test_fit_transform_basic() {
        let data = array![[1.0, 10.0], [2.0, 20.0], [3.0, 30.0]];
        let mut scaler = MinMaxScaler::new();
        let scaled = scaler.fit_transform(&data);

        assert!((scaled[[0, 0]] - 0.0).abs() < 1e-12);
        assert!((scaled[[1, 0]] - 0.5).abs() < 1e-12);
        assert!((scaled[[2, 0]] - 1.0).abs() < 1e-12);
        assert!((scaled[[0, 1]] - 0.0).abs() < 1e-12);
        assert!((scaled[[2, 1]] - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_constant_feature() {
        let data = array![[5.0, 1.0], [5.0, 2.0]];
        let mut scaler = MinMaxScaler::new();
        let scaled = scaler.fit_transform(&data);

        // Constant column -> 0.0
        assert!((scaled[[0, 0]] - 0.0).abs() < 1e-12);
        assert!((scaled[[1, 0]] - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let data = array![[0.0, 100.0], [10.0, 200.0]];
        let mut scaler = MinMaxScaler::new();
        scaler.fit(&data);

        let dir = std::env::temp_dir().join("ids_scaler_test.json");
        scaler.save(&dir).unwrap();

        let loaded = MinMaxScaler::load(&dir).unwrap();
        assert_eq!(scaler.min, loaded.min);
        assert_eq!(scaler.max, loaded.max);

        let _ = std::fs::remove_file(&dir);
    }
}
