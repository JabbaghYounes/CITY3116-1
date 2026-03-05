use anyhow::{Context, Result};
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Min-max normaliser that scales each feature to [0, 1].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinMaxScaler {
    pub min: Vec<f64>,
    pub max: Vec<f64>,
    fitted: bool,
}

impl MinMaxScaler {
    pub fn new() -> Self {
        Self {
            min: Vec::new(),
            max: Vec::new(),
            fitted: false,
        }
    }

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

    pub fn fit_transform(&mut self, data: &Array2<f64>) -> Array2<f64> {
        self.fit(data);
        self.transform(data)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialise MinMaxScaler")?;
        fs::write(path, json).context("failed to write scaler file")?;
        Ok(())
    }

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
