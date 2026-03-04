//! Custom Isolation Forest with parallel tree construction and scoring via rayon.

use ndarray::{Array1, Array2, ArrayView1};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationTree {
    Internal {
        feature_idx: usize,
        split_value: f64,
        left: Box<IsolationTree>,
        right: Box<IsolationTree>,
    },
    Leaf {
        size: usize,
    },
}

impl IsolationTree {
    fn build(
        x: &Array2<f64>,
        indices: &[usize],
        height_limit: usize,
        current_height: usize,
        rng: &mut impl Rng,
    ) -> Self {
        let n = indices.len();

        if current_height >= height_limit || n <= 1 {
            return IsolationTree::Leaf { size: n };
        }

        let n_features = x.ncols();
        let feature_idx = rng.gen_range(0..n_features);

        let mut min_val = f64::INFINITY;
        let mut max_val = f64::NEG_INFINITY;
        for &i in indices {
            let v = x[[i, feature_idx]];
            if v < min_val {
                min_val = v;
            }
            if v > max_val {
                max_val = v;
            }
        }

        if (max_val - min_val).abs() < f64::EPSILON {
            return IsolationTree::Leaf { size: n };
        }

        let split_value = rng.gen_range(min_val..max_val);

        let mut left_idx = Vec::new();
        let mut right_idx = Vec::new();
        for &i in indices {
            if x[[i, feature_idx]] < split_value {
                left_idx.push(i);
            } else {
                right_idx.push(i);
            }
        }

        let left = Self::build(x, &left_idx, height_limit, current_height + 1, rng);
        let right = Self::build(x, &right_idx, height_limit, current_height + 1, rng);

        IsolationTree::Internal {
            feature_idx,
            split_value,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn path_length(&self, sample: &ArrayView1<f64>, current_depth: usize) -> f64 {
        match self {
            IsolationTree::Leaf { size } => {
                current_depth as f64 + c_factor(*size)
            }
            IsolationTree::Internal {
                feature_idx,
                split_value,
                left,
                right,
            } => {
                if sample[*feature_idx] < *split_value {
                    left.path_length(sample, current_depth + 1)
                } else {
                    right.path_length(sample, current_depth + 1)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    n_samples: usize,
    contamination: f64,
    threshold: f64,
}

impl IsolationForest {
    /// Fit an Isolation Forest with parallel tree construction.
    pub fn fit(
        x: &Array2<f64>,
        n_trees: usize,
        sample_size: usize,
        contamination: f64,
    ) -> Self {
        let n = x.nrows();
        let actual_sample_size = sample_size.min(n);
        let height_limit = (actual_sample_size as f64).log2().ceil() as usize;

        info!(
            n_trees,
            sample_size = actual_sample_size,
            height_limit,
            contamination,
            "Fitting Isolation Forest (parallel)"
        );

        let all_indices: Vec<usize> = (0..n).collect();

        // Build trees in parallel, each with a deterministic RNG.
        let trees: Vec<IsolationTree> = (0..n_trees)
            .into_par_iter()
            .map(|i| {
                let mut rng = ChaCha8Rng::seed_from_u64(42 + i as u64);
                let indices = subsample(&all_indices, actual_sample_size, &mut rng);
                IsolationTree::build(x, &indices, height_limit, 0, &mut rng)
            })
            .collect();

        let mut forest = Self {
            trees,
            n_samples: actual_sample_size,
            contamination,
            threshold: 0.0,
        };

        forest.threshold = forest.compute_threshold(x);
        info!(threshold = forest.threshold, "Isolation Forest threshold set");

        forest
    }

    pub fn anomaly_score(&self, sample: &ArrayView1<f64>) -> f64 {
        let mean_path: f64 = self
            .trees
            .iter()
            .map(|t| t.path_length(sample, 0))
            .sum::<f64>()
            / self.trees.len() as f64;

        let c = c_factor(self.n_samples);
        2.0_f64.powf(-mean_path / c)
    }

    /// Compute anomaly scores in parallel across samples.
    pub fn anomaly_scores(&self, x: &Array2<f64>) -> Array1<f64> {
        let scores: Vec<f64> = (0..x.nrows())
            .into_par_iter()
            .map(|i| self.anomaly_score(&x.row(i)))
            .collect();
        Array1::from_vec(scores)
    }

    pub fn predict(&self, x: &Array2<f64>) -> Array1<bool> {
        let scores = self.anomaly_scores(x);
        scores.mapv(|s| s >= self.threshold)
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_string(self)?;
        std::fs::write(path, json)?;
        info!(?path, "Isolation Forest saved");
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let forest: Self = serde_json::from_str(&json)?;
        info!(?path, "Isolation Forest loaded");
        Ok(forest)
    }

    fn compute_threshold(&self, x: &Array2<f64>) -> f64 {
        let scores = self.anomaly_scores(x);
        let mut sorted: Vec<f64> = scores.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((1.0 - self.contamination) * sorted.len() as f64).ceil() as usize;
        let idx = idx.min(sorted.len().saturating_sub(1));
        sorted[idx]
    }
}

pub fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let nf = n as f64;
    let harmonic = (nf - 1.0).ln() + 0.5772156649;
    2.0 * harmonic - 2.0 * (nf - 1.0) / nf
}

fn subsample(all: &[usize], k: usize, rng: &mut impl Rng) -> Vec<usize> {
    let n = all.len();
    let k = k.min(n);
    let mut pool = all.to_vec();
    for i in 0..k {
        let j = rng.gen_range(i..n);
        pool.swap(i, j);
    }
    pool[..k].to_vec()
}
