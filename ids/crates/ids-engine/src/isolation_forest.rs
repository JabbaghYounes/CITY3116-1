//! Custom Isolation Forest implementation for unsupervised anomaly detection.
//!
//! The algorithm isolates anomalies by randomly selecting a feature and then
//! randomly choosing a split value between the minimum and maximum of that
//! feature.  Anomalies, being few and different, are isolated in fewer splits
//! (shorter path lengths) than normal points.
//!
//! Reference: Liu, Ting & Zhou, "Isolation Forest", ICDM 2008.

use ndarray::{Array1, Array2, ArrayView1};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;

// ---------------------------------------------------------------------------
// Tree structure
// ---------------------------------------------------------------------------

/// A single node in an isolation tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationTree {
    /// Internal split node.
    Internal {
        feature_idx: usize,
        split_value: f64,
        left: Box<IsolationTree>,
        right: Box<IsolationTree>,
    },
    /// Leaf node storing the number of samples that reached it.
    Leaf {
        size: usize,
    },
}

impl IsolationTree {
    /// Build an isolation tree from a data subset.
    ///
    /// `indices` — row indices into `x` that belong to this node.
    /// `height_limit` — maximum tree depth.
    /// `current_height` — depth of this node.
    fn build(
        x: &Array2<f64>,
        indices: &[usize],
        height_limit: usize,
        current_height: usize,
        rng: &mut impl Rng,
    ) -> Self {
        let n = indices.len();

        // Base case: leaf.
        if current_height >= height_limit || n <= 1 {
            return IsolationTree::Leaf { size: n };
        }

        let n_features = x.ncols();
        // Pick a random feature.
        let feature_idx = rng.gen_range(0..n_features);

        // Compute min / max of that feature over the current subset.
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

        // If the feature is constant, can't split further.
        if (max_val - min_val).abs() < f64::EPSILON {
            return IsolationTree::Leaf { size: n };
        }

        // Random split value in (min, max).
        let split_value = rng.gen_range(min_val..max_val);

        // Partition indices.
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

    /// Return the path length for a single sample traversing this tree.
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

// ---------------------------------------------------------------------------
// Forest
// ---------------------------------------------------------------------------

/// Isolation Forest ensemble for anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    /// Number of training samples (used for normalisation).
    n_samples: usize,
    /// Expected proportion of anomalies; used to derive the decision threshold.
    contamination: f64,
    /// Score threshold above which a sample is classified as anomalous.
    threshold: f64,
}

impl IsolationForest {
    /// Fit an Isolation Forest on the provided data.
    ///
    /// * `x`             — data matrix (n_samples x n_features)
    /// * `n_trees`       — number of isolation trees
    /// * `sample_size`   — subsample size for each tree (commonly 256)
    /// * `contamination` — expected fraction of anomalies (e.g. 0.05)
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
            "Fitting Isolation Forest"
        );

        let mut rng = rand::thread_rng();
        let all_indices: Vec<usize> = (0..n).collect();

        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            // Subsample without replacement.
            let indices = subsample(&all_indices, actual_sample_size, &mut rng);
            let tree = IsolationTree::build(x, &indices, height_limit, 0, &mut rng);
            trees.push(tree);
        }

        let mut forest = Self {
            trees,
            n_samples: actual_sample_size,
            contamination,
            threshold: 0.0, // will be set below
        };

        // Determine the threshold from the training data scores.
        forest.threshold = forest.compute_threshold(x);
        info!(threshold = forest.threshold, "Isolation Forest threshold set");

        forest
    }

    /// Compute the anomaly score for a single sample.
    ///
    /// The score is in [0, 1] where values close to 1 indicate anomalies.
    pub fn anomaly_score(&self, sample: &ArrayView1<f64>) -> f64 {
        let mean_path: f64 = self
            .trees
            .iter()
            .map(|t| t.path_length(sample, 0))
            .sum::<f64>()
            / self.trees.len() as f64;

        let c = c_factor(self.n_samples);
        // s(x, n) = 2^(-E[h(x)] / c(n))
        2.0_f64.powf(-mean_path / c)
    }

    /// Compute anomaly scores for every row in the matrix.
    pub fn anomaly_scores(&self, x: &Array2<f64>) -> Array1<f64> {
        Array1::from_vec(
            (0..x.nrows())
                .map(|i| self.anomaly_score(&x.row(i)))
                .collect(),
        )
    }

    /// Predict whether each sample is anomalous.
    ///
    /// Returns `true` for anomalies, `false` for normal points.
    pub fn predict(&self, x: &Array2<f64>) -> Array1<bool> {
        let scores = self.anomaly_scores(x);
        scores.mapv(|s| s >= self.threshold)
    }

    /// Persist the forest to disk.
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        info!(?path, "Isolation Forest saved");
        Ok(())
    }

    /// Load a previously saved forest.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let forest: Self = serde_json::from_str(&json)?;
        info!(?path, "Isolation Forest loaded");
        Ok(forest)
    }

    // ----- internals -----

    /// Set the threshold at the `(1 - contamination)` quantile of training
    /// scores so that roughly `contamination` fraction of training points are
    /// flagged as anomalies.
    fn compute_threshold(&self, x: &Array2<f64>) -> f64 {
        let mut scores: Vec<f64> = (0..x.nrows())
            .map(|i| self.anomaly_score(&x.row(i)))
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((1.0 - self.contamination) * scores.len() as f64).ceil() as usize;
        let idx = idx.min(scores.len().saturating_sub(1));
        scores[idx]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Average path length of an unsuccessful search in a Binary Search Tree —
/// used to normalise the isolation path length.
///
/// `c(n) = 2 H(n-1) - 2(n-1)/n`  where `H(i)` is the harmonic number
/// approximated by `ln(i) + 0.5772156649` (Euler-Mascheroni constant).
pub fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let nf = n as f64;
    let harmonic = (nf - 1.0).ln() + 0.5772156649;
    2.0 * harmonic - 2.0 * (nf - 1.0) / nf
}

/// Sample `k` indices without replacement from `all` using Fisher-Yates.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn c_factor_values() {
        assert_eq!(c_factor(0), 0.0);
        assert_eq!(c_factor(1), 0.0);
        // c(2) = 2 * (ln(1) + euler) - 2*(1)/2 = 2*0.577.. - 1 ≈ 0.154
        let c2 = c_factor(2);
        assert!((c2 - 0.1544).abs() < 0.01, "c(2) = {c2}");
    }

    #[test]
    fn anomaly_scores_in_range() {
        // Create a simple dataset with one clear outlier.
        let mut data = Array2::<f64>::zeros((100, 2));
        for i in 0..99 {
            data[[i, 0]] = (i as f64) / 100.0;
            data[[i, 1]] = (i as f64) / 100.0;
        }
        // Outlier
        data[[99, 0]] = 100.0;
        data[[99, 1]] = 100.0;

        let forest = IsolationForest::fit(&data, 50, 64, 0.05);

        for i in 0..data.nrows() {
            let score = forest.anomaly_score(&data.row(i));
            assert!(
                (0.0..=1.0).contains(&score),
                "score out of range: {score}"
            );
        }

        // The outlier should have a higher score than most normal points.
        let outlier_score = forest.anomaly_score(&data.row(99));
        let normal_score = forest.anomaly_score(&data.row(50));
        assert!(
            outlier_score > normal_score,
            "outlier ({outlier_score}) should score higher than normal ({normal_score})"
        );
    }

    #[test]
    fn predict_returns_correct_shape() {
        let data = array![[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]];
        let forest = IsolationForest::fit(&data, 10, 3, 0.1);
        let preds = forest.predict(&data);
        assert_eq!(preds.len(), 3);
    }
}
