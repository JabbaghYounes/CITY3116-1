//! Custom parallel Random Forest classifier.
//!
//! Replaces smartcore's single-threaded RF with a fully custom CART
//! implementation. Trees are built in parallel via rayon. The tree structure
//! derives Serialize/Deserialize for instant save/load (no retraining).
//!
//! Key improvements over the original smartcore wrapper:
//! - Parallel tree construction (~12-14x speedup on 16 cores)
//! - Real `predict_proba` from vote fractions (not one-hot approximation)
//! - Serializable tree nodes (instant model save/load)

use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

// ---------------------------------------------------------------------------
// Decision tree node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Node {
    /// Internal split node.
    Split {
        feature_idx: usize,
        threshold: f64,
        left: Box<Node>,
        right: Box<Node>,
    },
    /// Leaf node with class counts from the training samples that reached it.
    Leaf {
        /// counts[c] = number of training samples of class c at this leaf.
        counts: Vec<usize>,
    },
}

impl Node {
    /// Predict the majority class for a single sample.
    fn predict(&self, sample: &[f64]) -> usize {
        match self {
            Node::Leaf { counts } => counts
                .iter()
                .enumerate()
                .max_by_key(|(_, &c)| c)
                .map(|(cls, _)| cls)
                .unwrap_or(0),
            Node::Split {
                feature_idx,
                threshold,
                left,
                right,
            } => {
                if sample[*feature_idx] <= *threshold {
                    left.predict(sample)
                } else {
                    right.predict(sample)
                }
            }
        }
    }

    /// Return the class counts at the leaf for a single sample.
    fn leaf_counts(&self, sample: &[f64]) -> &[usize] {
        match self {
            Node::Leaf { counts } => counts,
            Node::Split {
                feature_idx,
                threshold,
                left,
                right,
            } => {
                if sample[*feature_idx] <= *threshold {
                    left.leaf_counts(sample)
                } else {
                    right.leaf_counts(sample)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CART tree builder
// ---------------------------------------------------------------------------

/// Build a CART decision tree using Gini impurity.
fn build_tree(
    x: &Array2<f64>,
    y: &[usize],
    indices: &[usize],
    n_classes: usize,
    max_depth: usize,
    min_samples_split: usize,
    max_features: usize,
    depth: usize,
    rng: &mut impl Rng,
) -> Node {
    // Count classes at this node.
    let mut counts = vec![0usize; n_classes];
    for &i in indices {
        counts[y[i]] += 1;
    }

    // Check stopping conditions.
    let n = indices.len();
    let n_non_zero = counts.iter().filter(|&&c| c > 0).count();

    if depth >= max_depth || n < min_samples_split || n_non_zero <= 1 {
        return Node::Leaf { counts };
    }

    // Find the best split across a random subset of features.
    let n_features = x.ncols();
    let features_to_try = random_feature_indices(n_features, max_features, rng);

    let parent_gini = gini_impurity(&counts, n);
    let mut best_gain = 0.0_f64;
    let mut best_feature = 0;
    let mut best_threshold = 0.0;
    let mut best_left = Vec::new();
    let mut best_right = Vec::new();

    for &feat in &features_to_try {
        // Collect and sort feature values for this subset.
        let mut vals: Vec<(f64, usize)> = indices.iter().map(|&i| (x[[i, feat]], i)).collect();
        vals.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Track running class counts for left split.
        let mut left_counts = vec![0usize; n_classes];
        let mut right_counts = counts.clone();
        let mut left_n = 0usize;
        let mut right_n = n;

        for i in 0..vals.len() - 1 {
            let (val, idx) = vals[i];
            let cls = y[idx];
            left_counts[cls] += 1;
            right_counts[cls] -= 1;
            left_n += 1;
            right_n -= 1;

            // Skip if next value is the same (no meaningful split point).
            if (vals[i + 1].0 - val).abs() < f64::EPSILON {
                continue;
            }

            let threshold = (val + vals[i + 1].0) / 2.0;

            let left_gini = gini_impurity(&left_counts, left_n);
            let right_gini = gini_impurity(&right_counts, right_n);
            let weighted = (left_n as f64 * left_gini + right_n as f64 * right_gini) / n as f64;
            let gain = parent_gini - weighted;

            if gain > best_gain {
                best_gain = gain;
                best_feature = feat;
                best_threshold = threshold;
                // Store split indices.
                best_left = vals[..=i].iter().map(|&(_, idx)| idx).collect();
                best_right = vals[i + 1..].iter().map(|&(_, idx)| idx).collect();
            }
        }
    }

    // If no useful split was found, make a leaf.
    if best_gain <= 0.0 || best_left.is_empty() || best_right.is_empty() {
        return Node::Leaf { counts };
    }

    let left = build_tree(
        x, y, &best_left, n_classes, max_depth, min_samples_split, max_features, depth + 1, rng,
    );
    let right = build_tree(
        x, y, &best_right, n_classes, max_depth, min_samples_split, max_features, depth + 1, rng,
    );

    Node::Split {
        feature_idx: best_feature,
        threshold: best_threshold,
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Gini impurity: 1 - sum(p_i^2)
fn gini_impurity(counts: &[usize], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let t = total as f64;
    1.0 - counts.iter().map(|&c| (c as f64 / t).powi(2)).sum::<f64>()
}

/// Select `k` random feature indices without replacement.
fn random_feature_indices(n_features: usize, k: usize, rng: &mut impl Rng) -> Vec<usize> {
    let k = k.min(n_features);
    let mut indices: Vec<usize> = (0..n_features).collect();
    for i in 0..k {
        let j = rng.gen_range(i..n_features);
        indices.swap(i, j);
    }
    indices[..k].to_vec()
}

/// Generate a bootstrap sample (sampling with replacement).
fn bootstrap_sample(n: usize, rng: &mut impl Rng) -> Vec<usize> {
    (0..n).map(|_| rng.gen_range(0..n)).collect()
}

// ---------------------------------------------------------------------------
// Random Forest model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFModel {
    trees: Vec<Node>,
    pub n_classes: usize,
    pub n_features: usize,
    n_trees: usize,
}

impl RFModel {
    /// Train a parallel Random Forest.
    ///
    /// Builds `n_trees` (default 100) CART decision trees in parallel using rayon.
    /// Each tree is trained on a bootstrap sample with `sqrt(n_features)` random
    /// features considered at each split.
    pub fn train(x: &Array2<f64>, y: &Array1<usize>) -> Result<Self> {
        let n_features = x.ncols();
        let n_classes = *y.iter().max().unwrap_or(&0) + 1;
        let n_samples = x.nrows();
        let n_trees = 100;
        let max_depth = 20;
        let min_samples_split = 2;
        let max_features = (n_features as f64).sqrt().ceil() as usize;

        info!(
            n_samples,
            n_features,
            n_classes,
            n_trees,
            max_depth,
            max_features,
            "Training parallel Random Forest"
        );

        let y_vec: Vec<usize> = y.to_vec();

        let trees: Vec<Node> = (0..n_trees)
            .into_par_iter()
            .map(|tree_idx| {
                let mut rng = ChaCha8Rng::seed_from_u64(42 + tree_idx as u64);
                let bootstrap = bootstrap_sample(n_samples, &mut rng);

                build_tree(
                    x,
                    &y_vec,
                    &bootstrap,
                    n_classes,
                    max_depth,
                    min_samples_split,
                    max_features,
                    0,
                    &mut rng,
                )
            })
            .collect();

        info!("Random Forest training complete ({} trees)", trees.len());

        Ok(Self {
            trees,
            n_classes,
            n_features,
            n_trees,
        })
    }

    /// Predict class labels for all samples (parallel across trees).
    pub fn predict(&self, x: &Array2<f64>) -> Result<Array1<usize>> {
        let n = x.nrows();

        // Get predictions from all trees in parallel.
        let all_preds: Vec<Vec<usize>> = self
            .trees
            .par_iter()
            .map(|tree| {
                (0..n)
                    .map(|i| tree.predict(&x.row(i).to_vec()))
                    .collect()
            })
            .collect();

        // Majority vote per sample.
        let mut final_preds = Array1::<usize>::zeros(n);
        for i in 0..n {
            let mut votes = vec![0u32; self.n_classes];
            for tree_preds in &all_preds {
                let cls = tree_preds[i];
                if cls < self.n_classes {
                    votes[cls] += 1;
                }
            }
            final_preds[i] = votes
                .iter()
                .enumerate()
                .max_by_key(|(_, &v)| v)
                .map(|(cls, _)| cls)
                .unwrap_or(0);
        }
        Ok(final_preds)
    }

    /// Real soft probabilities from vote fractions across all trees.
    ///
    /// Unlike the original smartcore wrapper which used a one-hot approximation,
    /// this computes actual vote proportions. For example, if 70 out of 100 trees
    /// predict class 0 and 30 predict class 1, the probabilities are [0.7, 0.3, ...].
    /// This allows the ensemble to meaningfully combine RF confidence with IForest scores.
    pub fn predict_proba(&self, x: &Array2<f64>) -> Result<Array2<f64>> {
        let n = x.nrows();
        let nc = self.n_classes;

        // Get predictions from all trees in parallel.
        let all_preds: Vec<Vec<usize>> = self
            .trees
            .par_iter()
            .map(|tree| {
                (0..n)
                    .map(|i| tree.predict(&x.row(i).to_vec()))
                    .collect()
            })
            .collect();

        let total = self.n_trees as f64;
        let mut proba = Array2::<f64>::zeros((n, nc));
        for i in 0..n {
            for tree_preds in &all_preds {
                let cls = tree_preds[i];
                if cls < nc {
                    proba[[i, cls]] += 1.0;
                }
            }
            for c in 0..nc {
                proba[[i, c]] /= total;
            }
        }
        Ok(proba)
    }

    /// Save the model to JSON (tree structures only — instant, no retraining on load).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string(self).context("Failed to serialise RFModel")?;
        std::fs::write(path, json).context("Failed to write RF model file")?;
        info!(?path, "Random Forest model saved");
        Ok(())
    }

    /// Load a previously saved model.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path).context("Failed to read RF model file")?;
        let model: Self = serde_json::from_str(&json).context("Failed to deserialise RFModel")?;
        info!(?path, "Random Forest model loaded");
        Ok(model)
    }
}
