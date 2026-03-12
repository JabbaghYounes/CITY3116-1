//! Ensemble combiner that fuses predictions from the Random Forest classifier
//! and the Isolation Forest anomaly detector.
//!
//! The approach is simple: use the RF probability distribution as the primary
//! signal and boost the anomaly class whenever the Isolation Forest flags a
//! sample.

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Ensemble detector that combines RF classification probabilities with
/// Isolation Forest anomaly scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleDetector {
    /// Weight applied to Random Forest probabilities (0..1).
    pub rf_weight: f64,
    /// Weight applied to Isolation Forest anomaly boost (0..1).
    pub iforest_weight: f64,
}

impl EnsembleDetector {
    pub fn new(rf_weight: f64, iforest_weight: f64) -> Self {
        Self {
            rf_weight,
            iforest_weight,
        }
    }

    /// Combine RF pseudo-probabilities and Isolation Forest anomaly scores
    /// into a single set of class predictions.
    ///
    /// # Arguments
    ///
    /// * `rf_probs`       — (n_samples x n_classes) probability matrix from RF.
    /// * `iforest_scores` — (n_samples,) anomaly scores in [0, 1] from IForest
    ///                      (higher = more anomalous).
    /// * `n_classes`      — total number of classes.  Class 0 is assumed to be
    ///                      "Normal" by convention; all other classes represent
    ///                      attack categories.
    ///
    /// # Returns
    ///
    /// `Array1<usize>` of length n_samples with the predicted class index for
    /// each sample.
    pub fn predict(
        &self,
        rf_probs: &Array2<f64>,
        iforest_scores: &Array1<f64>,
        n_classes: usize,
    ) -> Array1<usize> {
        let n = rf_probs.nrows();
        assert_eq!(
            iforest_scores.len(),
            n,
            "iforest_scores length must match rf_probs row count"
        );
        assert!(
            n_classes >= 2,
            "Need at least 2 classes (normal + 1 attack)"
        );

        let mut predictions = Array1::<usize>::zeros(n);

        for i in 0..n {
            // Start with weighted RF probabilities.
            let mut combined = vec![0.0_f64; n_classes];
            for c in 0..n_classes.min(rf_probs.ncols()) {
                combined[c] = self.rf_weight * rf_probs[[i, c]];
            }

            // Isolation Forest anomaly boost: when the IForest score is high,
            // reduce the weight on class 0 (Normal) and spread the boost
            // evenly across all attack classes (1..n_classes).
            let anomaly_score = iforest_scores[i];
            if n_classes > 1 {
                let boost = self.iforest_weight * anomaly_score;
                combined[0] -= boost;
                if combined[0] < 0.0 {
                    combined[0] = 0.0;
                }
                let per_class_boost = boost / (n_classes - 1) as f64;
                for c in 1..n_classes {
                    combined[c] += per_class_boost;
                }
            }

            // Argmax.
            let (best_class, _best_score) = combined
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap_or((0, &0.0));

            predictions[i] = best_class;
        }

        debug!(n_samples = n, "Ensemble prediction complete");
        predictions
    }
}

impl Default for EnsembleDetector {
    /// Default weights that strongly favour the RF classifier.
    fn default() -> Self {
        Self {
            rf_weight: 0.7,
            iforest_weight: 0.3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn normal_sample_stays_normal() {
        let det = EnsembleDetector::default();
        // RF says class 0 (Normal) with high probability.
        let rf_probs = array![[0.9, 0.05, 0.05]];
        // IForest says not anomalous.
        let if_scores = array![0.1];
        let preds = det.predict(&rf_probs, &if_scores, 3);
        assert_eq!(preds[0], 0);
    }

    #[test]
    fn anomaly_boosts_attack_class() {
        let det = EnsembleDetector::new(0.5, 0.5);
        // RF is ambiguous.
        let rf_probs = array![[0.35, 0.35, 0.30]];
        // IForest confidently says anomaly.
        let if_scores = array![0.95];
        let preds = det.predict(&rf_probs, &if_scores, 3);
        // Should pick an attack class (1 or 2), not 0.
        assert_ne!(preds[0], 0, "anomaly boost should override normal");
    }

    #[test]
    fn batch_prediction_shape() {
        let det = EnsembleDetector::default();
        let rf_probs = Array2::<f64>::from_shape_vec(
            (5, 3),
            vec![
                0.8, 0.1, 0.1, 0.2, 0.7, 0.1, 0.3, 0.3, 0.4, 0.9, 0.05,
                0.05, 0.1, 0.1, 0.8,
            ],
        )
        .unwrap();
        let if_scores = array![0.1, 0.8, 0.6, 0.05, 0.9];
        let preds = det.predict(&rf_probs, &if_scores, 3);
        assert_eq!(preds.len(), 5);
    }
}
