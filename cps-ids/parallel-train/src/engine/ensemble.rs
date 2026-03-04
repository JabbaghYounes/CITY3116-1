use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleDetector {
    pub rf_weight: f64,
    pub iforest_weight: f64,
}

impl EnsembleDetector {
    pub fn new(rf_weight: f64, iforest_weight: f64) -> Self {
        Self {
            rf_weight,
            iforest_weight,
        }
    }

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
            let mut combined = vec![0.0_f64; n_classes];
            for c in 0..n_classes.min(rf_probs.ncols()) {
                combined[c] = self.rf_weight * rf_probs[[i, c]];
            }

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
    fn default() -> Self {
        Self {
            rf_weight: 0.7,
            iforest_weight: 0.3,
        }
    }
}
