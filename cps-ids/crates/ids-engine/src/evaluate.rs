//! Evaluation metrics for multi-class classification.
//!
//! Provides accuracy, per-class precision / recall / F1, macro-averaged
//! metrics, false positive rate, a full confusion matrix, and k-fold
//! cross-validation.

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use tracing::info;

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Summary of classification performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationReport {
    /// Overall accuracy (correct / total).
    pub accuracy: f64,
    /// Per-class precision: TP / (TP + FP).
    pub precision_per_class: Vec<f64>,
    /// Per-class recall (sensitivity): TP / (TP + FN).
    pub recall_per_class: Vec<f64>,
    /// Per-class F1 score: harmonic mean of precision and recall.
    pub f1_per_class: Vec<f64>,
    /// Macro-averaged precision across all classes.
    pub macro_precision: f64,
    /// Macro-averaged recall across all classes.
    pub macro_recall: f64,
    /// Macro-averaged F1 across all classes.
    pub macro_f1: f64,
    /// False positive rate for the *attack* classes as a whole: FP / (FP + TN)
    /// where "positive" means any non-zero class.
    pub fpr: f64,
    /// Confusion matrix (n_classes x n_classes).
    /// `confusion_matrix[[true_class, predicted_class]]` = count.
    pub confusion_matrix: Array2<usize>,
}

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

/// Compute a full classification report.
///
/// * `y_true`    — ground-truth labels (values in 0..n_classes).
/// * `y_pred`    — predicted labels (same length as y_true).
/// * `n_classes` — total number of classes.
pub fn evaluate(
    y_true: &Array1<usize>,
    y_pred: &Array1<usize>,
    n_classes: usize,
) -> ClassificationReport {
    assert_eq!(
        y_true.len(),
        y_pred.len(),
        "y_true and y_pred must have the same length"
    );
    let n = y_true.len();

    // Build confusion matrix.
    let mut cm = Array2::<usize>::zeros((n_classes, n_classes));
    for (&t, &p) in y_true.iter().zip(y_pred.iter()) {
        if t < n_classes && p < n_classes {
            cm[[t, p]] += 1;
        }
    }

    // Per-class metrics.
    let mut precision = vec![0.0_f64; n_classes];
    let mut recall = vec![0.0_f64; n_classes];
    let mut f1 = vec![0.0_f64; n_classes];

    for c in 0..n_classes {
        let tp = cm[[c, c]] as f64;
        let fp: f64 = (0..n_classes)
            .filter(|&r| r != c)
            .map(|r| cm[[r, c]] as f64)
            .sum();
        let fn_: f64 = (0..n_classes)
            .filter(|&p| p != c)
            .map(|p| cm[[c, p]] as f64)
            .sum();

        precision[c] = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        recall[c] = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        f1[c] = if precision[c] + recall[c] > 0.0 {
            2.0 * precision[c] * recall[c] / (precision[c] + recall[c])
        } else {
            0.0
        };
    }

    let macro_precision = precision.iter().sum::<f64>() / n_classes as f64;
    let macro_recall = recall.iter().sum::<f64>() / n_classes as f64;
    let macro_f1 = f1.iter().sum::<f64>() / n_classes as f64;

    // Overall accuracy.
    let correct: usize = (0..n_classes).map(|c| cm[[c, c]]).sum();
    let accuracy = if n > 0 { correct as f64 / n as f64 } else { 0.0 };

    // Binary-style FPR treating class 0 as negative and classes 1..n as
    // positive.
    let fpr = if n_classes >= 2 {
        // FP = normal samples misclassified as attack.
        let fp: f64 = (1..n_classes).map(|p| cm[[0, p]] as f64).sum();
        // TN = normal samples correctly classified as normal.
        let tn = cm[[0, 0]] as f64;
        if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 }
    } else {
        0.0
    };

    ClassificationReport {
        accuracy,
        precision_per_class: precision,
        recall_per_class: recall,
        f1_per_class: f1,
        macro_precision,
        macro_recall,
        macro_f1,
        fpr,
        confusion_matrix: cm,
    }
}

// ---------------------------------------------------------------------------
// Pretty printing
// ---------------------------------------------------------------------------

/// Print a human-readable classification report to stdout.
///
/// `label_names` should have exactly `n_classes` entries.  If shorter, numeric
/// indices are used as fallback.
pub fn print_report(report: &ClassificationReport, label_names: &[String]) {
    let nc = report.precision_per_class.len();
    println!();
    println!(
        "{:<20} {:>10} {:>10} {:>10}",
        "Class", "Precision", "Recall", "F1"
    );
    println!("{}", "-".repeat(52));
    for c in 0..nc {
        let name = label_names
            .get(c)
            .map(|s| s.as_str())
            .unwrap_or("?");
        println!(
            "{:<20} {:>10.4} {:>10.4} {:>10.4}",
            name,
            report.precision_per_class[c],
            report.recall_per_class[c],
            report.f1_per_class[c],
        );
    }
    println!("{}", "-".repeat(52));
    println!(
        "{:<20} {:>10.4} {:>10.4} {:>10.4}",
        "Macro avg", report.macro_precision, report.macro_recall, report.macro_f1,
    );
    println!();
    println!("Accuracy : {:.4}", report.accuracy);
    println!("FPR      : {:.4}", report.fpr);
    println!();

    // Print confusion matrix.
    println!("Confusion matrix (rows = true, cols = predicted):");
    print!("{:<12}", "");
    for c in 0..nc {
        let name = label_names.get(c).map(|s| s.as_str()).unwrap_or("?");
        print!("{:>10}", name);
    }
    println!();
    for r in 0..nc {
        let name = label_names.get(r).map(|s| s.as_str()).unwrap_or("?");
        print!("{:<12}", name);
        for c in 0..nc {
            print!("{:>10}", report.confusion_matrix[[r, c]]);
        }
        println!();
    }
    println!();
}

// ---------------------------------------------------------------------------
// Cross-validation
// ---------------------------------------------------------------------------

/// Perform stratified k-fold cross-validation.
///
/// * `x`                — feature matrix (n_samples x n_features).
/// * `y`                — labels (n_samples,).
/// * `k_folds`          — number of folds.
/// * `n_classes`        — total number of classes.
/// * `train_predict_fn` — a closure that receives (x_train, y_train, x_test)
///                        and returns predicted labels for x_test.
///
/// Returns one `ClassificationReport` per fold.
pub fn cross_validate<F>(
    x: &Array2<f64>,
    y: &Array1<usize>,
    k_folds: usize,
    n_classes: usize,
    train_predict_fn: F,
) -> Vec<ClassificationReport>
where
    F: Fn(&Array2<f64>, &Array1<usize>, &Array2<f64>) -> Array1<usize>,
{
    let n = x.nrows();
    assert!(k_folds >= 2, "need at least 2 folds");
    assert!(n >= k_folds, "fewer samples than folds");

    // Build fold assignments (simple sequential split; not fully stratified
    // but deterministic and sufficient for evaluation).
    let fold_size = n / k_folds;
    let mut reports = Vec::with_capacity(k_folds);

    for fold in 0..k_folds {
        let test_start = fold * fold_size;
        let test_end = if fold == k_folds - 1 {
            n
        } else {
            test_start + fold_size
        };

        // Collect train/test indices.
        let train_idx: Vec<usize> = (0..test_start).chain(test_end..n).collect();
        let test_idx: Vec<usize> = (test_start..test_end).collect();

        let x_train = select_rows(x, &train_idx);
        let y_train = select_elements(y, &train_idx);
        let x_test = select_rows(x, &test_idx);
        let y_test = select_elements(y, &test_idx);

        let y_pred = train_predict_fn(&x_train, &y_train, &x_test);
        let report = evaluate(&y_test, &y_pred, n_classes);

        info!(
            fold = fold + 1,
            accuracy = report.accuracy,
            macro_f1 = report.macro_f1,
            "Cross-validation fold complete"
        );
        reports.push(report);
    }

    reports
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn select_rows(x: &Array2<f64>, indices: &[usize]) -> Array2<f64> {
    let ncols = x.ncols();
    let mut out = Array2::<f64>::zeros((indices.len(), ncols));
    for (new_i, &orig_i) in indices.iter().enumerate() {
        for j in 0..ncols {
            out[[new_i, j]] = x[[orig_i, j]];
        }
    }
    out
}

fn select_elements(y: &Array1<usize>, indices: &[usize]) -> Array1<usize> {
    Array1::from_vec(indices.iter().map(|&i| y[i]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn perfect_classification() {
        let y_true = array![0, 0, 1, 1, 2, 2];
        let y_pred = array![0, 0, 1, 1, 2, 2];
        let report = evaluate(&y_true, &y_pred, 3);

        assert!((report.accuracy - 1.0).abs() < 1e-12);
        assert!((report.macro_f1 - 1.0).abs() < 1e-12);
        assert!((report.fpr - 0.0).abs() < 1e-12);

        for c in 0..3 {
            assert!((report.precision_per_class[c] - 1.0).abs() < 1e-12);
            assert!((report.recall_per_class[c] - 1.0).abs() < 1e-12);
        }
    }

    #[test]
    fn all_wrong() {
        let y_true = array![0, 0, 1, 1];
        let y_pred = array![1, 1, 0, 0];
        let report = evaluate(&y_true, &y_pred, 2);

        assert!((report.accuracy - 0.0).abs() < 1e-12);
        assert!((report.fpr - 1.0).abs() < 1e-12);
    }

    #[test]
    fn confusion_matrix_shape() {
        let y_true = array![0, 1, 2, 0, 1, 2];
        let y_pred = array![0, 1, 2, 1, 0, 2];
        let report = evaluate(&y_true, &y_pred, 3);
        assert_eq!(report.confusion_matrix.dim(), (3, 3));
        // Total should equal number of samples.
        assert_eq!(report.confusion_matrix.sum(), 6);
    }

    #[test]
    fn cross_validate_returns_k_reports() {
        let x = Array2::<f64>::zeros((20, 3));
        let y = Array1::from_vec(vec![0; 20]);
        let reports = cross_validate(&x, &y, 5, 2, |_x_tr, _y_tr, x_te| {
            Array1::from_vec(vec![0; x_te.nrows()])
        });
        assert_eq!(reports.len(), 5);
    }
}
