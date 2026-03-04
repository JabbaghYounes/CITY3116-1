use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationReport {
    pub accuracy: f64,
    pub precision_per_class: Vec<f64>,
    pub recall_per_class: Vec<f64>,
    pub f1_per_class: Vec<f64>,
    pub macro_precision: f64,
    pub macro_recall: f64,
    pub macro_f1: f64,
    pub fpr: f64,
    pub confusion_matrix: Array2<usize>,
}

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

    let mut cm = Array2::<usize>::zeros((n_classes, n_classes));
    for (&t, &p) in y_true.iter().zip(y_pred.iter()) {
        if t < n_classes && p < n_classes {
            cm[[t, p]] += 1;
        }
    }

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

    let correct: usize = (0..n_classes).map(|c| cm[[c, c]]).sum();
    let accuracy = if n > 0 { correct as f64 / n as f64 } else { 0.0 };

    let fpr = if n_classes >= 2 {
        let fp: f64 = (1..n_classes).map(|p| cm[[0, p]] as f64).sum();
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
