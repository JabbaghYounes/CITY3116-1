"""Classification metrics matching Rust evaluate.rs exactly."""

import numpy as np


def evaluate(y_true, y_pred, n_classes):
    """Compute classification report matching Rust implementation."""
    n = len(y_true)
    cm = np.zeros((n_classes, n_classes), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        if 0 <= t < n_classes and 0 <= p < n_classes:
            cm[t, p] += 1

    precision = np.zeros(n_classes)
    recall = np.zeros(n_classes)
    f1 = np.zeros(n_classes)

    for c in range(n_classes):
        tp = float(cm[c, c])
        fp = float(sum(cm[r, c] for r in range(n_classes) if r != c))
        fn = float(sum(cm[c, p] for p in range(n_classes) if p != c))

        precision[c] = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall[c] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1[c] = (2 * precision[c] * recall[c] / (precision[c] + recall[c])
                 if (precision[c] + recall[c]) > 0 else 0.0)

    macro_precision = precision.mean()
    macro_recall = recall.mean()
    macro_f1 = f1.mean()

    correct = sum(cm[c, c] for c in range(n_classes))
    accuracy = correct / n if n > 0 else 0.0

    # FPR: false positives for class 0 (Normal) / (FP + TN for class 0)
    if n_classes >= 2:
        fp_0 = float(sum(cm[0, p] for p in range(1, n_classes)))
        tn_0 = float(cm[0, 0])
        fpr = fp_0 / (fp_0 + tn_0) if (fp_0 + tn_0) > 0 else 0.0
    else:
        fpr = 0.0

    return {
        "accuracy": accuracy,
        "precision_per_class": precision.tolist(),
        "recall_per_class": recall.tolist(),
        "f1_per_class": f1.tolist(),
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "fpr": fpr,
        "confusion_matrix": {
            "data": cm.flatten().tolist(),
            "dim": [n_classes, n_classes],
            "v": 1,
        },
    }


def print_report(report, label_names):
    n_classes = len(report["precision_per_class"])
    print()
    print(f"{'Class':<20} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 52)
    for c in range(n_classes):
        name = label_names[c] if c < len(label_names) else "?"
        print(f"{name:<20} {report['precision_per_class'][c]:>10.4f} "
              f"{report['recall_per_class'][c]:>10.4f} "
              f"{report['f1_per_class'][c]:>10.4f}")
    print("-" * 52)
    print(f"{'Macro avg':<20} {report['macro_precision']:>10.4f} "
          f"{report['macro_recall']:>10.4f} {report['macro_f1']:>10.4f}")
    print()
    print(f"Accuracy : {report['accuracy']:.4f}")
    print(f"FPR      : {report['fpr']:.4f}")
    print()

    cm_data = report["confusion_matrix"]["data"]
    dim = report["confusion_matrix"]["dim"]
    cm = np.array(cm_data).reshape(dim)
    print("Confusion matrix (rows = true, cols = predicted):")
    print(f"{'':12}", end="")
    for c in range(n_classes):
        name = label_names[c] if c < len(label_names) else "?"
        print(f"{name:>10}", end="")
    print()
    for r in range(n_classes):
        name = label_names[r] if r < len(label_names) else "?"
        print(f"{name:<12}", end="")
        for c in range(n_classes):
            print(f"{cm[r, c]:>10}", end="")
        print()
    print()
