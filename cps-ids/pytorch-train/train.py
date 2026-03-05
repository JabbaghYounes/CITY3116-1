"""CNN+LSTM IDS training — Python PyTorch port of Rust cnn-lstm-train.

Supports AMD GPUs via ROCm and NVIDIA GPUs via CUDA.
CLI flags match the Rust binary for consistency.
"""

import argparse
import json
import time
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from model import CnnLstm, CnnLstmConfig
from preprocessing import MinMaxScaler, smote
from evaluate import evaluate, print_report
from data_loaders import (
    load_nsl_kdd, load_cicids2017, load_unsw_nb15, load_combined,
    LABEL_NAMES,
)


def parse_args():
    p = argparse.ArgumentParser(description="CNN+LSTM IDS training (PyTorch)")
    p.add_argument("--dataset", required=True,
                   choices=["nsl-kdd", "cicids2017", "unsw-nb15", "combined"])
    p.add_argument("--nsl-train", type=str)
    p.add_argument("--nsl-test", type=str)
    p.add_argument("--cicids-dir", type=str)
    p.add_argument("--unsw-data", type=str)
    p.add_argument("--unsw-label", type=str)
    p.add_argument("--output-dir", type=str, default="data/models/model-a")
    p.add_argument("--no-smote", action="store_true")
    p.add_argument("--smote-target", type=int, default=0)
    p.add_argument("--batch-size", type=int, default=512)
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--learning-rate", type=float, default=1e-3)
    p.add_argument("--patience", type=int, default=5)
    p.add_argument("--lstm-hidden", type=int, default=128)
    p.add_argument("--lstm-layers", type=int, default=2)
    p.add_argument("--dropout", type=float, default=0.3)
    return p.parse_args()


def get_device():
    if torch.cuda.is_available():
        dev = torch.device("cuda")
        print(f"[+] Using GPU: {torch.cuda.get_device_name(0)}")
        return dev
    print("[!] No GPU detected — using CPU")
    return torch.device("cpu")


def load_dataset(args):
    ds = args.dataset
    if ds == "nsl-kdd":
        assert args.nsl_train and args.nsl_test, "--nsl-train and --nsl-test required"
        return load_nsl_kdd(args.nsl_train, args.nsl_test)
    elif ds == "cicids2017":
        assert args.cicids_dir, "--cicids-dir required"
        return load_cicids2017(args.cicids_dir)
    elif ds == "unsw-nb15":
        assert args.unsw_data and args.unsw_label, "--unsw-data and --unsw-label required"
        return load_unsw_nb15(args.unsw_data, args.unsw_label)
    elif ds == "combined":
        assert args.nsl_train and args.nsl_test, "--nsl-train and --nsl-test required"
        assert args.cicids_dir, "--cicids-dir required"
        assert args.unsw_data and args.unsw_label, "--unsw-data and --unsw-label required"
        return load_combined(
            args.nsl_train, args.nsl_test,
            args.cicids_dir,
            args.unsw_data, args.unsw_label,
        )
    else:
        raise ValueError(f"Unknown dataset: {ds}")


def to_tensor(arr, device, dtype=torch.float32):
    return torch.tensor(np.ascontiguousarray(arr), dtype=dtype, device=device)


def batched_forward(model, x, batch_size, training=False):
    n = x.size(0)
    if n <= batch_size:
        return model(x) if not training else model(x)
    outputs = []
    for start in range(0, n, batch_size):
        end = min(start + batch_size, n)
        outputs.append(model(x[start:end]))
    return torch.cat(outputs, dim=0)


def train(args):
    device = get_device()
    t0 = time.time()

    # Load data
    print("\n=== Loading Dataset ===")
    split = load_dataset(args)
    n_features = split.x_train.shape[1]
    n_classes = len(split.label_names)
    print(f"Dataset: {split.x_train.shape[0]} train, {split.x_val.shape[0]} val, "
          f"{split.x_test.shape[0]} test, {n_features} features, {n_classes} classes")

    # Normalize
    print("\n=== Normalizing ===")
    scaler = MinMaxScaler()
    x_train_scaled = scaler.fit_transform(split.x_train)
    x_val_scaled = scaler.transform(split.x_val)
    x_test_scaled = scaler.transform(split.x_test)

    # Optional SMOTE
    if not args.no_smote:
        target = args.smote_target
        if target == 0:
            from collections import Counter
            dist = Counter(split.y_train)
            target = max(dist.values())
        print(f"\n=== SMOTE (target={target}) ===")
        x_train_final, y_train_final = smote(x_train_scaled, split.y_train, target, 5)
        print(f"After SMOTE: {len(x_train_final)} samples")
    else:
        x_train_final = x_train_scaled
        y_train_final = split.y_train

    n_train_samples = len(x_train_final)

    # Convert to tensors
    print("\n=== Converting to tensors ===")
    x_train_t = to_tensor(x_train_final, device)
    y_train_t = to_tensor(y_train_final, device, dtype=torch.long)
    x_val_t = to_tensor(x_val_scaled, device)
    y_val_t = to_tensor(split.y_val, device, dtype=torch.long)
    x_test_t = to_tensor(x_test_scaled, device)

    # Model
    cfg = CnnLstmConfig(
        n_features=n_features,
        n_classes=n_classes,
        lstm_hidden=args.lstm_hidden,
        lstm_layers=args.lstm_layers,
        dropout=args.dropout,
    )
    model = CnnLstm(cfg).to(device)
    print(f"\nCNN+LSTM: {n_features} features, {n_classes} classes, "
          f"hidden={args.lstm_hidden}, layers={args.lstm_layers}, dropout={args.dropout}")
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Total parameters: {total_params:,}")

    # Optimizer
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)
    criterion = nn.CrossEntropyLoss()

    batch_size = args.batch_size
    n_batches = (n_train_samples + batch_size - 1) // batch_size

    print(f"\nTraining: {n_train_samples} samples, {n_batches} batches/epoch, device={device}")
    print()

    # Training state
    train_losses = []
    val_losses = []
    val_accuracies = []
    best_val_loss = float("inf")
    best_epoch = 0
    epochs_no_improve = 0
    lr_no_improve = 0
    current_lr = args.learning_rate
    lr_decay_factor = 0.5
    lr_decay_patience = 3
    lr_floor = 1e-6
    best_state = None

    for epoch in range(args.epochs):
        model.train()

        # Shuffle
        perm = torch.randperm(n_train_samples, device=device)
        x_shuffled = x_train_t[perm]
        y_shuffled = y_train_t[perm]

        epoch_loss = 0.0
        for b in range(n_batches):
            start = b * batch_size
            end = min(start + batch_size, n_train_samples)
            xb = x_shuffled[start:end]
            yb = y_shuffled[start:end]

            logits = model(xb)
            loss = criterion(logits, yb)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg_train_loss = epoch_loss / n_batches
        train_losses.append(avg_train_loss)

        # Validate
        model.eval()
        with torch.no_grad():
            val_logits = batched_forward(model, x_val_t, batch_size)
            vl = criterion(val_logits, y_val_t).item()
            preds = val_logits.argmax(dim=1)
            correct = (preds == y_val_t).float().sum().item()
            val_acc = correct / len(y_val_t)
        val_losses.append(vl)
        val_accuracies.append(val_acc)

        print(f"epoch {epoch+1}/{args.epochs}: train_loss={avg_train_loss:.4f}, "
              f"val_loss={vl:.4f}, val_acc={val_acc:.4f}, lr={current_lr:.2e}")

        # Early stopping + LR decay
        if vl < best_val_loss:
            best_val_loss = vl
            best_epoch = epoch
            epochs_no_improve = 0
            lr_no_improve = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            epochs_no_improve += 1
            lr_no_improve += 1

            if lr_no_improve >= lr_decay_patience and current_lr > lr_floor:
                current_lr = max(current_lr * lr_decay_factor, lr_floor)
                for pg in optimizer.param_groups:
                    pg["lr"] = current_lr
                lr_no_improve = 0
                print(f"  reducing learning rate to {current_lr:.2e}")

            if epochs_no_improve >= args.patience:
                print(f"  early stopping at epoch {epoch+1} (best epoch {best_epoch+1})")
                break

    # Reload best weights
    if best_state is not None:
        model.load_state_dict(best_state)
        model.to(device)

    best_val_acc = val_accuracies[best_epoch] if best_epoch < len(val_accuracies) else 0.0
    print(f"\nBest epoch: {best_epoch+1}, val_loss={best_val_loss:.4f}, val_acc={best_val_acc:.4f}")

    # Evaluate on test set
    print(f"\n=== Evaluating on test set ({split.x_test.shape[0]} samples) ===")
    model.eval()
    with torch.no_grad():
        test_logits = batched_forward(model, x_test_t, batch_size)
        test_preds = test_logits.argmax(dim=1).cpu().numpy()

    report = evaluate(split.y_test, test_preds, n_classes)

    print("\n=== CNN+LSTM Test Results ===")
    print_report(report, split.label_names)

    # Save artifacts
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "cnn_lstm_model.pt"
    scaler_path = output_dir / "scaler.json"
    report_path = output_dir / "evaluation_report.json"

    torch.save(model.state_dict(), model_path)
    print(f"Model saved to {model_path}")

    scaler.save(str(scaler_path))
    print(f"Scaler saved to {scaler_path}")

    report_json = {
        "cnn_lstm": report,
        "training_metrics": {
            "best_epoch": best_epoch + 1,
            "best_val_loss": best_val_loss,
            "final_val_accuracy": val_accuracies[-1] if val_accuracies else 0.0,
            "train_losses": train_losses,
            "val_losses": val_losses,
            "val_accuracies": val_accuracies,
        },
        "model_config": {
            "n_features": n_features,
            "n_classes": n_classes,
            "lstm_hidden": args.lstm_hidden,
            "lstm_layers": args.lstm_layers,
            "dropout": args.dropout,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
        },
        "dataset": args.dataset,
        "n_train_samples": n_train_samples,
    }
    with open(report_path, "w") as f:
        json.dump(report_json, f, indent=2)
    print(f"Report saved to {report_path}")

    elapsed = time.time() - t0
    print(f"\nTraining complete in {elapsed:.1f}s")


if __name__ == "__main__":
    train(parse_args())
