#!/usr/bin/env python3
"""Export trained CNN+LSTM models from .pt to .onnx format for Rust inference."""

import argparse
import json
import sys
from pathlib import Path

import torch

from model import CnnLstm, CnnLstmConfig


def export_model(model_dir: Path, output_path: Path | None = None):
    """Load a .pt model and export it to ONNX."""
    pt_path = model_dir / "cnn_lstm_model.pt"
    report_path = model_dir / "evaluation_report.json"

    if not pt_path.exists():
        print(f"ERROR: {pt_path} not found")
        sys.exit(1)

    # Read model config from evaluation report
    with open(report_path) as f:
        report = json.load(f)
    cfg_data = report["model_config"]

    cfg = CnnLstmConfig(
        n_features=cfg_data["n_features"],
        n_classes=cfg_data["n_classes"],
        lstm_hidden=cfg_data["lstm_hidden"],
        lstm_layers=cfg_data["lstm_layers"],
        dropout=cfg_data["dropout"],
    )

    # Load model weights
    model = CnnLstm(cfg)
    model.load_state_dict(torch.load(pt_path, map_location="cpu", weights_only=True))
    model.eval()

    # Dummy input: (batch=1, n_features)
    dummy = torch.randn(1, cfg.n_features)

    # Export
    if output_path is None:
        output_path = model_dir / "cnn_lstm_model.onnx"

    torch.onnx.export(
        model,
        dummy,
        str(output_path),
        input_names=["features"],
        output_names=["logits"],
        dynamic_axes={
            "features": {0: "batch"},
            "logits": {0: "batch"},
        },
        opset_version=17,
    )
    print(f"Exported: {output_path} ({output_path.stat().st_size / 1024:.1f} KB)")
    print(f"  n_features={cfg.n_features}, n_classes={cfg.n_classes}")


def main():
    parser = argparse.ArgumentParser(description="Export CNN+LSTM to ONNX")
    parser.add_argument(
        "--model-dir",
        type=Path,
        nargs="+",
        default=[
            Path("data/models/model-b"),
            Path("data/models/model-d"),
        ],
        help="Model directories containing cnn_lstm_model.pt",
    )
    args = parser.parse_args()

    for d in args.model_dir:
        print(f"\n--- Exporting {d} ---")
        export_model(d)


if __name__ == "__main__":
    main()
