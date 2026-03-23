#!/usr/bin/env python3
"""CNN+LSTM inference server — reads JSON feature vectors from stdin, writes predictions to stdout.

Protocol (JSON Lines):
  Request:  {"features": [0.1, 0.2, ...]}
  Response: {"class": 1, "category": "DoS", "confidence": 0.95, "probabilities": [0.02, 0.95, 0.01, 0.01, 0.01]}

  Special commands:
  Request:  {"command": "info"}
  Response: {"n_features": 78, "n_classes": 5, "status": "ready"}

The server loads the ONNX model and scaler on startup, then processes
one request per line until stdin is closed.
"""

import json
import sys
from pathlib import Path

import numpy as np

CLASS_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]


def load_scaler(scaler_path):
    """Load MinMaxScaler from JSON (matches Rust MinMaxScaler format)."""
    with open(scaler_path) as f:
        data = json.load(f)
    return np.array(data["min"]), np.array(data["max"])


def scale_features(features, scaler_min, scaler_max):
    """Apply min-max scaling to [0, 1]."""
    x = np.array(features, dtype=np.float64)
    range_ = scaler_max - scaler_min
    safe = range_ > np.finfo(np.float64).eps
    result = np.zeros_like(x)
    result[safe] = (x[safe] - scaler_min[safe]) / range_[safe]
    return result.astype(np.float32)


def softmax(logits):
    """Compute softmax probabilities."""
    x = logits - np.max(logits)
    e = np.exp(x)
    return e / e.sum()


def main():
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <model.onnx> <scaler.json>",
            file=sys.stderr,
        )
        sys.exit(1)

    model_path = Path(sys.argv[1])
    scaler_path = Path(sys.argv[2])

    # Import onnxruntime
    import onnxruntime as ort

    # Load model and scaler
    session = ort.InferenceSession(str(model_path))
    scaler_min, scaler_max = load_scaler(scaler_path)
    n_features = len(scaler_min)
    input_name = session.get_inputs()[0].name

    # Signal ready
    print(json.dumps({"status": "ready", "n_features": n_features}), flush=True)

    # Process requests
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"invalid JSON: {e}"}), flush=True)
            continue

        # Info command
        if req.get("command") == "info":
            print(json.dumps({
                "n_features": n_features,
                "n_classes": 5,
                "status": "ready",
            }), flush=True)
            continue

        # Inference request
        features = req.get("features")
        if features is None:
            print(json.dumps({"error": "missing 'features' field"}), flush=True)
            continue

        if len(features) != n_features:
            print(json.dumps({
                "error": f"expected {n_features} features, got {len(features)}",
            }), flush=True)
            continue

        # Scale and run inference
        scaled = scale_features(features, scaler_min, scaler_max)
        input_array = scaled.reshape(1, n_features)
        logits = session.run(None, {input_name: input_array})[0][0]
        probs = softmax(logits)
        class_idx = int(np.argmax(probs))

        print(json.dumps({
            "class": class_idx,
            "category": CLASS_NAMES[class_idx],
            "confidence": round(float(probs[class_idx]), 6),
            "probabilities": [round(float(p), 6) for p in probs],
        }), flush=True)


if __name__ == "__main__":
    main()
