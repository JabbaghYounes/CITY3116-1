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
MODBUS_PORTS = {502, 5502, 5520}

# CIC-IDS2017 feature indices used by the Modbus anomaly detector.
# These are the raw (unscaled) values from extract_cicids_features().
IDX_DST_PORT = 0
IDX_FLOW_DURATION_US = 1
IDX_TOTAL_FWD_PKTS = 2
IDX_TOTAL_BWD_PKTS = 3
IDX_FLOW_BYTES_PER_S = 14
IDX_FLOW_PKTS_PER_S = 15
IDX_FLOW_IAT_MEAN = 16
IDX_FWD_PKTS_PER_S = 36
IDX_BWD_PKTS_PER_S = 37


def modbus_anomaly_classify(features):
    """Classify Modbus flows using threshold-based anomaly detection.

    Returns (class_index, category, confidence) or None if not a Modbus flow.
    Thresholds derived from the attack-framework.py traffic patterns.
    """
    dst_port = int(features[IDX_DST_PORT])
    if dst_port not in MODBUS_PORTS:
        return None

    pkts_per_sec = features[IDX_FLOW_PKTS_PER_S]
    fwd_pkts = features[IDX_TOTAL_FWD_PKTS]
    bwd_pkts = features[IDX_TOTAL_BWD_PKTS]
    total_pkts = fwd_pkts + bwd_pkts
    fwd_pps = features[IDX_FWD_PKTS_PER_S]
    duration_sec = features[IDX_FLOW_DURATION_US] / 1_000_000.0
    iat_mean = features[IDX_FLOW_IAT_MEAN]

    # DoS — Modbus flood: extreme read rates
    if pkts_per_sec > 50 and total_pkts > 20:
        conf = min(pkts_per_sec / 200.0, 0.99)
        return (1, "DoS", round(conf, 4))

    # R2L — Command injection / write attacks: sustained writes at moderate rate
    if (duration_sec > 5 and 0.5 < fwd_pps <= 50
            and fwd_pkts > 5 and bwd_pkts > 0
            and fwd_pkts / max(bwd_pkts, 1) > 1.5):
        return (3, "R2L", 0.70)

    # Probe — Short reconnaissance bursts
    if duration_sec < 30 and fwd_pps > 5 and fwd_pkts > 5 and pkts_per_sec <= 50:
        return (2, "Probe", 0.65)

    # Normal — low-rate PLC polling
    return (0, "Normal", 0.95)


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

        # CNN+LSTM inference (always runs)
        scaled = scale_features(features, scaler_min, scaler_max)
        input_array = scaled.reshape(1, n_features)
        logits = session.run(None, {input_name: input_array})[0][0]
        probs = softmax(logits)
        cnn_class = int(np.argmax(probs))
        cnn_conf = float(probs[cnn_class])

        # Modbus anomaly detector (runs on Modbus flows)
        modbus_result = modbus_anomaly_classify(features)

        # Choose the best prediction: use Modbus detector if it finds
        # an attack, otherwise fall back to CNN+LSTM
        if modbus_result and modbus_result[0] != 0:
            # Modbus detector found an attack
            final_class, final_cat, final_conf = modbus_result
            model = "modbus-anomaly"
        else:
            final_class = cnn_class
            final_cat = CLASS_NAMES[cnn_class]
            final_conf = cnn_conf
            model = "cnn-lstm"

        print(json.dumps({
            "class": final_class,
            "category": final_cat,
            "confidence": round(final_conf, 6),
            "probabilities": [round(float(p), 6) for p in probs],
            "model": model,
            "cnn_lstm": {
                "class": cnn_class,
                "category": CLASS_NAMES[cnn_class],
                "confidence": round(cnn_conf, 6),
            },
        }), flush=True)


if __name__ == "__main__":
    main()
