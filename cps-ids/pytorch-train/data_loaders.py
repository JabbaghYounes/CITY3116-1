"""Dataset loaders for NSL-KDD, CIC-IDS2017, UNSW-NB15, and combined."""

import csv
import numpy as np
from pathlib import Path
from preprocessing import OneHotEncoder

LABEL_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CAT_PROTOCOL = 1
CAT_SERVICE = 2
CAT_FLAG = 3

# --- Attack category mappings (must match Rust exactly) ---

_NSL_DOS = {
    "back", "land", "neptune", "pod", "smurf", "teardrop",
    "apache2", "udpstorm", "processtable", "mailbomb", "worm",
}
_NSL_PROBE = {"satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"}
_NSL_R2L = {
    "guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
    "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
    "httptunnel", "sendmail", "named", "worm_sendmail", "sendmail_dictionary",
}
_NSL_U2R = {
    "buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
    "xterm", "ps", "httptunnel_u2r",
}


def nsl_attack_category(label: str) -> int:
    label = label.strip().rstrip(".")
    low = label.lower()
    if low == "normal":
        return 0
    if low == "attack" or low in _NSL_DOS:
        return 1
    if low in _NSL_PROBE:
        return 2
    if low in _NSL_R2L:
        return 3
    if low in _NSL_U2R:
        return 4
    print(f"  warning: unknown NSL-KDD label '{label}'; mapping to Probe")
    return 2


def cicids_attack_category(label: str) -> int:
    label = label.strip()
    if label == "BENIGN":
        return 0
    if label in ("DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"):
        return 1
    if label == "PortScan":
        return 2
    if label in ("FTP-Patator", "SSH-Patator", "Bot", "Heartbleed"):
        return 3
    if label == "Infiltration":
        return 4
    if label.startswith("Web Attack"):
        return 3
    print(f"  warning: unknown CIC-IDS2017 label '{label}'; mapping to Probe")
    return 2


def unsw_attack_category(label: int) -> int:
    mapping = {0: 0, 3: 1, 6: 1, 1: 2, 5: 2, 7: 2, 4: 3, 9: 3, 2: 4, 8: 4}
    if label in mapping:
        return mapping[label]
    print(f"  warning: unknown UNSW-NB15 label {label}; mapping to Probe")
    return 2


def clean_numeric(s: str) -> float:
    s = s.strip()
    low = s.lower()
    if low in ("nan", "infinity", "inf", "-infinity", "-inf"):
        return 0.0
    try:
        v = float(s)
        return v if np.isfinite(v) else 0.0
    except ValueError:
        return 0.0


# --- Dataset split helper ---

class DatasetSplit:
    def __init__(self, x_train, y_train, x_val, y_val, x_test, y_test,
                 feature_names, label_names):
        self.x_train = x_train
        self.y_train = y_train
        self.x_val = x_val
        self.y_val = y_val
        self.x_test = x_test
        self.y_test = y_test
        self.feature_names = feature_names
        self.label_names = label_names


# --- NSL-KDD ---

def _read_nsl_csv(path):
    records = []
    with open(path, "r") as f:
        reader = csv.reader(f, delimiter="\t")
        for line_no, row in enumerate(reader, 1):
            # Flatten: some files have comma-separated within tab fields
            fields = []
            for cell in row:
                fields.extend(cell.split(","))
            fields = [f.strip() for f in fields]
            if len(fields) < 42:
                raise ValueError(f"{path}:{line_no}: expected >=42 fields, got {len(fields)}")
            features = fields[:41]
            label = fields[41]
            records.append((features, label))
    return records


def _fit_nsl_encoders(train_records):
    enc_proto = OneHotEncoder()
    enc_service = OneHotEncoder()
    enc_flag = OneHotEncoder()
    enc_proto.fit([r[0][CAT_PROTOCOL] for r in train_records])
    enc_service.fit([r[0][CAT_SERVICE] for r in train_records])
    enc_flag.fit([r[0][CAT_FLAG] for r in train_records])
    return [enc_proto, enc_service, enc_flag]


def _encode_nsl_records(records, encoders):
    cat_indices = {CAT_PROTOCOL, CAT_SERVICE, CAT_FLAG}
    rows = []
    labels = []
    for features, label in records:
        numeric = []
        for j, val in enumerate(features):
            if j in cat_indices:
                continue
            try:
                numeric.append(float(val))
            except ValueError:
                numeric.append(0.0)
        for enc_idx, col_idx in enumerate([CAT_PROTOCOL, CAT_SERVICE, CAT_FLAG]):
            numeric.extend(encoders[enc_idx].transform(features[col_idx]))
        rows.append(numeric)
        labels.append(nsl_attack_category(label))
    return np.array(rows, dtype=np.float64), np.array(labels, dtype=np.intp)


def _build_nsl_feature_names(encoders):
    cat_indices = {CAT_PROTOCOL, CAT_SERVICE, CAT_FLAG}
    names = []
    for j, col_name in enumerate(NSL_KDD_COLUMNS):
        if j in cat_indices:
            continue
        names.append(col_name)
    cat_prefixes = ["protocol_type", "service", "flag"]
    for enc_idx, prefix in enumerate(cat_prefixes):
        for cat in encoders[enc_idx].category_names():
            names.append(f"{prefix}_{cat}")
    return names


def load_nsl_kdd(train_path, test_path):
    print(f"Loading NSL-KDD training data from {train_path}")
    train_records = _read_nsl_csv(train_path)
    print(f"Loading NSL-KDD test data from {test_path}")
    test_records = _read_nsl_csv(test_path)
    print(f"  parsed {len(train_records)} training, {len(test_records)} test records")

    encoders = _fit_nsl_encoders(train_records)
    print(f"  one-hot widths: protocol={encoders[0].num_categories()}, "
          f"service={encoders[1].num_categories()}, flag={encoders[2].num_categories()}")

    x_full, y_full = _encode_nsl_records(train_records, encoders)
    x_test, y_test = _encode_nsl_records(test_records, encoders)

    n = len(x_full)
    indices = np.random.permutation(n)
    split_point = round(n * 0.82)
    train_idx = indices[:split_point]
    val_idx = indices[split_point:]

    feature_names = _build_nsl_feature_names(encoders)
    print(f"  dataset ready: train={len(train_idx)}, val={len(val_idx)}, "
          f"test={len(x_test)}, features={len(feature_names)}")

    return DatasetSplit(
        x_train=x_full[train_idx], y_train=y_full[train_idx],
        x_val=x_full[val_idx], y_val=y_full[val_idx],
        x_test=x_test, y_test=y_test,
        feature_names=feature_names, label_names=LABEL_NAMES,
    )


# --- CIC-IDS2017 ---

CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

CICIDS_NUM_FEATURES = 78

CICIDS_FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
    "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def _load_cicids_csv(path):
    features = []
    labels = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)  # skip header
        for row in reader:
            if len(row) < CICIDS_NUM_FEATURES + 1:
                skipped += 1
                continue
            feat = [clean_numeric(row[i]) for i in range(CICIDS_NUM_FEATURES)]
            label_str = row[CICIDS_NUM_FEATURES].strip()
            labels.append(cicids_attack_category(label_str))
            features.append(feat)
    if skipped > 0:
        print(f"  warning: skipped {skipped} malformed rows in {path}")
    return features, labels


def load_cicids2017(csv_dir):
    csv_dir = Path(csv_dir)
    all_features = []
    all_labels = []
    for name in CICIDS_FILES:
        path = csv_dir / name
        print(f"Loading CIC-IDS2017: {name}")
        feats, labs = _load_cicids_csv(path)
        print(f"  loaded {len(feats)} records")
        all_features.extend(feats)
        all_labels.extend(labs)

    print(f"Total CIC-IDS2017 records: {len(all_features)}")
    x_all = np.array(all_features, dtype=np.float64)
    y_all = np.array(all_labels, dtype=np.intp)

    n = len(x_all)
    indices = np.random.permutation(n)
    train_end = round(n * 0.70)
    val_end = round(n * 0.82)

    train_idx = indices[:train_end]
    val_idx = indices[train_end:val_end]
    test_idx = indices[val_end:]

    print(f"CIC-IDS2017 ready: train={len(train_idx)}, val={len(val_idx)}, "
          f"test={len(test_idx)}, features={CICIDS_NUM_FEATURES}")

    return DatasetSplit(
        x_train=x_all[train_idx], y_train=y_all[train_idx],
        x_val=x_all[val_idx], y_val=y_all[val_idx],
        x_test=x_all[test_idx], y_test=y_all[test_idx],
        feature_names=CICIDS_FEATURE_NAMES, label_names=LABEL_NAMES,
    )


# --- UNSW-NB15 ---

UNSW_NUM_FEATURES = 76

UNSW_FEATURE_NAMES = [
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min",
    "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts",
    "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def load_unsw_nb15(data_path, label_path):
    print(f"Loading UNSW-NB15 features from {data_path}")
    print(f"Loading UNSW-NB15 labels from {label_path}")

    # Read labels
    raw_labels = []
    with open(label_path, "r") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            val = int(row[0].strip())
            raw_labels.append(unsw_attack_category(val))

    # Read features
    features = []
    with open(data_path, "r") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for i, row in enumerate(reader):
            if len(row) < UNSW_NUM_FEATURES:
                raise ValueError(f"Data.csv line {i+2}: expected >={UNSW_NUM_FEATURES} fields, got {len(row)}")
            feat = []
            for j in range(UNSW_NUM_FEATURES):
                try:
                    v = float(row[j].strip())
                    feat.append(v if np.isfinite(v) else 0.0)
                except ValueError:
                    feat.append(0.0)
            features.append(feat)

    assert len(features) == len(raw_labels), \
        f"Data.csv has {len(features)} rows but Label.csv has {len(raw_labels)} rows"

    n = len(features)
    print(f"  loaded {n} UNSW-NB15 records")

    x_all = np.array(features, dtype=np.float64)
    y_all = np.array(raw_labels, dtype=np.intp)

    indices = np.random.permutation(n)
    train_end = round(n * 0.70)
    val_end = round(n * 0.82)

    train_idx = indices[:train_end]
    val_idx = indices[train_end:val_end]
    test_idx = indices[val_end:]

    print(f"UNSW-NB15 ready: train={len(train_idx)}, val={len(val_idx)}, "
          f"test={len(test_idx)}, features={UNSW_NUM_FEATURES}")

    return DatasetSplit(
        x_train=x_all[train_idx], y_train=y_all[train_idx],
        x_val=x_all[val_idx], y_val=y_all[val_idx],
        x_test=x_all[test_idx], y_test=y_all[test_idx],
        feature_names=UNSW_FEATURE_NAMES, label_names=LABEL_NAMES,
    )


# --- Combined ---

def merge_datasets(splits):
    """Merge multiple DatasetSplits via union zero-padding.

    splits: list of (name, DatasetSplit) tuples
    """
    feature_counts = [ds.x_train.shape[1] for _, ds in splits]
    total_features = sum(feature_counts)
    print(f"Merging {len(splits)} datasets: "
          + ", ".join(f"{name}({fc})" for (name, _), fc in zip(splits, feature_counts))
          + f" -> {total_features} total features")

    feature_names = []
    for name, ds in splits:
        for fname in ds.feature_names:
            feature_names.append(f"{name}_{fname}")

    def merge_arrays(accessor):
        all_x = []
        all_y = []
        col_offset = 0
        for i, (_, ds) in enumerate(splits):
            x, y = accessor(ds)
            n_rows = x.shape[0]
            padded = np.zeros((n_rows, total_features), dtype=np.float64)
            padded[:, col_offset:col_offset + feature_counts[i]] = x
            all_x.append(padded)
            all_y.append(y)
            col_offset += feature_counts[i]
        return np.concatenate(all_x, axis=0), np.concatenate(all_y, axis=0)

    x_train, y_train = merge_arrays(lambda ds: (ds.x_train, ds.y_train))
    x_val, y_val = merge_arrays(lambda ds: (ds.x_val, ds.y_val))
    x_test, y_test = merge_arrays(lambda ds: (ds.x_test, ds.y_test))

    print(f"Merged dataset: train={len(x_train)}, val={len(x_val)}, "
          f"test={len(x_test)}, features={total_features}")

    return DatasetSplit(
        x_train=x_train, y_train=y_train,
        x_val=x_val, y_val=y_val,
        x_test=x_test, y_test=y_test,
        feature_names=feature_names, label_names=splits[0][1].label_names,
    )


def load_combined(nsl_train, nsl_test, cicids_dir, unsw_data, unsw_label):
    print("Loading combined dataset (NSL-KDD + CIC-IDS2017 + UNSW-NB15)")
    nsl = load_nsl_kdd(nsl_train, nsl_test)
    cic = load_cicids2017(cicids_dir)
    unsw = load_unsw_nb15(unsw_data, unsw_label)
    return merge_datasets([("nsl", nsl), ("cic", cic), ("unsw", unsw)])
