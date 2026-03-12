"""MinMaxScaler, OneHotEncoder, and SMOTE for IDS preprocessing."""

import json
import numpy as np
from pathlib import Path


class OneHotEncoder:
    """One-hot encoder using sorted categories (matches Rust BTreeMap ordering)."""

    def __init__(self):
        self.categories_ = []

    def fit(self, values):
        self.categories_ = sorted(set(values))

    def transform(self, value):
        vec = [0.0] * len(self.categories_)
        try:
            idx = self.categories_.index(value)
            vec[idx] = 1.0
        except ValueError:
            pass
        return vec

    def num_categories(self):
        return len(self.categories_)

    def category_names(self):
        return list(self.categories_)


class MinMaxScaler:
    """Min-max normalization to [0, 1]. Matches Rust MinMaxScaler."""

    def __init__(self):
        self.min_ = None
        self.max_ = None
        self.fitted = False

    def fit(self, data):
        self.min_ = np.min(data, axis=0)
        self.max_ = np.max(data, axis=0)
        self.fitted = True

    def transform(self, data):
        assert self.fitted, "Scaler not fitted"
        range_ = self.max_ - self.min_
        safe = range_ > np.finfo(np.float64).eps
        result = np.zeros_like(data)
        result[:, safe] = (data[:, safe] - self.min_[safe]) / range_[safe]
        return result

    def fit_transform(self, data):
        self.fit(data)
        return self.transform(data)

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "min": self.min_.tolist(),
                "max": self.max_.tolist(),
                "fitted": True,
            }, f)

    @classmethod
    def load(cls, path):
        with open(path) as f:
            d = json.load(f)
        s = cls()
        s.min_ = np.array(d["min"])
        s.max_ = np.array(d["max"])
        s.fitted = True
        return s


def smote(features, labels, target_count, k_neighbors=5):
    """SMOTE oversampling. Seed pattern: 42 + class*1_000_000 + idx."""
    classes = sorted(set(labels))
    aug_x = [features.copy()]
    aug_y = [labels.copy()]

    for cls in classes:
        mask = labels == cls
        cls_x = features[mask]
        n = len(cls_x)
        if n >= target_count:
            continue

        k = min(k_neighbors, n - 1)
        if k < 1:
            continue

        needed = target_count - n
        print(f"  SMOTE: class={cls} current={n} generating={needed}")

        # Precompute k-NN within class
        from numpy.linalg import norm
        neighbors = np.zeros((n, k), dtype=int)
        for i in range(n):
            dists = norm(cls_x - cls_x[i], axis=1)
            dists[i] = np.inf
            neighbors[i] = np.argpartition(dists, k)[:k]

        syn_x = np.empty((needed, features.shape[1]))
        syn_y = np.full(needed, cls)

        for idx in range(needed):
            seed = 42 + cls * 1_000_000 + idx
            rng = np.random.Generator(np.random.PCG64(seed))
            base_idx = rng.integers(0, n)
            nn_idx = neighbors[base_idx][rng.integers(0, k)]
            lam = rng.random()
            syn_x[idx] = cls_x[base_idx] + lam * (cls_x[nn_idx] - cls_x[base_idx])

        aug_x.append(syn_x)
        aug_y.append(syn_y)

    return np.concatenate(aug_x, axis=0), np.concatenate(aug_y, axis=0)
