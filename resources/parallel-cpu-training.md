# Parallel CPU Training Plan

Replace smartcore's single-threaded Random Forest with a custom parallel implementation using `rayon`. Also parallelise Isolation Forest tree construction and SMOTE k-NN search.

Target machine: 16-core / 32-thread AMD CPU.

## Current Bottlenecks

| Phase | Current Time (Model B, 1.98M rows) | Bottleneck |
|-------|-------------------------------------|------------|
| RF training | ~8.5 hours | smartcore builds 100 trees sequentially, single-threaded |
| SMOTE | ~62 min (Model C, 313K rows) | k-NN search is O(n²) per class, single-threaded |
| IForest training | ~1 sec | Already fast (256-sample subsample per tree), but parallelisable |
| Evaluation/prediction | ~19 min (Model A) | Sequential prediction across test samples, RF rebuilds model each call |

## Expected Speedups (16 cores)

| Phase | Estimated Speedup | Model B Projected |
|-------|-------------------|-------------------|
| RF training | ~12-14x | ~35-45 min |
| SMOTE | ~10-12x | ~5-6 min |
| IForest training | ~14-16x | negligible (already fast) |
| Prediction | ~14-16x | ~1-2 min |

Conservative estimate for Model D (combined, ~2.4M rows, 276 features, no SMOTE): **1-2 hours** vs the current estimated 12-20 hours.

## Changes Required

### 1. Add rayon dependency

**Files**: `cps-ids/crates/ids-engine/Cargo.toml`, `cps-ids/crates/ids-preprocess/Cargo.toml`

```toml
# ids-engine/Cargo.toml
rayon = "1.10"

# ids-preprocess/Cargo.toml
rayon = "1.10"
```

### 2. Replace smartcore RF with custom parallel RF

**File**: `cps-ids/crates/ids-engine/src/random_forest.rs`

smartcore's `RandomForestClassifier` is a black box — we can't parallelise its internals. Replace it with a custom implementation that builds individual decision trees in parallel.

**Approach**: Use smartcore's `DecisionTreeClassifier` for individual trees, wrapped in `rayon::par_iter` to build all 100 trees concurrently. Each tree gets a bootstrap sample (random sampling with replacement) and a random feature subset (sqrt(n_features) per split).

```rust
use rayon::prelude::*;
use smartcore::tree::decision_tree_classifier::{
    DecisionTreeClassifier, DecisionTreeClassifierParameters,
};

pub fn train(x: &Array2<f64>, y: &Array1<usize>, n_trees: usize) -> Result<Self> {
    let dm = array2_to_dense(x);
    let yv = labels_usize_to_i32(y);
    let n = x.nrows();

    // Build n_trees in parallel, each on a bootstrap sample
    let trees: Vec<_> = (0..n_trees)
        .into_par_iter()
        .map(|tree_idx| {
            let mut rng = rand::rngs::StdRng::seed_from_u64(42 + tree_idx as u64);
            let bootstrap_indices = bootstrap_sample(n, &mut rng);
            let boot_x = select_rows_dense(&dm, &bootstrap_indices);
            let boot_y: Vec<i32> = bootstrap_indices.iter().map(|&i| yv[i]).collect();

            let params = DecisionTreeClassifierParameters::default()
                .with_max_depth(20)
                .with_min_samples_split(2)
                .with_min_samples_leaf(1);

            DecisionTreeClassifier::fit(&boot_x, &boot_y, params)
                .expect("tree fit failed")
        })
        .collect();

    // ...store trees for prediction
}
```

**Prediction** also parallelises — each tree predicts independently, then majority vote:

```rust
pub fn predict(&self, x: &Array2<f64>) -> Result<Array1<usize>> {
    let dm = array2_to_dense(x);

    // Collect predictions from all trees in parallel
    let all_preds: Vec<Vec<i32>> = self.trees
        .par_iter()
        .map(|tree| tree.predict(&dm).unwrap())
        .collect();

    // Majority vote per sample
    let n_samples = x.nrows();
    let mut final_preds = Array1::<usize>::zeros(n_samples);
    for i in 0..n_samples {
        let mut votes = vec![0u32; self.n_classes];
        for tree_preds in &all_preds {
            votes[tree_preds[i] as usize] += 1;
        }
        final_preds[i] = votes.iter().enumerate()
            .max_by_key(|(_, &v)| v).unwrap().0;
    }
    Ok(final_preds)
}
```

**Key change for predict_proba**: With individual tree access, we can compute **real soft probabilities** (vote fractions across 100 trees) instead of the current one-hot approximation. This fixes the ensemble limitation where IForest can't override RF:

```rust
pub fn predict_proba(&self, x: &Array2<f64>) -> Result<Array2<f64>> {
    let dm = array2_to_dense(x);
    let all_preds: Vec<Vec<i32>> = self.trees
        .par_iter()
        .map(|tree| tree.predict(&dm).unwrap())
        .collect();

    let n = x.nrows();
    let nc = self.n_classes;
    let mut proba = Array2::<f64>::zeros((n, nc));
    for i in 0..n {
        for tree_preds in &all_preds {
            let cls = tree_preds[i] as usize;
            if cls < nc {
                proba[[i, cls]] += 1.0;
            }
        }
        // Normalise to probabilities
        let total = self.trees.len() as f64;
        for c in 0..nc {
            proba[[i, c]] /= total;
        }
    }
    Ok(proba)
}
```

**Serialisation**: Individual `DecisionTreeClassifier` from smartcore still doesn't implement `Serialize`. Two options:
- (a) Continue storing training data + bootstrap indices, retrain on load (same as current, but slower with 100 separate fits)
- (b) Implement a fully custom decision tree (no smartcore) that is `Serialize` — more work but removes the smartcore dependency entirely and makes save/load instant

Option (b) is recommended for Model D since retraining 100 trees on 2.4M rows at load time defeats the purpose.

### 3. Parallelise Isolation Forest tree construction

**File**: `cps-ids/crates/ids-engine/src/isolation_forest.rs`

The IForest already uses a custom implementation. Change the tree-building loop to use `par_iter`:

```rust
use rayon::prelude::*;
use rand::SeedableRng;

// In IsolationForest::fit():
let trees: Vec<IsolationTree> = (0..n_trees)
    .into_par_iter()
    .map(|i| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42 + i as u64);
        let indices = subsample(&all_indices, actual_sample_size, &mut rng);
        IsolationTree::build(x, &indices, height_limit, 0, &mut rng)
    })
    .collect();
```

Also parallelise `anomaly_scores()`:

```rust
pub fn anomaly_scores(&self, x: &Array2<f64>) -> Array1<f64> {
    let scores: Vec<f64> = (0..x.nrows())
        .into_par_iter()
        .map(|i| self.anomaly_score(&x.row(i)))
        .collect();
    Array1::from_vec(scores)
}
```

### 4. Parallelise SMOTE k-NN search

**File**: `cps-ids/crates/ids-preprocess/src/smote.rs`

The k-NN search inside SMOTE is O(n²) per class — for each synthetic sample, it computes distances to all same-class samples. Parallelise the outer loop:

```rust
use rayon::prelude::*;

// For each class, generate synthetic samples in parallel batches
let synthetic_rows: Vec<(Vec<f64>, usize)> = (0..needed)
    .into_par_iter()
    .map(|_| {
        let mut rng = rand::thread_rng();
        let base_idx = indices[rng.gen_range(0..current_count)];
        let base = features.row(base_idx);

        // k-NN search (still O(n) per sample, but samples processed in parallel)
        // ... same logic, returns (synthetic_vec, class)
    })
    .collect();
```

Note: `rand::thread_rng()` is thread-local and safe with rayon. Each thread gets its own RNG.

### 5. Parallelise evaluation

**File**: `cps-ids/crates/ids-engine/src/train.rs`

RF prediction on the test set (22K–509K samples) can be parallelised by chunking:

```rust
// Predict in parallel chunks
let chunk_size = 10_000;
let all_preds: Vec<Array1<usize>> = x_test_scaled
    .axis_chunks_iter(Axis(0), chunk_size)
    .into_par_iter()
    .map(|chunk| rf.predict(&chunk.to_owned()).unwrap())
    .collect();
```

## Implementation Order

1. **Custom parallel RF** (biggest impact) — replaces smartcore RF entirely
2. **Parallel IForest** (small change, easy win) — change one loop to `par_iter`
3. **Parallel SMOTE** (moderate impact) — helps Model A and C which use SMOTE
4. **Real predict_proba** (fixes ensemble) — vote fractions instead of one-hot
5. **Parallel evaluation** (nice-to-have) — chunked parallel prediction

Steps 1-2 are essential. Steps 3-5 are improvements that can be done after verifying the parallel RF works correctly.

## Testing Strategy

- Run `cargo test -p ids-engine` after each change — existing 11 tests must pass
- Train Model A first (smallest, ~5 min expected) and compare metrics against the current baseline to verify correctness:
  - RF accuracy should be within ±0.02 of 0.6726 (randomness in bootstrap sampling)
  - IForest metrics should be nearly identical
- Then run Model B to verify speedup on large data
- Finally run Model D

## Risk: smartcore DecisionTreeClassifier

smartcore's `DecisionTreeClassifier` may have its own performance issues or API limitations. If it proves too slow or inflexible, fall back to a **fully custom decision tree** implementation (~150-200 lines of Rust). A basic CART tree with:
- Gini impurity splitting
- Random feature subset (sqrt(n_features)) per split
- Max depth limit
- Serde derive for free serialisation

This is more work but eliminates the smartcore dependency entirely and gives full control over serialisation (instant save/load instead of retraining).
