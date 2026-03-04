use ndarray::{Array1, Array2};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use tracing::info;

/// Parallel SMOTE implementation.
///
/// For each minority class, synthetic samples are generated in parallel using
/// rayon. Each parallel task gets a deterministic RNG seeded from its index.
pub fn smote(
    features: &Array2<f64>,
    labels: &Array1<usize>,
    target_count: usize,
    k_neighbors: usize,
) -> (Array2<f64>, Array1<usize>) {
    let n_features = features.ncols();

    // Collect indices per class.
    let max_label = labels.iter().copied().max().unwrap_or(0);
    let mut class_indices: Vec<Vec<usize>> = vec![Vec::new(); max_label + 1];
    for (i, &l) in labels.iter().enumerate() {
        class_indices[l].push(i);
    }

    // Start with copies of the originals.
    let mut aug_rows: Vec<Vec<f64>> = Vec::with_capacity(features.nrows() + target_count);
    let mut aug_labels: Vec<usize> = Vec::with_capacity(features.nrows() + target_count);

    for row in features.rows() {
        aug_rows.push(row.to_vec());
    }
    aug_labels.extend(labels.iter().copied());

    for (class, indices) in class_indices.iter().enumerate() {
        if indices.is_empty() {
            continue;
        }
        let current_count = indices.len();
        if current_count >= target_count {
            continue;
        }

        let needed = target_count - current_count;
        let k = k_neighbors.min(current_count.saturating_sub(1)).max(1);

        info!(
            class,
            current_count,
            needed,
            "SMOTE: generating synthetic samples in parallel"
        );

        // Precompute k-NN for each sample in this class (parallelised).
        let knn_lists: Vec<Vec<usize>> = indices
            .par_iter()
            .map(|&base_idx| {
                let base = features.row(base_idx);
                let mut dists: Vec<(usize, f64)> = indices
                    .iter()
                    .filter(|&&j| j != base_idx)
                    .map(|&j| {
                        let other = features.row(j);
                        let d: f64 = base
                            .iter()
                            .zip(other.iter())
                            .map(|(a, b)| (a - b).powi(2))
                            .sum();
                        (j, d)
                    })
                    .collect();
                dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                dists.truncate(k);
                dists.into_iter().map(|(idx, _)| idx).collect()
            })
            .collect();

        // Generate synthetic samples in parallel.
        let synthetics: Vec<Vec<f64>> = (0..needed)
            .into_par_iter()
            .map(|syn_idx| {
                let mut rng = ChaCha8Rng::seed_from_u64(42 + class as u64 * 1_000_000 + syn_idx as u64);
                let local_idx = rng.gen_range(0..current_count);
                let base_idx = indices[local_idx];
                let base = features.row(base_idx);

                let nn_list = &knn_lists[local_idx];
                if nn_list.is_empty() {
                    return base.to_vec();
                }

                let nn_idx = nn_list[rng.gen_range(0..nn_list.len())];
                let neighbour = features.row(nn_idx);

                let lambda: f64 = rng.gen_range(0.0..1.0);
                base.iter()
                    .zip(neighbour.iter())
                    .map(|(&a, &b)| a + lambda * (b - a))
                    .collect()
            })
            .collect();

        for syn_row in synthetics {
            aug_rows.push(syn_row);
            aug_labels.push(class);
        }
    }

    let n_total = aug_rows.len();
    let flat: Vec<f64> = aug_rows.into_iter().flatten().collect();
    let aug_features = Array2::from_shape_vec((n_total, n_features), flat)
        .expect("SMOTE: shape mismatch when building augmented feature matrix");
    let aug_labels = Array1::from(aug_labels);

    (aug_features, aug_labels)
}
