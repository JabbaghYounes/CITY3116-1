//! N-dataset merger with zero-padded feature concatenation.
//!
//! Merges multiple [`DatasetSplit`] objects into a single combined split where each
//! dataset's features occupy a dedicated column range and all other columns are zero.

use anyhow::{Context, Result};
use ndarray::{Array1, Array2, Axis};
use tracing::info;

use crate::dataset::DatasetSplit;

/// Merge multiple `DatasetSplit`s into one combined split.
///
/// Each input dataset may have a different number of features. The merged dataset
/// has `sum(n_features_i)` columns. For each dataset, its rows have non-zero values
/// only in the columns corresponding to that dataset's features; columns from other
/// datasets are filled with zeros.
///
/// All datasets must share the same `label_names` (same 5-class scheme).
///
/// `splits` is a slice of `(prefix, dataset)` tuples. The prefix is used for
/// feature name namespacing (e.g., `"nsl"` produces `"nsl_duration"`).
pub fn merge_datasets(splits: &[(&str, &DatasetSplit)]) -> Result<DatasetSplit> {
    anyhow::ensure!(!splits.is_empty(), "merge_datasets called with no datasets");

    let feature_counts: Vec<usize> = splits.iter().map(|(_, ds)| ds.x_train.ncols()).collect();
    let total_features: usize = feature_counts.iter().sum();

    info!(
        "merging {} datasets: {:?} -> {} total features",
        splits.len(),
        splits
            .iter()
            .map(|(name, ds)| format!("{}({})", name, ds.x_train.ncols()))
            .collect::<Vec<_>>(),
        total_features
    );

    // Build merged feature names with dataset prefix
    let mut feature_names = Vec::with_capacity(total_features);
    for (name, ds) in splits {
        for fname in &ds.feature_names {
            feature_names.push(format!("{}_{}", name, fname));
        }
    }

    // Merge each split (train, val, test)
    let (x_train, y_train) = merge_split_arrays(
        splits,
        |ds| (&ds.x_train, &ds.y_train),
        &feature_counts,
        total_features,
    )?;
    let (x_val, y_val) = merge_split_arrays(
        splits,
        |ds| (&ds.x_val, &ds.y_val),
        &feature_counts,
        total_features,
    )?;
    let (x_test, y_test) = merge_split_arrays(
        splits,
        |ds| (&ds.x_test, &ds.y_test),
        &feature_counts,
        total_features,
    )?;

    let label_names = splits[0].1.label_names.clone();

    info!(
        "merged dataset: train={}, val={}, test={}, features={}",
        x_train.nrows(),
        x_val.nrows(),
        x_test.nrows(),
        total_features
    );

    Ok(DatasetSplit {
        x_train,
        y_train,
        x_val,
        y_val,
        x_test,
        y_test,
        feature_names,
        label_names,
    })
}

/// Internal helper: merge one split (train, val, or test) from multiple datasets.
fn merge_split_arrays<F>(
    splits: &[(&str, &DatasetSplit)],
    accessor: F,
    feature_counts: &[usize],
    total_features: usize,
) -> Result<(Array2<f64>, Array1<usize>)>
where
    F: Fn(&DatasetSplit) -> (&Array2<f64>, &Array1<usize>),
{
    let mut all_rows: Vec<Array2<f64>> = Vec::new();
    let mut all_labels: Vec<Array1<usize>> = Vec::new();

    let mut col_offset = 0usize;

    for (i, (_name, ds)) in splits.iter().enumerate() {
        let (x, y) = accessor(ds);
        let n_rows = x.nrows();
        let n_cols = feature_counts[i];

        // Create zero-padded matrix for this dataset
        let mut padded = Array2::<f64>::zeros((n_rows, total_features));
        padded
            .slice_mut(ndarray::s![.., col_offset..col_offset + n_cols])
            .assign(x);

        all_rows.push(padded);
        all_labels.push(y.clone());

        col_offset += n_cols;
    }

    let x_views: Vec<_> = all_rows.iter().map(|a| a.view()).collect();
    let x_merged =
        ndarray::concatenate(Axis(0), &x_views).context("failed to concatenate feature matrices")?;

    let y_views: Vec<_> = all_labels.iter().map(|a| a.view()).collect();
    let y_merged =
        ndarray::concatenate(Axis(0), &y_views).context("failed to concatenate label vectors")?;

    Ok((x_merged, y_merged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn test_merge_two_datasets() {
        let ds1 = DatasetSplit {
            x_train: array![[1.0, 2.0], [3.0, 4.0]],
            y_train: array![0, 1],
            x_val: array![[5.0, 6.0]],
            y_val: array![0],
            x_test: array![[7.0, 8.0]],
            y_test: array![1],
            feature_names: vec!["a".into(), "b".into()],
            label_names: vec!["Normal".into(), "DoS".into()],
        };

        let ds2 = DatasetSplit {
            x_train: array![[10.0, 20.0, 30.0]],
            y_train: array![0],
            x_val: array![[40.0, 50.0, 60.0]],
            y_val: array![1],
            x_test: array![[70.0, 80.0, 90.0]],
            y_test: array![0],
            feature_names: vec!["x".into(), "y".into(), "z".into()],
            label_names: vec!["Normal".into(), "DoS".into()],
        };

        let merged = merge_datasets(&[("d1", &ds1), ("d2", &ds2)]).unwrap();

        // Train: 2 + 1 = 3 rows, 2 + 3 = 5 features
        assert_eq!(merged.x_train.dim(), (3, 5));
        assert_eq!(merged.y_train.len(), 3);

        // First dataset rows: [1,2,0,0,0] and [3,4,0,0,0]
        assert_eq!(merged.x_train[[0, 0]], 1.0);
        assert_eq!(merged.x_train[[0, 1]], 2.0);
        assert_eq!(merged.x_train[[0, 2]], 0.0);
        assert_eq!(merged.x_train[[0, 3]], 0.0);
        assert_eq!(merged.x_train[[0, 4]], 0.0);

        // Second dataset row: [0,0,10,20,30]
        assert_eq!(merged.x_train[[2, 0]], 0.0);
        assert_eq!(merged.x_train[[2, 1]], 0.0);
        assert_eq!(merged.x_train[[2, 2]], 10.0);
        assert_eq!(merged.x_train[[2, 3]], 20.0);
        assert_eq!(merged.x_train[[2, 4]], 30.0);

        // Feature names
        assert_eq!(merged.feature_names.len(), 5);
        assert_eq!(merged.feature_names[0], "d1_a");
        assert_eq!(merged.feature_names[1], "d1_b");
        assert_eq!(merged.feature_names[2], "d2_x");
        assert_eq!(merged.feature_names[3], "d2_y");
        assert_eq!(merged.feature_names[4], "d2_z");

        // Val and test
        assert_eq!(merged.x_val.dim(), (2, 5));
        assert_eq!(merged.x_test.dim(), (2, 5));
    }
}
