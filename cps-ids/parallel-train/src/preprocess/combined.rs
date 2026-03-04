use anyhow::{Context, Result};
use ndarray::{Array1, Array2, Axis};
use tracing::info;

use crate::preprocess::dataset::DatasetSplit;

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

    let mut feature_names = Vec::with_capacity(total_features);
    for (name, ds) in splits {
        for fname in &ds.feature_names {
            feature_names.push(format!("{}_{}", name, fname));
        }
    }

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
