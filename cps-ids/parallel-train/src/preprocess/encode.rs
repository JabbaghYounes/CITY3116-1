use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One-hot encoder that learns unique categories from training data and
/// produces fixed-width binary vectors for each value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneHotEncoder {
    categories: BTreeMap<String, usize>,
}

impl OneHotEncoder {
    pub fn new() -> Self {
        Self {
            categories: BTreeMap::new(),
        }
    }

    pub fn fit(&mut self, values: &[String]) {
        self.categories.clear();
        let mut seen = BTreeMap::new();
        for v in values {
            seen.entry(v.clone()).or_insert(());
        }
        for (idx, key) in seen.keys().enumerate() {
            self.categories.insert(key.clone(), idx);
        }
    }

    pub fn transform(&self, value: &str) -> Vec<f64> {
        let n = self.categories.len();
        let mut vec = vec![0.0_f64; n];
        if let Some(&idx) = self.categories.get(value) {
            vec[idx] = 1.0;
        }
        vec
    }

    pub fn num_categories(&self) -> usize {
        self.categories.len()
    }

    pub fn category_names(&self) -> Vec<String> {
        let mut pairs: Vec<_> = self.categories.iter().collect();
        pairs.sort_by_key(|&(_, idx)| *idx);
        pairs.into_iter().map(|(name, _)| name.clone()).collect()
    }
}

impl Default for OneHotEncoder {
    fn default() -> Self {
        Self::new()
    }
}
