use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One-hot encoder that learns unique categories from training data and
/// produces fixed-width binary vectors for each value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneHotEncoder {
    /// Ordered map from category string to its index position in the one-hot
    /// vector.  We use BTreeMap so the ordering is deterministic across runs.
    categories: BTreeMap<String, usize>,
}

impl OneHotEncoder {
    /// Create a new, unfitted encoder.
    pub fn new() -> Self {
        Self {
            categories: BTreeMap::new(),
        }
    }

    /// Learn unique categories from the supplied slice of strings.
    ///
    /// Calling `fit` replaces any previously learnt categories.
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

    /// Transform a single value into its one-hot representation.
    ///
    /// Unknown categories (not seen during `fit`) produce an all-zero vector.
    pub fn transform(&self, value: &str) -> Vec<f64> {
        let n = self.categories.len();
        let mut vec = vec![0.0_f64; n];
        if let Some(&idx) = self.categories.get(value) {
            vec[idx] = 1.0;
        }
        vec
    }

    /// Return the number of distinct categories the encoder learnt.
    pub fn num_categories(&self) -> usize {
        self.categories.len()
    }

    /// Return the category names in index order (useful for feature naming).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fit_and_transform() {
        let mut enc = OneHotEncoder::new();
        let vals: Vec<String> = vec!["tcp".into(), "udp".into(), "icmp".into(), "tcp".into()];
        enc.fit(&vals);

        assert_eq!(enc.num_categories(), 3);

        let v = enc.transform("tcp");
        assert_eq!(v.iter().filter(|&&x| x == 1.0).count(), 1);
        assert_eq!(v.len(), 3);

        // Unknown category should produce all zeros.
        let v_unk = enc.transform("sctp");
        assert!(v_unk.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn test_deterministic_order() {
        let mut enc1 = OneHotEncoder::new();
        let mut enc2 = OneHotEncoder::new();
        let vals: Vec<String> = vec!["b".into(), "a".into(), "c".into()];
        enc1.fit(&vals);
        enc2.fit(&vals);

        assert_eq!(enc1.transform("a"), enc2.transform("a"));
        assert_eq!(enc1.transform("b"), enc2.transform("b"));
        assert_eq!(enc1.transform("c"), enc2.transform("c"));
    }
}
