pub mod dataset;
pub mod encode;
pub mod features;
pub mod normalize;
pub mod smote;
pub mod cicids;
pub mod unsw;
pub mod combined;

// Re-export key types for ergonomic use.
pub use dataset::{load_nsl_kdd, label_names, DatasetSplit};
pub use encode::OneHotEncoder;
pub use features::{extract_host_features, extract_network_features, extract_cicids_features, EventSource};
pub use normalize::MinMaxScaler;
pub use smote::smote;
pub use cicids::load_cicids2017;
pub use unsw::load_unsw_nb15;
pub use combined::merge_datasets;
