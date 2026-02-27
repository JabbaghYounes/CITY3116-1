pub mod dataset;
pub mod encode;
pub mod features;
pub mod normalize;
pub mod smote;

// Re-export key types for ergonomic use.
pub use dataset::{load_nsl_kdd, DatasetSplit};
pub use encode::OneHotEncoder;
pub use features::{extract_host_features, extract_network_features, EventSource};
pub use normalize::MinMaxScaler;
pub use smote::smote;
