use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdsError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Capture error: {0}")]
    Capture(String),

    #[error("Protocol parse error: {0}")]
    ProtocolParse(String),

    #[error("Preprocessing error: {0}")]
    Preprocessing(String),

    #[error("Model error: {0}")]
    Model(String),

    #[error("Dataset error: {0}")]
    Dataset(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Channel error: {0}")]
    Channel(String),
}
