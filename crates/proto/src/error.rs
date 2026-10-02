//! Protocol-level error type.

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp outside the accepted window")]
    StaleTimestamp,
    #[error("serialization failed: {0}")]
    Serialize(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
}
