//! Core runtime error type.

use netagent_proto::ProtoError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config error: {0}")]
    Config(String),
    #[error("protocol error: {0}")]
    Proto(#[from] ProtoError),
    #[error("not enrolled: run `netagent enroll` first")]
    NotEnrolled,
    #[error("enrollment failed: {0}")]
    Enroll(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("platform error: {0}")]
    Platform(#[from] crate::platform::PlatformError),
    #[error("update error: {0}")]
    Update(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
