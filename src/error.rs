use serde::Serialize;

/// Public errors intentionally contain no arbitrary upstream diagnostic text.
#[derive(Debug, thiserror::Error, Serialize)]
#[error("{code}: {message}")]
pub struct LoadError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

impl LoadError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            retry_after_secs: None,
        }
    }
    pub fn transient(code: &str, message: &str) -> Self {
        Self {
            retryable: true,
            ..Self::new(code, message)
        }
    }
}

pub type Result<T> = std::result::Result<T, LoadError>;

pub fn io_error(_: std::io::Error) -> LoadError {
    LoadError::new("storage_io", "filesystem operation failed")
}
