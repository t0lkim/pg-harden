use thiserror::Error;

/// Connection-related errors
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Failed to connect to PostgreSQL: {0}")]
    Connection(String),

    #[error("Socket not found: {0}")]
    SocketNotFound(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Connection timeout after {0} seconds")]
    Timeout(u64),
}

/// Check execution errors
#[derive(Error, Debug)]
pub enum CheckError {
    #[error("Query execution failed: {0}")]
    QueryFailed(String),

    #[error("File read error: {0}")]
    FileRead(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Check requires database connection")]
    RequiresConnection,
}

/// Application-level errors
#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),

    #[error(transparent)]
    Check(#[from] CheckError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
