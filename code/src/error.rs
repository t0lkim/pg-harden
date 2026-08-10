use thiserror::Error;

/// Connection-related errors
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Failed to connect to PostgreSQL: {0}")]
    Connection(String),
}

/// Check execution errors
#[derive(Error, Debug)]
pub enum CheckError {
    #[error("Query execution failed: {0}")]
    QueryFailed(String),

    #[error("File read error: {0}")]
    FileRead(String),

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
