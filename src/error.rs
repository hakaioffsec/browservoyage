use std::fmt;
use thiserror::Error;

pub type BrowserVoyageResult<T> = Result<T, BrowserVoyageError>;

#[derive(Error, Debug)]
pub enum BrowserVoyageError {
    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("I/O error: {0}")]
    StdIo(#[from] std::io::Error),

    #[error("Windows error: {0}")]
    Windows(String),

    #[error("No data found")]
    NoDataFound,

    #[error("Invalid key length: {0}")]
    InvalidKeyLength(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Base64 decode error")]
    Base64Error,

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Environment variable error: {0}")]
    EnvError(#[from] std::env::VarError),

    #[error(transparent)]
    Other(#[from] color_eyre::eyre::Error),
}

impl BrowserVoyageError {
    pub fn with_info(self, info: impl fmt::Display) -> Self {
        tracing::error!("{}: {}", self, info);
        self
    }
}

// Helper function to convert Windows errors
pub fn convert_windows_error(error: windows::core::Error) -> BrowserVoyageError {
    let code = error.code().0;

    // Categorize Windows errors based on HRESULT codes
    match code {
        // Access denied
        -2147024891 => BrowserVoyageError::AccessDenied(error.to_string()),
        // File not found
        -2147024894 => BrowserVoyageError::Io(format!("File not found: {error}")),
        // Path not found
        -2147024893 => BrowserVoyageError::Io(format!("Path not found: {error}")),
        // Other Windows errors
        _ => {
            let msg = format!("HRESULT: 0x{:08X} - {}", error.code().0, error);
            BrowserVoyageError::Windows(msg)
        }
    }
}
