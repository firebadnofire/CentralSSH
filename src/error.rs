use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CentralSshError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("password hash error: {0}")]
    PasswordHash(#[from] argon2::password_hash::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("security policy violation for {path}: {message}")]
    SecurityPolicy { path: PathBuf, message: String },

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("authorization denied")]
    AuthorizationDenied,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("totp validation failed")]
    TotpInvalid,

    #[error("ssh error: {0}")]
    Ssh(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("timeout waiting for user input")]
    InputTimeout,

    #[error("input cancelled by user")]
    InputCanceled,
}

pub type Result<T> = std::result::Result<T, CentralSshError>;
