use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CentralSshError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("TOML decode error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("TOML encode error: {0}")]
    TomlSer(#[from] toml::ser::Error),

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

    #[error("channel closed")]
    ChannelClosed,

    #[error("input canceled")]
    InputCanceled,

    #[error("input timed out")]
    InputTimeout,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("totp validation failed")]
    TotpInvalid,

    #[error("ssh error: {0}")]
    Ssh(String),
}

pub type Result<T> = std::result::Result<T, CentralSshError>;
