use anyhow::anyhow;
use thiserror::Error;

/// The common error type returned by this crate
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Failed parsing config file: {path}")]
    ConfigParseError {
        source: toml::de::Error,
        path: String,
    },
    #[error("File not found: {path}")]
    FileNotFound { path: String },
    #[error("File read error: {path}")]
    FileReadError {
        source: std::io::Error,
        path: String,
    },
    #[error("File read error: {path}")]
    FileWriteError {
        source: std::io::Error,
        path: String,
    },
    #[error("An I/O error occurred")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("Missing required argument: {arg}")]
    MissingArgumentError { arg: String },
    #[error("Failed parsing SSH public key")]
    SSHParseError { source: sshkeys::Error },
    #[error("Unsupported login method")]
    UnsupportedLogin,
    #[error("An error occurred with Vault")]
    VaultError {
        #[from]
        source: vaultrs::error::ClientError,
    },
    #[error("The Vault server returned an error: {message}")]
    VaultAPIError { message: String },
}

/// Attempts to discern if a given error is a
/// [vaultrs::error::ClientError::APIError] and casts it into a
/// [ClientError::VaultAPIError], extracting the error message in the process.
///
/// This is useful for returning errors sent from the server directly to the
/// end user.
pub fn try_api_error(error: &anyhow::Error) -> Option<anyhow::Error> {
    match error.downcast_ref::<vaultrs::error::ClientError>() {
        Some(vaultrs::error::ClientError::APIError { code: _, errors }) => {
            Some(anyhow! { ClientError::VaultAPIError{ message: errors[0].clone()}})
        }
        _ => None,
    }
}
