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

/// Attempts to provide greater clarity about certain errors.
///
/// For example, it's confusing when a missing token error is returned when
/// attempting to login. In reality, this translates to there not being any auth
/// engine mounted at the requested path.
pub fn handle_login_error(error: anyhow::Error) -> anyhow::Error {
    if let Some(e) = try_api_error(&error) {
        match e.downcast_ref::<ClientError>() {
            Some(ClientError::VaultAPIError { message }) => {
                println!("YO!");
                if message == "missing client token" {
                    anyhow! {"There was no auth engine mounted at the given mount point."}
                } else {
                    error
                }
            }
            _ => error,
        }
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::ClientError;
    use anyhow::anyhow;

    #[test]
    fn test_try_api_error() {
        let err = anyhow! { vaultrs::error::ClientError::ResponseWrapError };
        let res = super::try_api_error(&err);
        assert!(res.is_none());

        let message = String::from("test");
        let err =
            anyhow! { vaultrs::error::ClientError::APIError { code: 400, errors: vec![message]} };
        let res = super::try_api_error(&err);
        assert!(res.is_some());
    }

    #[test]
    fn test_handle_login_error() {
        let err = anyhow! { ClientError::UnsupportedLogin };
        let res = super::handle_login_error(err);
        let res = res.downcast_ref::<ClientError>();
        assert!(matches! {
            res,
            Some(ClientError::UnsupportedLogin)
        });

        let err = anyhow! { ClientError::VaultAPIError{ message: String::from("test")} };
        let res = super::handle_login_error(err);
        let res = res.downcast_ref::<ClientError>();
        assert!(matches! {
            res,
            Some(ClientError::VaultAPIError{ .. })
        });

        let err = anyhow! { vaultrs::error::ClientError::APIError { code: 400, errors: vec![String::from("missing client token")] } };
        let res = super::handle_login_error(err);
        assert_eq!(
            res.to_string(),
            "There was no auth engine mounted at the given mount point."
        );
    }
}
