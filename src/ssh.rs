use crate::ClientError;
use anyhow::Result;
use sshkeys::Certificate;
use std::path::PathBuf;
use vaultrs::client::VaultClient;
use vaultrs::ssh;

/// Signs the given public key contents.
pub async fn sign(client: &VaultClient, mount: &str, role: &str, contents: &str) -> Result<String> {
    Ok(ssh::ca::sign(client, mount, role, contents, None)
        .await?
        .signed_key)
}

/// Validates a SSH certificate is not expired.
pub fn validate(contents: &str) -> Result<bool> {
    let cert =
        Certificate::from_string(contents).map_err(|e| ClientError::SSHParseError { source: e })?;
    let current = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if current > cert.valid_before {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Returns the public key associated with a private key
pub fn public_from_private(path: &str) -> PathBuf {
    let expanded_path = shellexpand::tilde(&path).to_string();
    let mut file_path = PathBuf::from(&expanded_path);
    file_path.set_extension("pub");
    file_path
}

// Returns the public key certificate associated with a private key
pub fn cert_from_private(path: &str) -> PathBuf {
    let expanded_path = shellexpand::tilde(&path).to_string();
    let mut file_path = PathBuf::from(&expanded_path);
    let base_name = file_path.with_extension("");
    let file_name = base_name.file_name().unwrap().to_string_lossy();
    file_path.set_file_name(format!("{}-cert", file_name));
    file_path.set_extension("pub");
    file_path
}
