//! # vaultssh
//!
//! <p align="center">
//!     <a href="https://!crates.io/crates/vaultssh">
//!         <img src="https://!img.shields.io/crates/v/vaultssh">
//!     </a>
//!     <a href="https://!docs.rs/vaultssh">
//!         <img src="https://!img.shields.io/docsrs/vaultssh" />
//!     </a>
//!     <a href="https://!github.com/jmgilman/vaultssh/actions/workflows/ci.yml">
//!         <img src="https://!github.com/jmgilman/vaultssh/actions/workflows/ci.yml/badge.svg"/>
//!     </a>
//! </p>
//!
//! > A small CLI wrapper for authenticating with SSH keys from [Hashicorp Vault][1]
//!
//! vaultssh is a small CLI wrapper for automatically fetching and using signed SSH
//! certificates when remoting into a host. It wraps the ssh process and is
//! therefore compatible with all standard ssh flags.
//!
//! ## Installation
//!
//! ```ignore
//! cargo install vaultssh
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! $> vssh --help
//!
//! vaultssh 0.1.0
//!
//! A small CLI wrapper for authenticating with SSH keys from Hashicorp Vault
//!
//! USAGE:
//!     vssh [FLAGS] [OPTIONS] <HOST> [ARGS]...
//!
//! ARGS:
//!     <HOST>       ssh host
//!     <ARGS>...    additional arguments to pass to ssh
//!
//! FLAGS:
//!     -b, --basic      disables terminal effects
//!     -h, --help       Print help information
//!     -p, --persist    persist acquired tokens to ~/.vault-token
//!     -V, --version    Print version information
//!
//! OPTIONS:
//!     -a, --auth-method <AUTH>         default authentication method to use
//!         --auth-mount <AUTH_MOUNT>    default authentication mount to use
//!     -c, --config <CONFIG>            config file (default: $HOME/.vssh)
//!     -i, --identity <IDENTITY>        ssh key-pair to sign and use (default: $HOME/.ssh/id_rsa)
//!     -m, --mount <MOUNT>              mount path for ssh backend (default: ssh)
//!     -r, --role <ROLE>                vault role account to sign with (default: "default")
//!     -s, --server <SERVER>            address of vault server (default: $VAULT_ADDR)
//!     -t, --token <TOKEN>              vault token to use for authentication (default: $VAULT_TOKEN)
//! ```
//!
//! ## Configuration
//!
//! A configuration can be used by either creating it at `~/.vssh` or passing one in
//! using the CLI option. Configuration files are in TOML format. An example one is
//! shown below:
//!
//! ```toml
//! # Example config - place this in ~/.vssh to automatically use it
//! #
//! # The authentication names are the same as the default mount point for the
//! # associated engine. For example, "approle" for AppRole and "oidc" for OIDC.
//! # Not all engines are supported, only the ones shown below. You don't have to
//! # configure each one and may only configure the one you set to the default.
//!
//! auth = "oidc"                  # default authentication method to use
//! identity = "~/.ssh/id_rsa"     # ssh key-pair to sign and use
//! mount = "ssh"                  # mount path for ssh backend
//! persist = true                 # persist acquired tokens to ~/.vault-token
//! role = "myrole"                # vault role account to sign with
//! server = "https://!vault:8200"  # address of vault server
//!
//! [approle]                      # name of auth method to configure
//! role_id = "myrole"             # default values for auth method
//!
//! [oidc]
//! role = "admin
//!
//! [userpass]
//! username = "myuser"
//! ```
//!
//! ## Flow
//!
//! The following occurs when you run vssh:
//!
//! * A valid SSH certificate is searched for using the passed identity name
//! * If no certificate is found, or the found certificate is expired, a new
//!   certificate is requested
//! * A connection to Vault is initiated using any found tokens. If no token is
//!   found or the token is expired, a login prompt is given to acquire a new token.
//! * The public key for the passed identity is signed and the certificate is saved
//!   to the local filesystem
//! * The ssh program is executed and is passed the host and any additional
//!   arguments
//!
//! ## Authentication
//!
//! By default, if a new certificate is needed but no valid token has been found
//! then vssh will initiate a login prompt for acquiring a new token. This token
//! will only be used for the single session unless the `--persist` option is given
//! in which case the token is saved to the Vault CLI's default location of
//! `~/.vault-token`. Future uses of vssh will use this token.
//!
//! Not all authentication methods are currently supported, see the above
//! configuration example for the ones that are. Specifying defaults for the
//! authentication method will pre-fill the login prompt to make logging in easier.
//! However, all other auth methods are still available if desired (i.e. setting
//! defaults does not skip any prompts).
//!
//! [1]: https://!www.vaultproject.io/
mod config;
mod display;
mod error;
mod login;
mod ssh;
#[cfg(test)]
mod testing;

use std::path::PathBuf;
use std::process::Command;

use crate::{display::Console, error::ClientError, login::TokenFileHandler};
use anyhow::{anyhow, Result};
use clap::Clap;
use config::Config;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs_login::method::Method;

/// A small CLI wrapper for authenticating with SSH keys from Hashicorp Vault
#[derive(Clap, Default)]
#[clap(
    version = "0.1.0",
    setting = clap::AppSettings::TrailingVarArg
)]
pub struct Opts {
    /// default authentication method to use
    #[clap(short = 'a', long = "auth-method")]
    auth: Option<Method>,
    /// default authentication mount to use
    #[clap(long = "auth-mount")]
    auth_mount: Option<String>,
    /// disables terminal effects
    #[clap(short = 'b', long = "basic")]
    basic: bool,
    /// config file (default: $HOME/.vssh)
    #[clap(short = 'c', long = "config")]
    config: Option<String>,
    /// ssh key-pair to sign and use (default: $HOME/.ssh/id_rsa)
    #[clap(short = 'i', long = "identity")]
    identity: Option<String>,
    /// mount path for ssh backend (default: ssh)
    #[clap(short = 'm', long = "mount")]
    mount: Option<String>,
    /// persist acquired tokens to ~/.vault-token
    #[clap(short = 'p', long = "persist")]
    persist: bool,
    /// vault role account to sign with (default: "default")
    #[clap(short = 'r', long = "role")]
    role: Option<String>,
    /// address of vault server (default: $VAULT_ADDR)
    #[clap(short = 's', long = "server")]
    server: Option<String>,
    /// vault token to use for authentication (default: $VAULT_TOKEN)
    #[clap(short = 't', long = "token")]
    token: Option<String>,
    /// ssh host
    host: String,
    /// additional arguments to pass to ssh
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    let config_path = opts.config.clone();
    let host = opts.host.clone();
    let args = opts.args.clone();

    let config = crate::config::merge(opts, load_config(config_path)?)?;
    let identity = config.identity.as_ref().unwrap();

    // Check if a new certificate is needed
    let cert = load_cert(identity);
    let needs_signing = if let Err(e) = cert {
        match e.downcast_ref() {
            Some(ClientError::FileNotFound { path: _ }) => true,
            _ => return Err(e),
        }
    } else {
        !ssh::is_valid(&ssh::str_to_cert(cert.unwrap().as_str())?)
    };

    if needs_signing {
        match config.basic {
            Some(true) => {
                gen_cert(&config, &display::VanillaConsole::new()).await?;
            }
            _ => {
                gen_cert(&config, &display::CLIConsole::new()).await?;
            }
        }
    }

    // Run SSH
    Command::new("ssh")
        .arg(host)
        .args(args)
        .stdout(std::process::Stdio::inherit())
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()?;

    Ok(())
}

/// Checks the Vault server status and confirms it's initialized and unsealed.
async fn check_status(client: &VaultClient) -> Result<()> {
    match client.status().await? {
        vaultrs::sys::ServerStatus::OK => Ok(()),
        vaultrs::sys::ServerStatus::SEALED => Err(anyhow!("The Vault server is sealed")),
        vaultrs::sys::ServerStatus::UNINITIALIZED => {
            Err(anyhow!("The Vault server is not initialized"))
        }
        _ => Err(anyhow!("The Vault server is in an invalid state")),
    }
}

/// Generates a signed SSH public key certificate and writes it to the
/// filesystem.
async fn gen_cert(config: &Config, console: &impl Console) -> Result<()> {
    let identity = config.identity.as_ref().unwrap();
    let mount = config.mount.as_ref().unwrap();
    let role = config.role.as_ref().unwrap();
    let server = config.server.as_ref().unwrap();

    // Attempt to load token from file if needed
    let token = match config.token.is_none() {
        true => {
            console.neutral("Using token from ~/.vault-token...");
            VaultClient::token_from_file().unwrap_or_else(|_| "".to_string())
        }
        false => config.token.as_ref().unwrap().clone(),
    };

    // Configure Vault client
    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(server)
            .token(token)
            .build()
            .unwrap(),
    )
    .unwrap();

    // Verify the Vault server is available
    check_status(&client).await?;

    // Check if login is required
    if client.lookup().await.is_err() {
        console.error("No valid token found.");

        if let Err(e) = crate::login::login(&mut client, config, console).await {
            return Err(error::handle_login_error(e).context("Login failed"));
        }

        console.success("Login success!");
    }

    console.success("Valid token found.");

    // Create certificate
    console.neutral("Generating new certificate...");
    let contents = load_pub(identity)?;

    let res = ssh::sign(&client, mount, role, &contents).await;
    if let Err(ref e) = res {
        if let Some(e) = error::try_api_error(e) {
            return Err(e);
        }
    }

    let path = ssh::cert_from_private(identity);
    let path_str = path.to_string_lossy().to_string();
    write_key(path, &res?)?;

    console.success(format!("Saved certificate to {}", path_str).as_str());

    Ok(())
}

/// Attempts to load the pass configuration file path into a [Config].
///
/// If an explicit path is provided, and the loading fails, an error is
/// returned. If the passed path is [None], the configuration file located at
/// the default path is loaded. If this fails an empty [Config] is returned.
fn load_config(path: Option<String>) -> Result<Config> {
    // If they passed a config via the CLI, try to parse it first
    match path {
        Some(p) => Config::new(p.as_str()),
        None => {
            // Attempt to load default configuration.
            // The user may not have a config, so we ignore file not found
            // errors and return a default config. All other errors are
            // propogated.
            let p = shellexpand::tilde(crate::config::DEFAULTS["config"]);
            let config = Config::new(&p);
            if let Err(error) = config {
                match error.downcast_ref::<ClientError>() {
                    Some(ClientError::FileNotFound { path: _ }) => Ok(Config::default()),
                    _ => Err(error),
                }
            } else {
                config
            }
        }
    }
}

/// Returns the signed certificate associated with the given private key
fn load_cert(path: &str) -> Result<String> {
    load_key(ssh::cert_from_private(path))
}

/// Returns the public key associated with the given private key
fn load_pub(path: &str) -> Result<String> {
    load_key(ssh::public_from_private(path))
}

/// Returns the contents of the SSH key at the given path
fn load_key(path: PathBuf) -> Result<String> {
    // Check if a certificate is present
    let path_str = path.to_string_lossy().to_string();
    if !path.exists() {
        return Err(anyhow! { ClientError::FileNotFound { path: path_str }});
    }

    // Read and return certificate contents
    std::fs::read_to_string(path)
        .map_err(|e| anyhow! { ClientError::FileReadError { source: e, path: path_str}})
}

/// Writes the given SSH key contents to the given path
fn write_key(path: PathBuf, contents: &str) -> Result<()> {
    let path_str = path.to_string_lossy().to_string();
    std::fs::write(path, contents)
        .map_err(|e| anyhow! { ClientError::FileWriteError { source: e, path: path_str}})
}
