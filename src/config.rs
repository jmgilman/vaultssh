use crate::{error::ClientError, Opts};
use anyhow::{anyhow, Result};
use phf::phf_map;
use serde::Deserialize;
use vaultrs::login::Method;

pub static DEFAULTS: phf::Map<&'static str, &'static str> = phf_map! {
    "config" => "~/.vssh",
    "identity" => "~/.ssh/id_rsa",
    "mount" => "ssh",
};

/// Represents the format of the configuration file
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub approle: Option<AppRoleConfig>,
    pub auth: Option<Method>,
    pub identity: Option<String>,
    pub mount: Option<String>,
    pub oidc: Option<OIDCConfig>,
    pub persist: Option<bool>,
    pub role: Option<String>,
    pub server: Option<String>,
    pub token: Option<String>,
    pub userpass: Option<UserpassConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AppRoleConfig {
    pub role_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OIDCConfig {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UserpassConfig {
    pub username: String,
}

impl Config {
    /// Attempts to parse a [Config] from the given TOML file path
    pub fn new(path: &str) -> Result<Self> {
        let path = std::path::Path::new(path);

        if !path.exists() {
            return Err(
                anyhow! { ClientError::FileNotFound { path: path.to_string_lossy().to_string()}},
            );
        }

        let content = std::fs::read_to_string(path).map_err(|e| ClientError::FileReadError {
            source: e,
            path: path.to_string_lossy().to_string(),
        })?;

        toml::from_str::<Config>(content.as_str()).map_err(|e| {
            anyhow! { ClientError::ConfigParseError {
                source: e,
                path: path.to_string_lossy().to_string(),
            }}
        })
    }
}

/// Merges configuration options with CLI, environment, and in some cases
/// default options.
///
/// If a required option cannot be found an error is returned.
pub fn merge(opts: Opts, config: Config) -> Result<Config> {
    Ok(Config {
        approle: config.approle,
        auth: merge_option("auth_method", opts.auth, None, config.auth, None, false)?,
        identity: merge_option(
            "identity",
            opts.identity,
            None,
            config.identity,
            Some(DEFAULTS["identity"].to_string()),
            true,
        )?,
        mount: merge_option(
            "mount",
            opts.mount,
            None,
            config.mount,
            Some(DEFAULTS["mount"].to_string()),
            true,
        )?,
        oidc: config.oidc,
        persist: merge_option(
            "persist",
            opts.persist,
            None,
            config.persist,
            Some(false),
            false,
        )?,
        role: merge_option(
            "role",
            opts.role,
            None,
            config.role,
            Some("default".to_string()),
            true,
        )?,
        server: merge_option(
            "server",
            opts.server,
            std::env::var("VAULT_ADDR").ok(),
            config.server,
            None,
            true,
        )?,
        token: merge_option(
            "token",
            opts.token,
            std::env::var("VAULT_TOKEN").ok(),
            config.token,
            None,
            false,
        )?,
        userpass: config.userpass,
    })
}

/// Merges options in the order of CLI > Env > Config > default.
///
/// This function will fail if an option is required but no value is found.
fn merge_option<T>(
    name: &str,
    cli: Option<T>,
    env: Option<T>,
    config: Option<T>,
    default: Option<T>,
    required: bool,
) -> Result<Option<T>> {
    match cli {
        Some(v) => Ok(Some(v)),
        None => match env {
            Some(v) => Ok(Some(v)),
            None => match config {
                Some(v) => Ok(Some(v)),
                None => match default {
                    Some(v) => Ok(Some(v)),
                    None => {
                        if required {
                            Err(
                                anyhow! { ClientError::MissingArgumentError { arg: name.to_string() } },
                            )
                        } else {
                            Ok(None)
                        }
                    }
                },
            },
        },
    }
}
