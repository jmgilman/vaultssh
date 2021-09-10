use crate::{error::ClientError, Opts};
use anyhow::{anyhow, Result};
use phf::phf_map;
use serde::Deserialize;
use vaultrs_login::method::Method;

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
    pub auth_mount: Option<String>,
    pub basic: Option<bool>,
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
        auth_mount: merge_option(
            "auth_mount",
            opts.auth_mount,
            None,
            config.auth_mount,
            None,
            false,
        )?,
        basic: merge_option(
            "basic",
            Some(opts.basic),
            None,
            config.basic,
            Some(false),
            false,
        )?,
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
            Some(opts.persist),
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

#[test]
fn test_merge() {
    let config = Config {
        approle: None,
        auth: Some(Method::APPROLE),
        auth_mount: Some(String::from("l3")),
        basic: Some(false),
        identity: Some(String::from("l3")),
        mount: None,
        oidc: None,
        persist: Some(true),
        role: Some(String::from("l3")),
        server: Some(String::from("l3")),
        token: Some(String::from("l3")),
        userpass: None,
    };
    let opts = crate::Opts {
        auth: Some(Method::USERPASS),
        auth_mount: Some(String::from("l1")),
        basic: false,
        config: Some(String::from("l1")),
        identity: Some(String::from("l1")),
        mount: None,
        persist: false,
        role: None,
        server: None,
        token: Some(String::from("l1")),
        host: String::from("l1"),
        args: vec![String::from("l1")],
    };
    std::env::set_var("VAULT_ADDR", "l2");
    std::env::set_var("VAULT_TOKEN", "l2");

    let res = merge(opts, config);
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res.auth, Some(Method::USERPASS));
    assert_eq!(res.server, Some(String::from("l2")));
    assert_eq!(res.role, Some(String::from("l3")));
    assert_eq!(res.token, Some(String::from("l1")));
    assert_eq!(res.mount, Some(DEFAULTS["mount"].to_string()))
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

#[test]
fn test_merge_option() {
    let res = merge_option(
        "test",
        Some("test"),
        Some("test1"),
        Some("test2"),
        Some("test3"),
        false,
    );
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), Some("test"));

    let res = merge_option(
        "test",
        None,
        Some("test1"),
        Some("test2"),
        Some("test3"),
        false,
    );
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), Some("test1"));

    let res = merge_option("test", None, None, Some("test2"), Some("test3"), false);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), Some("test2"));

    let res = merge_option("test", None, None, None, Some("test3"), false);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), Some("test3"));

    let res = merge_option::<&str>("test", None, None, None, None, false);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), None);

    let res = merge_option::<&str>("test", None, None, None, None, true);
    assert!(res.is_err());
}
