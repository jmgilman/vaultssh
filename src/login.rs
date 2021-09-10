use crate::config::Config;
use crate::display;
use crate::error::ClientError;
use anyhow::{anyhow, Result};
use vaultrs::client::Client;
use vaultrs_login::method::{self, Method};
use vaultrs_login::{
    engines::{approle::AppRoleLogin, oidc::OIDCLogin, userpass::UserpassLogin},
    LoginClient,
};

/// Provides a method for generating login methods from a CLI prompt
pub trait LoginPrompt: Sized {
    fn prompt(console: &impl display::Console, config: &Config) -> Result<Self>;
}

impl LoginPrompt for AppRoleLogin {
    fn prompt(console: &impl display::Console, config: &Config) -> Result<Self> {
        let role_id = match config.approle.as_ref() {
            Some(c) => c.role_id.clone(),
            None => console.input("Role ID", None, None)?,
        };
        let secret_id = console.password("Secret ID")?;

        Ok(AppRoleLogin { role_id, secret_id })
    }
}

impl LoginPrompt for OIDCLogin {
    fn prompt(console: &impl display::Console, config: &Config) -> Result<Self> {
        let role = match config.oidc.as_ref() {
            Some(c) => c.role.clone(),
            None => console.input("Role", None, None)?,
        };
        let role = match role.is_empty() {
            false => Some(role),
            true => None,
        };

        Ok(OIDCLogin { port: None, role })
    }
}

impl LoginPrompt for UserpassLogin {
    fn prompt(console: &impl display::Console, config: &Config) -> Result<Self> {
        let username = match config.userpass.as_ref() {
            Some(c) => c.username.clone(),
            None => console.input("Username", None, None)?,
        };
        let password = console.password("Password")?;

        Ok(UserpassLogin { username, password })
    }
}

/// Provides an interface for persisting tokens to a filesystem
pub trait TokenFileHandler {
    /// Reads a token from the default location and returns it
    fn token_from_file() -> Result<String>;

    /// Writes the token configured for the client to the default location.
    fn token_to_file(&self) -> Result<()>;
}

impl<C: Client> TokenFileHandler for C {
    fn token_from_file() -> Result<String> {
        let home_dir = dirs::home_dir();
        let token_file = match home_dir {
            Some(d) => d.join(".vault-token"),
            None => {
                return Err(anyhow! { ClientError::FileNotFound {
                    path: "$HOME".to_string(),
                }})
            }
        };

        let token_file_string = token_file.to_string_lossy().to_string();
        if !token_file.exists() {
            return Err(anyhow! { ClientError::FileNotFound{
                path: token_file_string,
            }});
        }

        std::fs::read_to_string(token_file).map_err(|e| {
            anyhow! {  ClientError::FileReadError {
                source: e,
                path: token_file_string.clone(),
            }}
        })
    }

    fn token_to_file(&self) -> Result<()> {
        let home_dir = dirs::home_dir();
        let token_file = match home_dir {
            Some(d) => d.join(".vault-token"),
            None => {
                return Err(anyhow! { ClientError::FileNotFound {
                    path: "$HOME".to_string(),
                }})
            }
        };

        let token_file_string = token_file.to_string_lossy().to_string();
        std::fs::write(token_file, self.settings().token.clone()).map_err(|e| {
            anyhow! { ClientError::FileWriteError {
                source: e,
                path: token_file_string,
            } }
        })
    }
}

/// Checks if the client has a valid token and performs a login if it doesn't.
///
/// If a login is needed, the end-user is prompted to select the login method
/// from a list. Further details are collected depending on the method selected
/// and then finally a login attempt is made. If successful, the given client
/// can be assumed to have a valid token.
pub async fn login(
    client: &mut impl LoginClient,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Use default method and mount, otherwise prompt user to select
    let method = match config.auth.as_ref() {
        Some(m) => m.clone(),
        None => choose_method(console)?,
    };
    let mount = match config.auth_mount.as_ref() {
        Some(m) => m.clone(),
        None => console.input("Mount", Some(method::default_mount(&method)), None)?,
    };

    // Perform login
    match method {
        Method::APPROLE => login_approle(client, mount.as_str(), config, console).await?,
        Method::OIDC => login_oidc(client, mount.as_str(), config, console).await?,
        Method::USERPASS => login_userpass(client, mount.as_str(), config, console).await?,
        _ => return Err(ClientError::UnsupportedLogin.into()),
    }

    // Persist token to ~/.vault-token if requested by user
    if config.persist.unwrap_or(false) {
        client.token_to_file()?;
    }

    Ok(())
}

/// Prompts a user to select a login method from the supported methods.
fn choose_method(console: &impl display::Console) -> Result<Method> {
    let methods = method::SUPPORTED_METHODS.to_vec();
    let index = console
        .select("Please select a login option below", &methods, None)?
        .unwrap();

    Ok(methods[index].clone())
}

/// Performs a login using the AppRole auth engine.
async fn login_approle(
    client: &mut impl LoginClient,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    let params = AppRoleLogin::prompt(console, config)?;
    client.login(mount, &params).await?;
    Ok(())
}

/// Performs a login using the OIDC auth engine.
async fn login_oidc(
    client: &mut impl LoginClient,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Generate authorization URL
    let params = OIDCLogin::prompt(console, config)?;
    let callback = client.login_multi(mount, params).await?;

    // Attempt to open user's browser to the authorization URL
    console.browser(callback.url.as_str());

    // Wait for callback and then configure newly acquired token
    client.login_multi_callback(mount, callback).await?;

    Ok(())
}

/// Performs a login using the Userpass auth engine.
async fn login_userpass(
    client: &mut impl LoginClient,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    let params = UserpassLogin::prompt(console, config)?;
    client.login(mount, &params).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{choose_method, Config};
    use vaultrs_login::engines::{
        approle::AppRoleLogin,
        oidc::{OIDCCallback, OIDCCallbackParams, OIDCLogin},
        userpass::UserpassLogin,
    };
    use vaultrs_login::method::Method;

    #[tokio::test]
    async fn test_login() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let mut console = crate::testing::console();

        console
            .expect_select()
            .returning(|_, _: &[Method], _| Ok(Some(0)))
            .withf(|prompt, _, _| prompt == "Please select a login option below");
        client
            .expect_login()
            .returning(|_, _: &AppRoleLogin| Ok(()))
            .withf(|mount, login| {
                mount == "input" && login.role_id == "input" && login.secret_id == "password"
            });
        let res = super::login(&mut client, &config, &console).await;
        assert!(res.is_ok());

        // Test with default
        let console = crate::testing::console();
        config.auth = Some(Method::APPROLE);
        config.auth_mount = Some(String::from("mount"));
        config.approle = Some(crate::config::AppRoleConfig {
            role_id: String::from("role"),
        });
        client
            .expect_login()
            .returning(|_, _: &AppRoleLogin| Ok(()))
            .withf(|mount, login| {
                mount == "mount" && login.role_id == "role" && login.secret_id == "password"
            });
        let res = super::login(&mut client, &config, &console).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_choose_method() {
        let mut console = crate::display::MockConsole::new();

        console
            .expect_select()
            .returning(|_, _: &[Method], _| Ok(Some(1)))
            .withf(|prompt, _, _| prompt == "Please select a login option below");
        let res = choose_method(&console);
        assert!(res.is_ok());
        assert!(matches! { res.unwrap(), Method::OIDC });
    }

    #[tokio::test]
    async fn test_login_approle() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let console = crate::testing::console();

        client
            .expect_login()
            .returning(|_, _: &AppRoleLogin| Ok(()))
            .withf(|mount, login| {
                mount == "mount" && login.role_id == "input" && login.secret_id == "password"
            });
        let res = super::login_approle(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        // Test with default
        config.approle = Some(crate::config::AppRoleConfig {
            role_id: String::from("role"),
        });
        client
            .expect_login()
            .returning(|_, _: &AppRoleLogin| Ok(()))
            .withf(|mount, login: &AppRoleLogin| {
                mount == "mount" && login.role_id == "role" && login.secret_id == "password"
            });
        let res = super::login_approle(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_login_oidc() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let mut console = crate::testing::console();

        client
            .expect_login_multi()
            .returning(|_, _: OIDCLogin| {
                let params = OIDCCallbackParams {
                    code: String::from("code"),
                    nonce: String::from("nonce"),
                    state: String::from("state"),
                };
                Ok(OIDCCallback {
                    handle: tokio::task::spawn(async { params }),
                    url: String::from("test"),
                })
            })
            .withf(|mount, login| {
                mount == "mount" && login.port == None && login.role == Some(String::from("input"))
            });

        console
            .expect_browser()
            .returning(|_| ())
            .withf(|url| url == "test");
        client
            .expect_login_multi_callback()
            .returning(|_, _| Ok(()))
            .withf(|mount, callback: &OIDCCallback| mount == "mount" && callback.url == "test");

        let res = super::login_oidc(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        // Test with default
        config.oidc = Some(crate::config::OIDCConfig {
            role: String::from("role"),
        });
        client
            .expect_login_multi()
            .returning(|_, _: OIDCLogin| {
                let params = OIDCCallbackParams {
                    code: String::from("code"),
                    nonce: String::from("nonce"),
                    state: String::from("state"),
                };
                Ok(OIDCCallback {
                    handle: tokio::task::spawn(async { params }),
                    url: String::from("test"),
                })
            })
            .withf(|mount, login| {
                mount == "mount" && login.port == None && login.role == Some(String::from("role"))
            });
        let res = super::login_oidc(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_login_userpass() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let console = crate::testing::console();

        client
            .expect_login()
            .returning(|_, _: &UserpassLogin| Ok(()))
            .withf(|mount, login| {
                mount == "mount" && login.username == "input" && login.password == "password"
            });
        let res = super::login_userpass(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        // Test with default
        config.userpass = Some(crate::config::UserpassConfig {
            username: String::from("username"),
        });
        client
            .expect_login()
            .returning(|_, _: &UserpassLogin| Ok(()))
            .withf(|mount, login: &UserpassLogin| {
                mount == "mount" && login.username == "username" && login.password == "password"
            });
        let res = super::login_userpass(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());
    }
}
