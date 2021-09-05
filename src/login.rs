use crate::config::Config;
use crate::display;
use crate::error::ClientError;
use anyhow::{anyhow, Result};
use vaultrs::client::{Client, VaultClient};
use vaultrs::login::{self, Method};

/// Checks if the client has a valid token and performs a login if it doesn't.
///
/// If a login is needed, the end-user is prompted to select the login method
/// from a list. Further details are collected depending on the method selected
/// and then finally a login attempt is made. If successful, the given client
/// can be assumed to have a valid token.
pub async fn handle_login(
    client: &mut VaultClient,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Check that the current token is valid
    if client.lookup().await.is_ok() {
        console.success("Valid token found.");
        return Ok(());
    }

    // Offer options for obtaining a new token
    console.error("No valid token found.");

    // Get choice from user, highlighting the default method if provided
    let method = choose_method(&config.auth, console)?;

    // Perform login
    let mount = console.input("Mount", Some(login::method::default_mount(&method)), None)?;

    match method {
        Method::APPROLE => login_approle(client, mount.as_str(), config, console).await?,
        Method::OIDC => login_oidc(client, mount.as_str(), config, console).await?,
        Method::USERPASS => login_userpass(client, mount.as_str(), config, console).await?,
        _ => return Err(ClientError::UnsupportedLogin.into()),
    }

    if config.persist.unwrap() {
        client.token_to_file()?;
    }

    console.success("Login success!");
    Ok(())
}

/// Prompts a user to select a login method from the supported methods.
fn choose_method(default: &Option<Method>, console: &impl display::Console) -> Result<Method> {
    let methods = login::method::SUPPORTED_METHODS.to_vec();
    let index = match default {
        Some(m) => login::method::SUPPORTED_METHODS
            .iter()
            .position(|v| v == m)
            .unwrap_or(0),
        None => 0,
    };
    let index = console
        .select("Please select a login option below", &methods, Some(index))?
        .unwrap();

    Ok(methods[index].clone())
}

/// Performs a login using the AppRole auth engine.
async fn login_approle(
    client: &mut impl Client,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Collect login details
    let default_role_id = if let Some(ref c) = config.approle {
        c.role_id.clone()
    } else {
        String::from("")
    };
    let role_id = console.input("Role ID", None, Some(default_role_id))?;
    let secret_id = console.password("Secret ID")?;

    // Perform login
    let login = login::AppRoleLogin { role_id, secret_id };
    client.login(mount, &login).await?;
    Ok(())
}

/// Performs a login using the OIDC auth engine.
async fn login_oidc(
    client: &mut impl Client,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Collect login details
    let default_role = if let Some(ref c) = config.oidc {
        c.role.clone()
    } else {
        String::from("")
    };
    let role = console.input("Role", Some(String::from("")), Some(default_role))?;
    let role = match role.is_empty() {
        false => Some(role),
        true => None,
    };

    // Generate authorization URL
    let login = vaultrs::login::OIDCLogin { port: None, role };
    let callback = client.login_multi(mount, login).await.unwrap();

    // Attempt to open user's browser to the authorization URL
    console.browser(callback.url.as_str());

    // Wait for callback and then configure newly acquired token
    client.login_multi_callback(mount, callback).await?;

    Ok(())
}

/// Performs a login using the Userpass auth engine.
async fn login_userpass(
    client: &mut impl Client,
    mount: &str,
    config: &Config,
    console: &impl display::Console,
) -> Result<()> {
    // Collect login details
    let default_username = if let Some(ref c) = config.userpass {
        c.username.clone()
    } else {
        String::from("")
    };
    let username = console.input("Username", None, Some(default_username))?;
    let password = console.password("Password")?;

    // Perform login
    let login = login::UserpassLogin { username, password };
    client.login(mount, &login).await?;
    Ok(())
}

/// Attempts to provide greater clarity about certain errors.
///
/// For example, it's confusing when a missing token error is returned when
/// attempting to login. In reality, this translates to there not being any auth
/// engine mounted at the requested path.
pub fn handle_login_error(error: anyhow::Error) -> anyhow::Error {
    if let Some(e) = crate::error::try_api_error(&error) {
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
    use super::{choose_method, login, ClientError, Config};
    use anyhow::anyhow;

    #[tokio::test]
    async fn test_choose_method() {
        let mut console = crate::display::MockConsole::new();
        let default_method = login::Method::USERPASS;

        console
            .expect_select()
            .returning(|_, _: &[login::Method], _| Ok(Some(1)))
            .withf(|prompt, _, _| prompt == "Please select a login option below");
        let res = choose_method(&None, &console);
        assert!(res.is_ok());
        assert!(matches! { res.unwrap(), login::Method::OIDC });

        console
            .expect_select()
            .returning(|_, _: &[login::Method], _| Ok(Some(1)))
            .withf(|prompt, _, default| {
                prompt == "Please select a login option below" && *default == Some(2)
            });
        let res = choose_method(&Some(default_method), &console);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_login_approle() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let mut console = crate::testing::console();

        client
            .expect_login()
            .returning(|_, _: &login::AppRoleLogin| Ok(()))
            .withf(|mount, login| {
                mount == "mount" && login.role_id == "input" && login.secret_id == "password"
            });
        let res = super::login_approle(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        config.approle = Some(crate::config::AppRoleConfig {
            role_id: String::from("role"),
        });
        console.expect_input().withf(|prompt, default, text| {
            prompt == "Role ID" && *default == None && *text == Some(String::from("role"))
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
            .returning(|_, _: login::OIDCLogin| {
                let params = login::oidc::OIDCCallbackParams {
                    code: String::from("code"),
                    nonce: String::from("nonce"),
                    state: String::from("state"),
                };
                Ok(login::OIDCCallback {
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
            .withf(|mount, callback: &login::OIDCCallback| {
                mount == "mount" && callback.url == "test"
            });

        let res = super::login_oidc(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        config.oidc = Some(crate::config::OIDCConfig {
            role: String::from("role"),
        });
        console.expect_input().withf(|prompt, default, text| {
            prompt == "Role" && *default == None && *text == Some(String::from("role"))
        });
        let res = super::login_oidc(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_login_userpass() {
        let mut client = crate::testing::MockClient::new();
        let mut config = Config::default();
        let mut console = crate::testing::console();

        client
            .expect_login()
            .returning(|_, _: &login::UserpassLogin| Ok(()))
            .withf(|mount, login| {
                mount == "mount" && login.username == "input" && login.password == "password"
            });
        let res = super::login_userpass(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());

        config.userpass = Some(crate::config::UserpassConfig {
            username: String::from("username"),
        });
        console.expect_input().withf(|prompt, default, text| {
            prompt == "Username" && *default == None && *text == Some(String::from("username"))
        });
        let res = super::login_userpass(&mut client, "mount", &config, &console).await;
        assert!(res.is_ok());
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
