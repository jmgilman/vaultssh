use crate::config::Config;
use crate::display;
use crate::error::ClientError;
use anyhow::{anyhow, Result};
use console::Term;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use vaultrs::client::VaultClient;
use vaultrs::login::{self, Method};

/// Checks if the client has a valid token and performs a login if it doesn't.
///
/// If a login is needed, the end-user is prompted to select the login method
/// from a list. Further details are collected depending on the method selected
/// and then finally a login attempt is made. If successful, the given client
/// can be assumed to have a valid token.
pub async fn handle_login(client: &mut VaultClient, config: &Config) -> Result<()> {
    // Check that the current token is valid
    if client.lookup().await.is_ok() {
        display::print_success("Valid token found.");
        return Ok(());
    }

    // Offer options for obtaining a new token
    display::print_error("No valid token found.");

    // Get choice from user, highlighting the default method if provided
    let method = choose_method(&config.auth)?;

    // Perform login
    let mount = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Mount")
        .default(login::method::default_mount(&method))
        .interact_text()?;

    match method {
        Method::APPROLE => login_approle(client, mount.as_str(), config).await?,
        Method::OIDC => login_oidc(client, mount.as_str(), config).await?,
        Method::USERPASS => login_userpass(client, mount.as_str(), config).await?,
        _ => return Err(ClientError::UnsupportedLogin.into()),
    }

    if config.persist.unwrap() {
        client.token_to_file()?;
    }

    display::print_success("Login success!");
    Ok(())
}

/// Prompts a user to select a login method from the supported methods.
fn choose_method(default: &Option<Method>) -> Result<Method> {
    let methods = login::method::SUPPORTED_METHODS.to_vec();
    let index = match default {
        Some(m) => login::method::SUPPORTED_METHODS
            .iter()
            .position(|v| v == m)
            .unwrap_or(0),
        None => 0,
    };

    let index = Select::with_theme(&ColorfulTheme::default())
        .items(&methods)
        .default(index)
        .with_prompt("Please select a login option below")
        .interact_on_opt(&Term::stderr())?
        .unwrap();

    Ok(methods[index].clone())
}

/// Performs a login using the AppRole auth engine.
async fn login_approle(client: &mut VaultClient, mount: &str, config: &Config) -> Result<()> {
    // Collect login details
    let default_role_id = if let Some(ref c) = config.approle {
        c.role_id.clone()
    } else {
        "".to_string()
    };
    let role_id = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Role ID")
        .with_initial_text(default_role_id)
        .interact_text()?;
    let secret_id = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Secret ID")
        .interact()?;

    // Perform login
    let login = login::AppRoleLogin { role_id, secret_id };
    client.login(mount, &login).await?;
    Ok(())
}

/// Performs a login using the OIDC auth engine.
async fn login_oidc(client: &mut VaultClient, mount: &str, config: &Config) -> Result<()> {
    // Collect login details
    let default_role = if let Some(ref c) = config.oidc {
        c.role.clone()
    } else {
        "".to_string()
    };
    let role = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Role")
        .default("".to_string())
        .with_initial_text(default_role)
        .interact_text()?;

    let role = match role.is_empty() {
        false => Some(role),
        true => None,
    };

    // Generate authorization URL
    let login = vaultrs::login::OIDCLogin { port: None, role };
    let callback = client.login_multi(mount, login).await.unwrap();

    // Attempt to open user's browser to the authorization URL
    display::print_neutral("Opening browser to OIDC provider...");
    if webbrowser::open(callback.url.as_str()).is_err() {
        display::print_error("Failed opening browser. Please manually paste the below URL:");
        println!("{}", callback.url)
    }

    // Wait for callback and then configure newly acquired token
    client.login_multi_callback("oidc", callback).await?;

    Ok(())
}

/// Performs a login using the Userpass auth engine.
async fn login_userpass(client: &mut VaultClient, mount: &str, config: &Config) -> Result<()> {
    // Collect login details
    let default_username = if let Some(ref c) = config.userpass {
        c.username.clone()
    } else {
        "".to_string()
    };
    let username = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .with_initial_text(default_username)
        .interact_text()?;
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()?;

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
