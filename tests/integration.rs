mod common;

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use common::VaultServerHelper;
use predicates::prelude::*;
use std::{
    io::Write,
    process::{Command, Stdio},
};
use vaultrs::{
    api::{auth::userpass::requests::CreateUserRequest, ssh::requests::SetRoleRequest},
    client::Client,
    error::ClientError,
};
use vaultrs_test::docker::{Server, ServerConfig};
use vaultrs_test::{VaultServer, VaultServerConfig};

#[test]
fn test_with_login() {
    let config = VaultServerConfig::default(Some(common::VERSION));
    let instance = config.to_instance();

    instance.run(|ops| async move {
        let server = VaultServer::new(&ops, &config);
        let client = server.client();
        let config = setup(&server, &client).await.unwrap();

        // Run the binary
        let mut proc = Command::cargo_bin("vssh")
            .unwrap()
            .arg("-b") // The terminal effects break the test
            .arg("-i")
            .arg(config.key)
            .arg("-a")
            .arg("userpass")
            .arg("--auth-mount")
            .arg(config.userpass.path)
            .arg("-m")
            .arg(config.ssh.path)
            .arg("-r")
            .arg(config.ssh.role)
            .arg("-s")
            .arg(server.address)
            .arg("test.com")
            .arg("--")
            .arg("--help") // Don't want to actually SSH into anything
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        // Write username/password to login prompt
        let mut stdin = proc.stdin.take().unwrap();
        stdin
            .write_fmt(format_args!("{}\n", config.userpass.username))
            .unwrap();
        stdin
            .write_fmt(format_args!("{}\n", config.userpass.password))
            .unwrap();
        drop(stdin);

        let res = proc.wait_with_output().unwrap();
        assert!(res.status.success());

        // Validate a certificate was generated
        config
            .dir
            .child("id_rsa-cert.pub")
            .assert(predicate::path::exists());
    });
}

#[derive(Debug)]
pub struct SSHEndpoint {
    pub path: String,
    pub role: String,
}

pub struct UserpassEndpoint {
    pub path: String,
    pub username: String,
    pub password: String,
}

pub struct TestConfig {
    pub dir: assert_fs::TempDir,
    pub key: String,
    pub ssh: SSHEndpoint,
    pub userpass: UserpassEndpoint,
}

async fn setup(server: &VaultServer, client: &impl Client) -> Result<TestConfig, ClientError> {
    let ssh = SSHEndpoint {
        path: String::from("ssh"),
        role: String::from("test"),
    };
    let userpass = UserpassEndpoint {
        path: String::from("userpass"),
        username: String::from("test"),
        password: String::from("T3st1ng!"),
    };
    let policy = r#"
    path "ssh/*" {
        capabilities = ["create","read","update","delete","list","sudo"]
    }"#;

    // Setup temporary FS
    let dir = assert_fs::TempDir::new().unwrap();
    let key = dir.path().join("id_rsa").to_string_lossy().to_string();
    dir.copy_from("tests/files", &["id_rsa*"]).unwrap();

    // Mount the Userpass auth engine
    server
        .mount_auth(client, userpass.path.as_str(), "userpass")
        .await?;

    // Create policy
    vaultrs::sys::policy::set(client, "test", policy).await?;

    // Create test user
    vaultrs::auth::userpass::user::set(
        client,
        userpass.path.as_str(),
        userpass.username.as_str(),
        userpass.password.as_str(),
        Some(CreateUserRequest::builder().token_policies(vec![String::from("test")])),
    )
    .await?;

    // Mount the SSH secrets engine
    server
        .mount_secret(client, ssh.path.as_str(), "ssh")
        .await?;

    // Create role
    vaultrs::ssh::role::set(
        client,
        ssh.path.as_str(),
        ssh.role.as_str(),
        Some(
            &mut SetRoleRequest::builder()
                .key_type("ca")
                .allow_user_certificates(true)
                .allowed_users("*")
                .default_user("admin")
                .cidr_list("192.168.0.0/16")
                .ttl("10m"),
        ),
    )
    .await?;

    // Generate CA certificate
    vaultrs::ssh::ca::generate(client, ssh.path.as_str()).await?;

    Ok(TestConfig {
        dir,
        key,
        ssh,
        userpass,
    })
}
