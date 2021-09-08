use testcontainers::clients::Cli;
use testcontainers::images::generic::{GenericImage, WaitFor};
use testcontainers::{Container, Docker};
use vaultrs::api::sys::requests::{EnableEngineDataConfig, EnableEngineRequest};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::sys::{auth, mount};

const NETWORK: &str = "test";
const TOKEN: &str = "testtoken";
const VERSION: &str = "1.8.2";

pub struct VaultServer<'a> {
    pub address: String,
    pub client: VaultClient,
    pub container: Container<'a, Cli, GenericImage>,
}

impl<'a> VaultServer<'a> {
    pub fn new(client: &'a Cli) -> Self {
        let im = GenericImage::new(format!("vault:{}", VERSION))
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", TOKEN)
            .with_wait_for(WaitFor::message_on_stdout(
                "Development mode should NOT be used in production installations!",
            ));
        let args = testcontainers::RunArgs::default();

        let container = client.run_with_args(im, args.with_network(NETWORK));
        let host_port = container.get_host_port(8200).unwrap();
        let address = format!("http://localhost:{}", host_port);
        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(address.as_str())
                .token(TOKEN)
                .build()
                .unwrap(),
        )
        .unwrap();

        VaultServer {
            address,
            client,
            container,
        }
    }

    #[allow(dead_code)]
    pub async fn mount(&self, path: &str, engine: &str) -> Result<(), ClientError> {
        mount::enable(&self.client, path, engine, None).await
    }

    #[allow(dead_code)]
    pub async fn mount_auth(&self, path: &str, engine: &str) -> Result<(), ClientError> {
        auth::enable(&self.client, path, engine, None).await
    }

    #[allow(dead_code)]
    pub async fn mount_with_config(
        &self,
        path: &str,
        engine: &str,
        config: EnableEngineDataConfig,
    ) -> Result<(), ClientError> {
        mount::enable(
            &self.client,
            path,
            engine,
            Some(EnableEngineRequest::builder().config(config)),
        )
        .await
    }
}
