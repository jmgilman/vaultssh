use async_trait::async_trait;
use mockall::mock;
use rustify::clients::reqwest::Client as HTTPClient;
use vaultrs::api::EndpointMiddleware;
use vaultrs::client::{Client, VaultClientSettings};
use vaultrs::error::ClientError;
use vaultrs::login::core::{LoginMethod, MultiLoginCallback, MultiLoginMethod};
use vaultrs::login::Method;

mock! {
    pub Client {}

    #[async_trait]
    impl Client for Client {
        fn http(&self) -> &HTTPClient;
        async fn login<M: 'static + LoginMethod>(&mut self, mount: &str, method: &M) -> Result<(), ClientError>;
        async fn login_multi<M: 'static + MultiLoginMethod>(
            &self,
            mount: &str,
            method: M,
        ) -> Result<M::Callback, ClientError>;
        async fn login_multi_callback<C: 'static + MultiLoginCallback>(
            &mut self,
            mount: &str,
            callback: C,
        ) -> Result<(), ClientError>;
        fn middle(&self) -> &EndpointMiddleware;
        fn settings(&self) -> &VaultClientSettings;
    }
}

pub fn console() -> crate::display::MockConsole {
    let mut console = crate::display::MockConsole::new();
    console
        .expect_input()
        .returning(|_, _, _| Ok(String::from("input")));
    console
        .expect_password()
        .returning(|_| Ok(String::from("password")));
    console
        .expect_select()
        .returning(|_, _: &[Method], _| Ok(Some(0)));
    console
}
