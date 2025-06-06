use core::fmt::Display;

pub mod sql;

#[async_trait::async_trait]
pub trait Store: Clone + Send + Sync + 'static {
    type Error: Display;
    async fn verify_api_key(&self, api_key: String) -> Result<(), Self::Error>;
}