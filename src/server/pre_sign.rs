#[async_trait::async_trait]
pub trait PreSignHook: Send + Sync + 'static {
    async fn call(&self, tx_message: &[u8]) -> Result<(), tonic::Status>;
}
