#[async_trait::async_trait]
pub trait PreSignHook: Send + Sync + 'static {
    async fn call(&self, message: &[u8]) -> Result<(), tonic::Status>;
}
