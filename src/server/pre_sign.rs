#[async_trait::async_trait]
pub trait PreSignHook: Send + Sync + 'static {
    async fn call(&self, prices: &[(String, u64)]) -> Result<(), tonic::Status>;
}
