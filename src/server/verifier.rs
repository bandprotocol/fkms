#[async_trait::async_trait]
pub trait Verifier: Send + Sync + 'static {
    async fn verify_message(&self, message: &[u8]) -> Result<(), tonic::Status>;
}
