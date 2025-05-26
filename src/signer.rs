use crate::signer::signature::Signature;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "local")]
pub mod local;
pub mod signature;

#[async_trait::async_trait]
pub trait Signer<S: Signature>: Send + Sync + 'static {
    // TODO: Change to use custom error instead of anyhow.
    // For purpose of development anyhow will be used until other providers are complete
    async fn sign(&self, message: &[u8]) -> anyhow::Result<S>;

    fn public_key(&self) -> &[u8];
}
