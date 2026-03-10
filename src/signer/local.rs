use crate::signer::Signer;
use crate::signer::signature::Signature;
use crate::signer::signature::ecdsa::DerSignature;
use k256::ecdsa;
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;

// ECDSA Signer (secp256k1)
pub struct LocalSigner {
    signing_key: EcdsaSigningKey,
    // Storing these avoids lifetime issues when returning slices
    compressed_pk: Vec<u8>,
    uncompressed_pk: Vec<u8>,
}

impl LocalSigner {
    pub fn new(private_key: &[u8]) -> Result<Self, ecdsa::Error> {
        let signing_key = EcdsaSigningKey::from_slice(private_key)?;
        let vk = signing_key.verifying_key();

        let compressed_pk = vk.to_encoded_point(true).as_bytes().to_vec();
        let uncompressed_pk = vk.to_encoded_point(false).as_bytes().to_vec();

        Ok(LocalSigner {
            signing_key,
            compressed_pk,
            uncompressed_pk,
        })
    }
}

#[async_trait::async_trait]
impl Signer for LocalSigner {
    // Ensure these match your trait's async/sync status
    async fn sign_ecdsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .signing_key
            .sign_prehash_recoverable(message)?
            .into_vec())
    }

    async fn sign_der(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature: DerSignature = self.signing_key.sign_prehash(message)?;
        Ok(signature.into_vec())
    }

    fn public_key(&self, compressed: bool) -> &[u8] {
        if compressed {
            &self.compressed_pk
        } else {
            &self.uncompressed_pk
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signer::Signer;
    use k256::sha2::{Digest, Sha512};
    use sha3::Keccak256;

    #[tokio::test]
    async fn test_sign_ecdsa() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk).unwrap();
        let message = b"Hello, world!";
        let signature = hex::encode(
            &signer
                .sign_ecdsa(&Keccak256::digest(message))
                .await
                .unwrap()[..64],
        );
        let expected = "351ce606456376c70913430ab2eabd76e3e6e6b7898fb01422e31cbffe2cf55b5a1d67d3a35367879e4983d50bdfcdc0cd052b8ec30edbaa47dcfe36585adf47";

        assert_eq!(signature, expected);
    }

    #[tokio::test]
    async fn test_sign_der() {
        let pk = hex::decode("45ea1ad910df93d1a021a42f384aad55c7c65d565ad6b2203a4ba50418922a7b")
            .unwrap();
        let signer = LocalSigner::new(&pk).unwrap();
        let message = &Sha512::digest(b"Hello, world!")[..32];
        let signature = hex::encode(signer.sign_der(message).await.unwrap());
        let expected = "304402203a3fcf5aadf9e26bc931fc54a924013413d80fb538c5048fc4e4c8dd2e6c178502202de7b72145515c0d23ed4f2bce9dd26541c26059557a607ccdcfee47d88cd1eb";

        assert_eq!(signature, expected);
    }
}
