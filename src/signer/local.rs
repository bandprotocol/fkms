use crate::signer::Signer;
use k256::ecdsa;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::signer::signature::ecdsa::EcdsaSignature;

pub struct LocalSigner {
    signing_key: SigningKey,
    ecdsa_public_key: Vec<u8>,
}

impl LocalSigner {
    pub fn new(private_key: &[u8]) -> Result<Self, ecdsa::Error> {
        let signing_key = SigningKey::from_slice(private_key)?;
        let ecdsa_public_key = signing_key
            .verifying_key()
            .as_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        Ok(LocalSigner {
            signing_key,
            ecdsa_public_key,
        })
    }

    fn sign_ecdsa(
        &self,
        message: &[u8],
    ) -> Result<EcdsaSignature, ecdsa::Error> {
        self.signing_key.sign_prehash_recoverable(message)
    }

    fn ecsda_public_key(&self) -> &[u8] {
        self.ecdsa_public_key.as_slice()
    }
}

#[async_trait::async_trait]
impl Signer<EcdsaSignature> for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<EcdsaSignature> {
        Ok(self.sign_ecdsa(message)?)
    }

    fn public_key(&self) -> &[u8] {
        self.ecsda_public_key()
    }
}

#[cfg(test)]
mod test {
    use crate::signer::local::LocalSigner;
    use k256::sha2::Digest;
    use sha3::Keccak256;

    #[test]
    fn test_sign_ecdsa() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk).unwrap();
        let message = b"Hello, world!";
        let signature = hex::encode(
            signer
                .sign_ecdsa(&Keccak256::digest(message))
                .unwrap()
                .0
                .to_bytes(),
        );
        let expected = "351ce606456376c70913430ab2eabd76e3e6e6b7898fb01422e31cbffe2cf55b5a1d67d3a35367879e4983d50bdfcdc0cd052b8ec30edbaa47dcfe36585adf47";

        assert_eq!(signature, expected);
    }
}
