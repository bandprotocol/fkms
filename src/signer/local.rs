use crate::signer::Signer;
use k256::ecdsa;
use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Signer as EcdsaSigner;
use k256::elliptic_curve::sec1::ToEncodedPoint;

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

    fn sign_ecdsa(&self, message: &[u8]) -> ecdsa::Signature {
        self.signing_key.sign(message)
    }

    fn ecsda_public_key(&self) -> &[u8] {
        self.ecdsa_public_key.as_slice()
    }
}

#[async_trait::async_trait]
impl Signer<ecdsa::Signature> for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<ecdsa::Signature> {
        Ok(self.sign_ecdsa(message))
    }

    fn public_key(&self) -> &[u8] {
        self.ecsda_public_key()
    }
}

#[cfg(test)]
mod test {
    use crate::signer::local::LocalSigner;

    #[test]
    fn test_sign_ecdsa() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk).unwrap();
        let message = b"Hello, world!";
        let signature = hex::encode(signer.sign_ecdsa(message).to_bytes());
        let expected = "a09edc400231f09d7d45481a4a5aee58e2d9e194e28cb9a42bbfed6a46735620038597c0afdbb500cabd87a16305ef19c7df944d214b63379689f0ad2ae5dc71";

        assert_eq!(signature, expected);
    }
}
