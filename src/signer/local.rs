use crate::config::signer::local::ChainType;
use crate::signer::signature::Signature;
use crate::signer::signature::ecdsa::DerSignature;
use crate::signer::{Signer, public_key_to_evm_address, public_key_to_xrpl_address};
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;

// ECDSA Signer (secp256k1)
pub struct LocalSigner {
    signing_key: SigningKey,
    public_key: Vec<u8>,
    address: String,
    chain_type: ChainType,
}

pub enum SigningKey {
    Ecdsa(EcdsaSigningKey),
}

impl LocalSigner {
    pub fn new(private_key: &[u8], chain_type: &ChainType) -> anyhow::Result<Self> {
        let (signing_key, public_key, address) = match chain_type {
            ChainType::Evm => {
                let signing_key = EcdsaSigningKey::from_slice(private_key)?;
                let public_key = create_public_key(&signing_key, false);
                let address = public_key_to_evm_address(&public_key)?;
                (SigningKey::Ecdsa(signing_key), public_key, address)
            }
            ChainType::Xrpl => {
                let signing_key = EcdsaSigningKey::from_slice(private_key)?;
                let public_key = create_public_key(&signing_key, true);
                let address = public_key_to_xrpl_address(&public_key)?;
                (SigningKey::Ecdsa(signing_key), public_key, address)
            }
        };

        Ok(LocalSigner {
            signing_key,
            public_key,
            address,
            chain_type: chain_type.clone(),
        })
    }

    async fn sign_ecdsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::Ecdsa(signing_key) => {
                Ok(signing_key.sign_prehash_recoverable(message)?.into_vec())
            }
        }
    }

    async fn sign_der(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::Ecdsa(signing_key) => {
                let signature: DerSignature = signing_key.sign_prehash(message)?;
                Ok(signature.into_vec())
            }
        }
    }
}

#[async_trait::async_trait]
impl Signer for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.chain_type {
            ChainType::Evm => self.sign_ecdsa(message).await,
            ChainType::Xrpl => self.sign_der(message).await,
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn address(&self) -> &str {
        &self.address
    }

    fn chain_type(&self) -> &ChainType {
        &self.chain_type
    }
}

fn create_public_key(signing_key: &EcdsaSigningKey, compressed: bool) -> Vec<u8> {
    signing_key
        .verifying_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
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
        let signer = LocalSigner::new(&pk, &ChainType::Evm).unwrap();
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
        let signer = LocalSigner::new(&pk, &ChainType::Evm).unwrap();
        let message = &Sha512::digest(b"Hello, world!")[..32];
        let signature = hex::encode(signer.sign_der(message).await.unwrap());
        let expected = "304402203a3fcf5aadf9e26bc931fc54a924013413d80fb538c5048fc4e4c8dd2e6c178502202de7b72145515c0d23ed4f2bce9dd26541c26059557a607ccdcfee47d88cd1eb";

        assert_eq!(signature, expected);
    }

    #[test]
    fn test_address_generation_evm() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Evm).unwrap();
        assert_eq!(
            signer.address(),
            "0x994df35cc8d6954155ec2d9d3d59b40d0e0bce93"
        );
    }

    #[test]
    fn test_address_generation_xrpl() {
        let pk = hex::decode("D5A397A10DE2C485FA5592FFD86A7B5744BC221E24F71196ACD32EB66B14264C")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Xrpl).unwrap();
        assert_eq!(signer.address(), "rpeTutzWtCQbVv9EmwJFQvtebkMw42ujnG");
    }

    #[test]
    fn test_public_key_to_evm_address_1() {
        let pk = hex::decode("04b01ab5a1640da9ad9f9593c9e3d90a68a6a64b9fa4742edb13acb15e93ebee20ae14072003dd69a1eaf060bb74a90e27acd3e66fdb234b5225c665e2a26f52e7").unwrap();
        let address = public_key_to_evm_address(&pk).unwrap();
        let expected = "0x29754940a23e3571db50103dd379e1ec15597611";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_2() {
        let pk = hex::decode("0470d624fa6823e50a874d65580961696626059fc2fc7d698813e24550ab51f1e5eb58b15735e50318a1c9f79c2d6b5a5c7fe34b64c99e59c207b0bb7f7c492b83").unwrap();
        let address = public_key_to_evm_address(&pk).unwrap();
        let expected = "0x151df313e367d60af962bd1fbd2508cf8da1fed6";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_3() {
        let pk = hex::decode("0409cb1cab6bd46b7b050bf8427850340bc6906b88957d584432f6fc6510688f4a7c01b45e009bd1d700b4486325c915a6d25ba69722c8ded9da0ab76941870e3d").unwrap();
        let address = public_key_to_evm_address(&pk).unwrap();
        let expected = "0xf9c62d223a203c8160f19be3588e41d9d6e67a59";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_xrpl_address() {
        let pk = hex::decode("02D5A397A10DE2C485FA5592FFD86A7B5744BC221E24F71196ACD32EB66B14264C")
            .unwrap();
        let address = public_key_to_xrpl_address(&pk).unwrap();
        let expected = "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB";
        assert_eq!(address, expected);
    }
}
