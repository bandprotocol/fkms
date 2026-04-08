use crate::config::signer::local::ChainType;
use crate::signer::signature::Signature;
use crate::signer::signature::ecdsa::{DerSignature, P256Signature};
use crate::signer::{
    Signer, public_key_to_evm_address, public_key_to_icon_address, public_key_to_secret_address,
    public_key_to_xrpl_address,
};
use ecdsa::SignatureSize;
use ecdsa::hazmat::SignPrimitive;
use ecdsa::{PrimeCurve, SigningKey as EcdsaSigningKey};
use ed25519_dalek::Signer as Ed25519Signer;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::ops::Invert;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::sec1::{self, FromEncodedPoint};
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{AffinePoint, FieldBytesSize, Scalar};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::elliptic_curve::CurveArithmetic;
use p256::ecdsa::SigningKey as P256SigningKey;
use stellar_strkey::Strkey;

pub struct LocalSigner {
    signing_key: SigningKey,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    address: String,
    chain_type: ChainType,
}

pub enum SigningKey {
    EcdsaK256(K256SigningKey),
    EcdsaP256(P256SigningKey),
    Ed25519(Ed25519SigningKey),
}

impl LocalSigner {
    pub fn new(
        private_key: &[u8],
        chain_type: &ChainType,
        address: Option<&str>,
    ) -> anyhow::Result<Self> {
        let (signing_key, public_key, address) = match chain_type {
            ChainType::Evm => {
                let signing_key = K256SigningKey::from_slice(private_key)?;
                let public_key = create_ecdsa_public_key(&signing_key, false);
                let address = public_key_to_evm_address(&public_key)?;
                (SigningKey::EcdsaK256(signing_key), public_key, address)
            }
            ChainType::Xrpl => {
                let signing_key = K256SigningKey::from_slice(private_key)?;
                let public_key = create_ecdsa_public_key(&signing_key, true);
                let address = public_key_to_xrpl_address(&public_key)?;
                (SigningKey::EcdsaK256(signing_key), public_key, address)
            }
            ChainType::Icon => {
                let signing_key = K256SigningKey::from_slice(private_key)?;
                let public_key = create_ecdsa_public_key(&signing_key, false);
                let address = public_key_to_icon_address(&public_key)?;
                (SigningKey::EcdsaK256(signing_key), public_key, address)
            }
            ChainType::Flow => {
                let address = address
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Flow chain type requires address in config (Flow addresses are network-assigned)"
                        )
                    })?
                    .to_string();

                if !is_valid_flow_address(&address) {
                    return Err(anyhow::anyhow!(
                        "Invalid Flow address: {}. Must be 16 hex characters, optionally prefixed with 0x.",
                        address
                    ));
                }

                let signing_key = P256SigningKey::from_slice(private_key)?;
                let public_key = create_ecdsa_public_key(&signing_key, false);
                (SigningKey::EcdsaP256(signing_key), public_key, address)
            }
            ChainType::Soroban => {
                let key_bytes: [u8; 32] = private_key
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Ed25519 private key must be exactly 32 bytes"))?;
                let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
                let public_key = signing_key.verifying_key().to_bytes().to_vec();
                let public_key_address = Strkey::PublicKeyEd25519(
                    stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes()),
                )
                .to_string()
                .to_string();
                (
                    SigningKey::Ed25519(signing_key),
                    public_key,
                    public_key_address,
                )
            }
            ChainType::Secret => {
                let signing_key = EcdsaSigningKey::from_slice(private_key)?;
                let public_key = create_ecdsa_public_key(&signing_key, true);
                let address = public_key_to_secret_address(&public_key)?;
                (SigningKey::EcdsaK256(signing_key), public_key, address)
            }
        };

        Ok(LocalSigner {
            signing_key,
            public_key,
            private_key: private_key.to_vec(),
            address,
            chain_type: chain_type.clone(),
        })
    }

    async fn sign_ecdsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::EcdsaK256(signing_key) => {
                Ok(signing_key.sign_prehash_recoverable(message)?.into_vec())
            }
            _ => Err(anyhow::anyhow!(
                "Wrong signing key type for secp256k1 ECDSA"
            )),
        }
    }

    async fn sign_der(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::EcdsaK256(signing_key) => {
                let signature: DerSignature = signing_key.sign_prehash(message)?;
                Ok(signature.into_vec())
            }
            _ => Err(anyhow::anyhow!("Wrong signing key type for DER ECDSA")),
        }
    }

    async fn sign_p256(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::EcdsaP256(signing_key) => {
                let signature: P256Signature = signing_key.sign_prehash(message)?;
                Ok(signature.into_vec())
            }
            _ => Err(anyhow::anyhow!("Wrong signing key type for P-256 ECDSA")),
        }
    }

    async fn sign_ed25519(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.signing_key {
            SigningKey::Ed25519(signing_key) => {
                let signature = signing_key.sign(message);
                Ok(signature.into_vec())
            }
            _ => Err(anyhow::anyhow!("Wrong signing key type for Ed25519")),
        }
    }
}

#[async_trait::async_trait]
impl Signer for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.chain_type {
            ChainType::Evm => self.sign_ecdsa(message).await,
            ChainType::Xrpl => self.sign_der(message).await,
            ChainType::Icon => self.sign_ecdsa(message).await,
            ChainType::Flow => self.sign_p256(message).await,
            ChainType::Soroban => self.sign_ed25519(message).await,
            ChainType::Secret => self.sign_ecdsa(message).await,
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

    fn private_key(&self) -> Option<&[u8]> {
        Some(&self.private_key)
    }
}

fn create_ecdsa_public_key<C>(signing_key: &EcdsaSigningKey<C>, compressed: bool) -> Vec<u8>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    signing_key
        .verifying_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
}

fn is_valid_flow_address(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signer::Signer;
    use base32;
    use k256::sha2::{Digest, Sha512};
    use sha3::Keccak256;

    #[tokio::test]
    async fn test_sign_ecdsa() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Evm, None).unwrap();
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
        let signer = LocalSigner::new(&pk, &ChainType::Xrpl, None).unwrap();
        let message = &Sha512::digest(b"Hello, world!")[..32];
        let signature = hex::encode(signer.sign_der(message).await.unwrap());
        let expected = "304402203a3fcf5aadf9e26bc931fc54a924013413d80fb538c5048fc4e4c8dd2e6c178502202de7b72145515c0d23ed4f2bce9dd26541c26059557a607ccdcfee47d88cd1eb";

        assert_eq!(signature, expected);
    }

    #[tokio::test]
    async fn test_sign_p256_raw_produces_64_bytes() {
        // P-256 test key (32 bytes random)
        let pk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Flow, Some("0x1234567890abcdef")).unwrap();
        let message = [0u8; 32]; // 32-byte prehash
        let signature = signer.sign_p256(&message).await.unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[tokio::test]
    async fn test_sign_ed25519_deterministic() {
        let pk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Soroban, None).unwrap();
        let message = b"deterministic signing test";
        let sig1 = signer.sign_ed25519(message).await.unwrap();
        let sig2 = signer.sign_ed25519(message).await.unwrap();
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_sign_ed25519_produces_valid_signature() {
        // RFC 8037 test vector seed
        let pk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Soroban, None).unwrap();
        let message = b"hello soroban";
        let signature_bytes = signer.sign_ed25519(message).await.unwrap();
        assert_eq!(signature_bytes.len(), 64);

        use ed25519_dalek::{Signature, VerifyingKey};
        let vk_bytes: [u8; 32] = signer.public_key().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let sig_arr: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(message, &sig).unwrap();
    }

    #[test]
    fn test_address_generation_evm() {
        let pk = hex::decode("d430736144cbe3c083b22b8b5975eef970bf04336dda98748bbef1a3e5e5713a")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Evm, None).unwrap();
        assert_eq!(
            signer.address(),
            "0x994df35cc8d6954155ec2d9d3d59b40d0e0bce93"
        );
    }

    #[test]
    fn test_address_generation_xrpl() {
        let pk = hex::decode("D5A397A10DE2C485FA5592FFD86A7B5744BC221E24F71196ACD32EB66B14264C")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Xrpl, None).unwrap();
        assert_eq!(signer.address(), "rpeTutzWtCQbVv9EmwJFQvtebkMw42ujnG");
    }

    #[test]
    fn test_address_generation_flow_uses_override() {
        let pk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        let signer = LocalSigner::new(&pk, &ChainType::Flow, Some("0x1234567890abcdef")).unwrap();
        assert_eq!(signer.address(), "0x1234567890abcdef");
    }

    #[test]
    fn test_flow_missing_address_override_errors() {
        let pk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        assert!(LocalSigner::new(&pk, &ChainType::Flow, None).is_err());
    }

    #[test]
    fn test_address_generation_soroban() {
        let pk = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            "SBH2O4SMUKNXIDBDF33DH2WO2G6K2ITAEE4LF4QRQ4ZOKLTXKTQVXSXH",
        )
        .unwrap();
        let signer = LocalSigner::new(&pk[1..33], &ChainType::Soroban, None).unwrap();
        assert_eq!(
            signer.address(),
            "GAO3EMICCMT746DHGEDA3RQGMIQGGIBW2IUSPT6TACD43BKDAGZIXWWT"
        );
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

    #[test]
    fn test_public_key_to_icon_address() {
        let pk = hex::decode("0409cb1cab6bd46b7b050bf8427850340bc6906b88957d584432f6fc6510688f4a7c01b45e009bd1d700b4486325c915a6d25ba69722c8ded9da0ab76941870e3d")
            .unwrap();
        let address = public_key_to_icon_address(&pk).unwrap();
        let expected = "hx8521060f28fdedcc4e4544ee499008809d4c0322";
        assert_eq!(address, expected);
    }
}
