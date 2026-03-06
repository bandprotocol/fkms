use crate::signer::signature::Signature;
use crate::signer::signature::ecdsa::{DerSignature, EcdsaSignature};
use k256::EncodedPoint;
use k256::sha2::{Digest, Sha256};
use ripemd::Ripemd160;

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

pub trait EvmSigner: Send + Sync + 'static {
    fn evm_address(&self) -> String;
}

pub trait XrplSigner: Send + Sync + 'static {
    fn xrpl_address(&self) -> String;
}

impl<T> EvmSigner for T
where
    T: Signer<EcdsaSignature>,
{
    fn evm_address(&self) -> String {
        public_key_to_evm_address(self.public_key())
    }
}

impl<T> XrplSigner for T
where
    T: Signer<DerSignature>,
{
    fn xrpl_address(&self) -> String {
        public_key_to_xrpl_address(self.public_key())
    }
}

fn public_key_to_evm_address(public_key: &[u8]) -> String {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&public_key[1..]); // Skip the first byte (0x04)
    let hash = hasher.finalize();
    format!("0x{}", hex::encode(&hash[12..]))
}

// This function can be ignored panic because it must not be called after server start
fn public_key_to_xrpl_address(public_key: &[u8]) -> String {
    let encoded = EncodedPoint::from_bytes(public_key).expect("Invalid secp256k1 public key");

    let compressed = encoded.compress();
    let sha256 = Sha256::digest(compressed.as_bytes());
    let account_id = Ripemd160::digest(sha256);

    let mut payload = Vec::with_capacity(1 + account_id.len() + 4);
    payload.push(0x00);
    payload.extend_from_slice(&account_id);

    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);

    bs58::encode(payload)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_public_key_to_evm_address_1() {
        let pk = hex::decode("04b01ab5a1640da9ad9f9593c9e3d90a68a6a64b9fa4742edb13acb15e93ebee20ae14072003dd69a1eaf060bb74a90e27acd3e66fdb234b5225c665e2a26f52e7").unwrap();
        let address = public_key_to_evm_address(&pk);
        let expected = "0x29754940a23e3571db50103dd379e1ec15597611";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_2() {
        let pk = hex::decode("0470d624fa6823e50a874d65580961696626059fc2fc7d698813e24550ab51f1e5eb58b15735e50318a1c9f79c2d6b5a5c7fe34b64c99e59c207b0bb7f7c492b83").unwrap();
        let address = public_key_to_evm_address(&pk);
        let expected = "0x151df313e367d60af962bd1fbd2508cf8da1fed6";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_3() {
        let pk = hex::decode("0409cb1cab6bd46b7b050bf8427850340bc6906b88957d584432f6fc6510688f4a7c01b45e009bd1d700b4486325c915a6d25ba69722c8ded9da0ab76941870e3d").unwrap();
        let address = public_key_to_evm_address(&pk);
        let expected = "0xf9c62d223a203c8160f19be3588e41d9d6e67a59";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_xrpl_address() {
        let pk = hex::decode("02D5A397A10DE2C485FA5592FFD86A7B5744BC221E24F71196ACD32EB66B14264C")
            .unwrap();
        let address = public_key_to_xrpl_address(&pk);
        let expected = "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB";
        assert_eq!(address, expected);
    }
}
