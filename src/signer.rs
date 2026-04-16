#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "local")]
pub mod local;
pub mod signature;

use anyhow::anyhow;
use k256::EncodedPoint;
use k256::sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use sha3::Sha3_256;

use crate::config::signer::local::ChainType;
use cosmrs::AccountId;

#[async_trait::async_trait]
pub trait Signer: Send + Sync + 'static {
    // TODO: Change to use custom error instead of anyhow.
    // For purpose of development anyhow will be used until other providers are complete
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> &[u8];

    fn address(&self) -> &str;

    fn chain_type(&self) -> &ChainType;
}

pub fn public_key_to_evm_address(public_key: &[u8]) -> anyhow::Result<String> {
    // Check exact length
    if public_key.len() != 65 {
        return Err(anyhow!(
            "Invalid public key length for EVM address. Expected 65 bytes, got {}",
            public_key.len()
        ));
    }

    // Validate uncompressed SEC1 prefix (0x04)
    if public_key[0] != 0x04 {
        return Err(anyhow!(
            "Invalid public key SEC1 prefix for EVM address. Expected 0x04 (uncompressed), got 0x{:02x}",
            public_key[0]
        ));
    }

    let mut hasher = sha3::Keccak256::new();
    // We can now safely skip the first byte because we validated length and prefix
    hasher.update(&public_key[1..]);
    let hash = hasher.finalize();

    // EVM address is the last 20 bytes of the Keccak256 hash
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

pub fn public_key_to_xrpl_address(public_key: &[u8]) -> anyhow::Result<String> {
    let encoded = EncodedPoint::from_bytes(public_key)
        .map_err(|e| anyhow!("Invalid secp256k1 public key: {}", e))?;

    let compressed = encoded.compress();
    let sha256 = Sha256::digest(compressed.as_bytes());
    let account_id = Ripemd160::digest(sha256);

    let mut payload = Vec::with_capacity(1 + account_id.len() + 4);
    payload.push(0x00);
    payload.extend_from_slice(&account_id);

    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);

    // Already correct! Returns Ok(String)
    Ok(bs58::encode(payload)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string())
}

pub fn public_key_to_icon_address(public_key: &[u8]) -> anyhow::Result<String> {
    // Check exact length
    if public_key.len() != 65 {
        return Err(anyhow!(
            "Invalid public key length for Icon address. Expected 65 bytes, got {}",
            public_key.len()
        ));
    }

    // Validate uncompressed SEC1 prefix (0x04)
    if public_key[0] != 0x04 {
        return Err(anyhow!(
            "Invalid public key SEC1 prefix for Icon address. Expected 0x04 (uncompressed), got 0x{:02x}",
            public_key[0]
        ));
    }

    let mut hasher = Sha3_256::new();
    // We can now safely skip the first byte because we validated length and prefix
    hasher.update(&public_key[1..]);
    let hash = hasher.finalize();

    // Icon address is the last 20 bytes of the Sha3_256 hash
    Ok(format!("hx{}", hex::encode(&hash[12..])))
}

pub fn public_key_to_secret_address(public_key: &[u8]) -> anyhow::Result<String> {
    // Cosmos SDK account address for secp256k1 is:
    //   bech32(prefix, ripemd160(sha256(pubkey_bytes)))
    // where pubkey_bytes is the compressed SEC1 encoded pubkey (33 bytes).
    if public_key.len() != 33 {
        return Err(anyhow!(
            "Invalid public key length for Secret address. Expected 33 bytes, got {}",
            public_key.len()
        ));
    }

    // For compressed SEC1 pubkeys, the first byte is 0x02 or 0x03.
    if public_key[0] != 0x02 && public_key[0] != 0x03 {
        return Err(anyhow!(
            "Invalid public key SEC1 prefix for Secret address. Expected 0x02/0x03, got 0x{:02x}",
            public_key[0]
        ));
    }

    let sha256 = Sha256::digest(public_key);
    let account_id = Ripemd160::digest(sha256);
    let acc_id_bytes: &[u8] = account_id.as_slice();
    // Secret Network typically uses the `secret` bech32 prefix.
    let account_id = AccountId::new("secret", acc_id_bytes)
        .map_err(|e| anyhow!("failed to create Secret AccountId: {e}"))?;
    Ok(account_id.to_string())
}
