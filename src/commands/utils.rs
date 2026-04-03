use crate::config::Config;
use crate::config::signer::local::ChainType;
use crate::config::signer::local::{DerivationScheme, Encoding, LocalSignerConfig};
use crate::signer::local::LocalSigner;
use alloy_signer_local::MnemonicBuilder;
use alloy_signer_local::coins_bip39::English;
use base64::Engine;
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

pub fn get_config(path: PathBuf) -> anyhow::Result<Config> {
    Ok(toml::de::from_str(&std::fs::read_to_string(&path)?)?)
}

#[cfg(feature = "local")]
pub fn get_local_signers_from_config(
    configs: &[LocalSignerConfig],
) -> anyhow::Result<HashMap<ChainType, Vec<LocalSigner>>> {
    let mut map: HashMap<ChainType, Vec<LocalSigner>> = HashMap::new();

    for config in configs {
        let (chain_type, signer) = match config {
            LocalSignerConfig::PrivateKey {
                env_variable,
                encoding,
                chain_type,
                address,
            } => {
                let pk = env::var(env_variable)?;
                let pkb = match encoding {
                    Encoding::Hex => hex::decode(pk)?,
                    Encoding::Base64 => {
                        let engine = base64::engine::general_purpose::STANDARD;
                        engine.decode(pk)?
                    }
                };
                (
                    chain_type,
                    LocalSigner::new(&pkb, chain_type, address.as_deref())?,
                )
            }
            LocalSignerConfig::Mnemonic {
                env_variable,
                coin_type,
                account,
                index,
                chain_type,
                derivation_scheme,
                address,
            } => {
                let mnemonic = env::var(env_variable)?;
                let scheme = derivation_scheme.clone().unwrap_or_default();
                let pkb = derive_credential_from_mnemonic(
                    mnemonic, *coin_type, *account, *index, scheme,
                )?;
                (
                    chain_type,
                    LocalSigner::new(&pkb, chain_type, address.as_deref())?,
                )
            }
        };

        map.entry(chain_type.clone()).or_default().push(signer);
    }

    Ok(map)
}

#[cfg(feature = "local")]
fn derive_credential_from_mnemonic(
    mnemonic: String,
    coin_type: u32,
    account: u32,
    index: u32,
    scheme: DerivationScheme,
) -> anyhow::Result<Vec<u8>> {
    match scheme {
        DerivationScheme::Slip010 => derive_slip010_ed25519_key(&mnemonic, coin_type, index),
        DerivationScheme::Bip32 => {
            let hd_path = format!("m/44'/{coin_type}'/{account}'/{index}");
            let signer = MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .derivation_path(&hd_path)?
                .build()?;
            Ok(signer.credential().to_bytes().to_vec())
        }
    }
}

/// Derives an Ed25519 private key from a mnemonic using SLIP-0010 at path m/44'/{coin_type}'/{account}'.
/// This is the correct scheme for Stellar/Soroban (SEP-0005).
#[cfg(feature = "local")]
fn derive_slip010_ed25519_key(
    mnemonic_phrase: &str,
    coin_type: u32,
    index: u32,
) -> anyhow::Result<Vec<u8>> {
    // BIP39: mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512)
    let mnemonic: Mnemonic = mnemonic_phrase
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");

    // SLIP-0010 master key: HMAC-SHA512(key="ed25519 seed", data=seed)
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
        .map_err(|e| anyhow::anyhow!("HMAC init error: {e}"))?;
    mac.update(&seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Hardened child derivation for m/44'/{coin_type}'/{account}'
    // Ed25519 SLIP-0010 only supports hardened derivation.
    for component in [44u32, coin_type, index] {
        let hardened = component | 0x8000_0000;
        // data = 0x00 || key || hardened_index (big-endian)
        let mut data = Vec::with_capacity(37);
        data.push(0x00);
        data.extend_from_slice(&key);
        data.extend_from_slice(&hardened.to_be_bytes());

        let mut mac = Hmac::<Sha512>::new_from_slice(&chain_code)
            .map_err(|e| anyhow::anyhow!("HMAC init error: {e}"))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    Ok(key.to_vec())
}
