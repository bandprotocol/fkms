use crate::config::Config;
use crate::config::signer::local::ChainType;
use crate::config::signer::local::{Encoding, LocalSignerConfig};
use crate::signer::local::LocalSigner;
use alloy_signer_local::MnemonicBuilder;
use alloy_signer_local::coins_bip39::English;
use base64::Engine;
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
                address,
            } => {
                let mnemonic = env::var(env_variable)?;
                let pkb = derive_credential_from_mnemonic(mnemonic, *coin_type, *account, *index)?;
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
) -> anyhow::Result<Vec<u8>> {
    let hd_path = format!("m/44'/{coin_type}'/{account}'/0/{index}");

    let signer = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path(&hd_path)?
        .build()?;

    Ok(signer.credential().to_bytes().to_vec())
}
