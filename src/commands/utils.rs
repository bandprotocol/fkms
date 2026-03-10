use crate::config::Config;
use crate::config::signer::local::ChainType;
use crate::config::signer::local::{Encoding, LocalSignerConfig};
use crate::signer::local::LocalSigner;
use alloy_signer_local::MnemonicBuilder;
use alloy_signer_local::coins_bip39::English;
use base64::Engine;
use std::env;
use std::path::PathBuf;

pub fn get_config(path: PathBuf) -> anyhow::Result<Config> {
    Ok(toml::de::from_str(&std::fs::read_to_string(&path)?)?)
}

#[cfg(feature = "local")]
pub fn get_evm_local_signers_from_config(
    configs: &[LocalSignerConfig],
) -> anyhow::Result<Vec<LocalSigner>> {
    let mut signers = Vec::new();
    for config in configs {
        match config {
            LocalSignerConfig::PrivateKey {
                env_variable,
                encoding,
                chain_type,
            } => {
                if chain_type == &ChainType::Evm {
                    let pk = env::var(env_variable)?;
                    let pkb = match encoding {
                        Encoding::Hex => hex::decode(pk)?,
                        Encoding::Base64 => {
                            let engine = base64::engine::general_purpose::STANDARD;
                            engine.decode(pk)?
                        }
                    };
                    signers.push(LocalSigner::new(&pkb, false)?);
                }
            }
            LocalSignerConfig::Mnemonic {
                env_variable,
                coin_type,
                account,
                index,
            } => {
                if *coin_type == 60 {
                    let mnemonic = env::var(env_variable)?;
                    let pkb =
                        derive_credential_from_mnemonic(mnemonic, *coin_type, *account, *index)?;
                    signers.push(LocalSigner::new(&pkb, false)?);
                }
            }
        }
    }
    Ok(signers)
}

#[cfg(feature = "local")]
pub fn get_xrpl_local_signers_from_config(
    configs: &[LocalSignerConfig],
) -> anyhow::Result<Vec<LocalSigner>> {
    let mut signers = Vec::new();
    for config in configs {
        if let LocalSignerConfig::Mnemonic {
            env_variable,
            coin_type,
            account,
            index,
        } = config
            && *coin_type == 144
        {
            let mnemonic = env::var(env_variable)?;
            let pkb = derive_credential_from_mnemonic(mnemonic, *coin_type, *account, *index)?;
            signers.push(LocalSigner::new(&pkb, true)?);
        }
    }
    Ok(signers)
}

#[cfg(feature = "local")]
fn derive_credential_from_mnemonic(
    mnemonic: String,
    coin_type: u32,
    account: u32,
    index: u32,
) -> anyhow::Result<Vec<u8>> {
    let hd_path = format!("m/44'/{}'/{}'/0/{}", coin_type, account, index);

    let signer = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path(&hd_path)?
        .build()?;

    Ok(signer.credential().to_bytes().to_vec())
}
