use crate::config::Config;
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
            } => {
                let pk = env::var(env_variable)?;
                let pkb = match encoding {
                    Encoding::Hex => hex::decode(pk)?,
                    Encoding::Base64 => {
                        let engine = base64::engine::general_purpose::STANDARD;
                        engine.decode(pk)?
                    }
                };
                signers.push(LocalSigner::new(&pkb)?);
            }
            LocalSignerConfig::Mnemonic {
                env_variable,
                coin_type,
                account,
                index,
            } => {
                if *coin_type == 60 {
                    let mnemonic = env::var(env_variable)?;

                    let hd_path = format!("m/44'/{}'/{}'/0/{}", coin_type, account, index);

                    let signer = MnemonicBuilder::<English>::default()
                        .phrase(mnemonic)
                        .derivation_path(hd_path)?
                        .build()?;

                    let pkb = signer.credential().to_bytes().to_vec();
                    signers.push(LocalSigner::new(&pkb)?);
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

            let hd_path = format!("m/44'/{}'/{}'/0/{}", coin_type, account, index);

            let signer = MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .derivation_path(hd_path)?
                .build()?;

            let pkb = signer.credential().to_bytes().to_vec();
            signers.push(LocalSigner::new(&pkb)?);
        }
    }
    Ok(signers)
}
