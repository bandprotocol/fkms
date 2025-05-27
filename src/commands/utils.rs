use crate::config::Config;
use crate::config::signer::local::LocalSignerConfig::PrivateKey;
use crate::config::signer::local::{Encoding, LocalSignerConfig};
use crate::signer::local::LocalSigner;
use base64::Engine;
use std::env;
use std::path::PathBuf;

pub fn get_config(path: PathBuf) -> anyhow::Result<Config> {
    Ok(toml::de::from_str(&std::fs::read_to_string(&path)?)?)
}

#[cfg(feature = "local")]
pub fn get_local_signers_from_config(
    configs: &[LocalSignerConfig],
) -> anyhow::Result<Vec<LocalSigner>> {
    let signers = configs
        .iter()
        .map(|config| {
            let (pk, encoding) = match config {
                LocalSignerConfig::Env {
                    env_variable,
                    encoding,
                } => {
                    let pk = env::var(env_variable)?;
                    (pk, encoding)
                }
                LocalSignerConfig::File { path, encoding } => {
                    let pk = std::fs::read_to_string(path)?;
                    (pk, encoding)
                }
                PrivateKey {
                    private_key,
                    encoding,
                } => (private_key.clone(), encoding),
            };
            let pkb = match encoding {
                Encoding::Hex => hex::decode(pk)?,
                Encoding::Base64 => {
                    let engine = base64::engine::general_purpose::STANDARD;
                    engine.decode(pk)?
                }
            };
            Ok(LocalSigner::new(&pkb)?)
        })
        .collect::<anyhow::Result<Vec<LocalSigner>>>()?;

    Ok(signers)
}
