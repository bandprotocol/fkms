use crate::commands::utils::{
    get_config, get_evm_local_signers_from_config, get_xrpl_local_signers_from_config,
};
use crate::config::default_config_path;
use crate::signer::{EvmSigner, XrplSigner};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// List all keys
    List {
        /// Path to the config file.
        #[arg(short, long, default_value = default_config_path().into_os_string())]
        path: PathBuf,
    },
}

impl KeyCommand {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            KeyCommand::List { path } => list_keys(path),
        }
    }
}

fn list_keys(path: PathBuf) -> anyhow::Result<()> {
    let config = get_config(path)?;

    // only run this if the local feature is enabled
    #[cfg(feature = "local")]
    {
        let signer_configs = &config.signer_config.local_signer_configs;
        let evm_signers = get_evm_local_signers_from_config(signer_configs)?;
        for local_signer in evm_signers {
            println!("--- EVM Signer ---");
            println!(
                "Public Key: {}",
                hex::encode(local_signer.uncompressed_public_key())
            );
            println!("Address: {}", local_signer.evm_address());
        }

        let xrpl_signers = get_xrpl_local_signers_from_config(signer_configs)?;
        for local_signer in xrpl_signers {
            println!("--- XRPL Signer ---");
            println!(
                "Public Key: {}",
                hex::encode(local_signer.compressed_public_key())
            );
            println!("XRPL Address: {}", local_signer.xrpl_address());
        }
    }

    #[cfg(feature = "aws")]
    {
        // TODO: implement
    }

    Ok(())
}
