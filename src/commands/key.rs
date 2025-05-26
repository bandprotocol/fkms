use crate::commands::utils::{get_config, get_local_signers_from_config};
use crate::signer::Signer;
use crate::util::evm_address_from_pub_key;
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
        /// Path to the config file. Defaults to $HOME/.fkms/config.toml
        #[arg(short, long, global = true)]
        path: Option<PathBuf>,
    },
}

impl KeyCommand {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            KeyCommand::List { path } => list_keys(path),
        }
    }
}

fn list_keys(path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = get_config(path)?;

    // only run this if the local feature is enabled
    #[cfg(feature = "local")]
    {
        let signer_configs = &config.signer_config.local_signer_configs;
        let local_signers = get_local_signers_from_config(signer_configs)?;
        for local_signer in local_signers {
            let pk = local_signer.public_key();
            println!("Public Key: {}", hex::encode(pk));
            println!("Address: {}", evm_address_from_pub_key(pk));
        }
    }

    #[cfg(feature = "aws")]
    {}

    Ok(())
}
