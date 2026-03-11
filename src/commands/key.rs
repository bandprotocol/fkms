use crate::commands::utils::get_config;
use crate::commands::utils::get_local_signers_from_config;
use crate::config::default_config_path;
use crate::config::signer::local::ChainType;
use crate::signer::Signer;
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
        let signer_groups = get_local_signers_from_config(signer_configs)?;
        for (chain_type, signers) in signer_groups {
            for signer in signers {
                println!("{:?} Address: {}", chain_type, signer.address());
            }
        }
    }

    #[cfg(feature = "aws")]
    {
        // TODO: implement
    }

    Ok(())
}
