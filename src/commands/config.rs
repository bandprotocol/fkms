use crate::config::{Config, default_config_path};
use anyhow::anyhow;
use clap::{Args, Subcommand};
use std::fs::{create_dir_all, write};
use std::path::PathBuf;

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    Init {
        /// Path to the config file.
        #[arg(short, long, default_value = default_config_path().into_os_string())]
        path: PathBuf,

        /// Force overwrite of an existing config file
        #[arg(short, long = "override")]
        override_: bool,
    },

    Validate {
        /// Path to the config file.
        #[arg(short, long, default_value = default_config_path().into_os_string())]
        path: PathBuf,
    },
}

impl ConfigCommand {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            ConfigCommand::Init { path, override_ } => initialize_config(path, override_),
            ConfigCommand::Validate { path } => validate_config(path),
        }
    }
}

fn initialize_config(path: PathBuf, override_: bool) -> anyhow::Result<()> {
    if path.exists() && !override_ {
        return Err(anyhow!(
            "Config file already exists. Use --override to overwrite."
        ));
    }

    // Create the config directory if it doesn't exist
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    // Write default config to file
    let config = Config::default();
    write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn validate_config(path: PathBuf) -> anyhow::Result<()> {
    if path.exists() {
        let _: Config = toml::de::from_str(&std::fs::read_to_string(path)?)?;
        println!("Config file is valid");
        Ok(())
    } else {
        Err(anyhow!(
            "Config file does not exist. Please run 'config init' to create one."
        ))
    }
}
