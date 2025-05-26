use crate::commands::config::ConfigArgs;
use crate::commands::key::KeyArgs;
use crate::commands::start::start;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub(crate) mod config;
pub(crate) mod key;
pub(crate) mod start;
pub(crate) mod utils;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Configuration command
    Config(ConfigArgs),
    Key(KeyArgs),
    Start {
        #[arg(short, long, global = true)]
        path: Option<PathBuf>,
    },
}

impl Command {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Command::Config(config_args) => config_args.command.run(),
            Command::Key(key_args) => key_args.command.run(),
            Command::Start { path } => start(path).await,
        }
    }
}
