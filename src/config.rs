pub mod logging;
mod server;
pub mod signer;

use crate::config::logging::LoggingConfig;
use crate::config::server::ServerConfig;
use crate::config::signer::SignerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub signer_config: SignerConfig,
    pub logging: LoggingConfig,
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|mut path| {
        path.push(".fkms/config.toml");
        path
    })
}
