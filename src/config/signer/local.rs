use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalSignerConfig {
    Env {
        env_variable: String,
        encoding: Encoding,
    },
    File {
        path: PathBuf,
        encoding: Encoding,
    },
    PrivateKey {
        private_key: String,
        encoding: Encoding,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Hex,
    Base64,
}
