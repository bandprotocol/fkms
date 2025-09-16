use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalSignerConfig {
    PrivateKey {
        env_variable: String,
        encoding: Encoding,
    },
    Mnemonic {
        env_variable: String,
        coin_type: u32,
        account: u32,
        index: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Hex,
    Base64,
}
