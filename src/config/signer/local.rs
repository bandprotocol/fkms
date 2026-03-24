use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalSignerConfig {
    PrivateKey {
        env_variable: String,
        encoding: Encoding,
        chain_type: ChainType,
        #[serde(default)]
        address_override: Option<String>,
    },
    Mnemonic {
        env_variable: String,
        coin_type: u32,
        account: u32,
        index: u32,
        chain_type: ChainType,
        #[serde(default)]
        address_override: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Hex,
    Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    Evm,
    Xrpl,
    Icon,
     Flow,
}
