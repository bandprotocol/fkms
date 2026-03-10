use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; 33],
    pub expired_time: u64,
}
