use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    #[serde_as(as = "Hex")]
    pub public_key: [u8; 33],
    pub expired_time: Option<u64>,
}
