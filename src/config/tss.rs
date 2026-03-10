use crate::config::tss::group::Group;
use serde::{Deserialize, Serialize};

pub mod group;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TssConfig {
    pub enable_verify: bool,
    pub groups: Vec<Group>,
}
