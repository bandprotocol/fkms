use crate::config::tss::group::Group;
use serde::{Deserialize, Serialize};

pub mod group;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TssConfig {
    #[serde(default = "default_enable_verify")]
    pub enable_verify: bool,
    #[serde(default = "default_groups")]
    pub groups: Vec<Group>,
}

fn default_enable_verify() -> bool {
    false
}

fn default_groups() -> Vec<Group> {
    vec![]
}

impl Default for TssConfig {
    fn default() -> Self {
        TssConfig {
            enable_verify: default_enable_verify(),
            groups: default_groups(),
        }
    }
}
