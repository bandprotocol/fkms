#[cfg(feature = "aws")]
use crate::config::signer::aws::AwsSignerConfig;
#[cfg(feature = "local")]
use crate::config::signer::local::LocalSignerConfig;
use serde::{Deserialize, Serialize};

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "local")]
pub mod local;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignerConfig {
    #[cfg(feature = "local")]
    pub local_signer_configs: Vec<LocalSignerConfig>,
    #[cfg(feature = "aws")]
    pub aws: Vec<AwsSignerConfig>,
}
