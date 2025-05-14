use crate::signer::provider::SigningProvider;
use k256::ecdsa;
use std::collections::HashMap;

mod builder;
pub mod evm;
mod utils;

pub use builder::ServerBuilder;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn SigningProvider<ecdsa::Signature> + 'static>>,
}
