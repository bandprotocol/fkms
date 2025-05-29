use crate::signer::Signer;
use k256::ecdsa;
use std::collections::HashMap;

pub mod builder;
pub mod evm;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<(ecdsa::Signature, ecdsa::RecoveryId)> + 'static>>,
}
