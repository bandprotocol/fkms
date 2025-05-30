use crate::signer::Signer;
use k256::ecdsa;
use std::collections::HashMap;
use crate::signer::signature::ecdsa::EcdsaSignature;

pub mod builder;
pub mod evm;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
}
