use crate::signer::Signer;
use crate::signer::signature::ecdsa::EcdsaSignature;
use std::collections::HashMap;

pub mod builder;
pub mod evm;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
}
