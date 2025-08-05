use crate::server::verifier::Verifier;
use crate::signer::Signer;
use crate::signer::signature::ecdsa::EcdsaSignature;
use std::collections::HashMap;

pub mod builder;
pub mod evm;
pub mod middleware;
pub mod verifier;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    price_verifier: Option<Box<dyn Verifier + Send + Sync + 'static>>,
}
