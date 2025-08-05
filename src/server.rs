use crate::server::pre_sign::PreSignHook;
use crate::signer::Signer;
use crate::signer::signature::ecdsa::EcdsaSignature;
use std::collections::HashMap;

pub mod builder;
pub mod evm;
pub mod middleware;
pub mod pre_sign;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
}
