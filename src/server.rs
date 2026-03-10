use crate::server::pre_sign::PreSignHook;
use crate::signer::Signer;
use crate::verifier::tss::signature::SignatureVerifier;
use std::collections::HashMap;

pub mod builder;
pub mod middleware;
pub mod pre_sign;
pub mod service;

pub struct Server {
    signers: HashMap<String, Box<dyn Signer>>,
    pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    tss_signature_verifier: Option<SignatureVerifier>,
}
