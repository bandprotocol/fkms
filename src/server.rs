use crate::server::pre_sign::PreSignHook;
use crate::signer::Signer;
use crate::signer::signature::ecdsa::{DerSignature, EcdsaSignature};
use crate::verifier::tss::signature::SignatureVerifier;
use std::collections::HashMap;

pub mod builder;
pub mod middleware;
pub mod pre_sign;
pub mod service;

pub struct Server {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    xrpl_signers: HashMap<String, Box<dyn Signer<DerSignature> + 'static>>,
    evm_pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    xrpl_pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    tss_signature_verifier: Option<SignatureVerifier>,
}
