use crate::config::signer::local::ChainType;
use crate::server::Server;
use crate::server::pre_sign::PreSignHook;
use crate::signer::Signer;
use crate::verifier::tss::signature::SignatureVerifier;
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    signers: HashMap<(ChainType, String), Box<dyn Signer + 'static>>,
    pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    tss_signature_verifier: Option<SignatureVerifier>,
}

impl ServerBuilder {
    pub fn with_signer<T>(&mut self, signer: T)
    where
        T: Signer,
    {
        self.signers.insert(
            (signer.chain_type().clone(), signer.address().into()),
            Box::new(signer) as Box<dyn Signer + 'static>,
        );
    }

    pub fn with_pre_sign_hook<P>(&mut self, pre_sign_hook: P)
    where
        P: PreSignHook,
    {
        self.pre_sign_hooks.push(Box::new(pre_sign_hook));
    }

    pub fn with_tss_signature_verifier(&mut self, verifier: SignatureVerifier) {
        self.tss_signature_verifier = Some(verifier);
    }

    pub fn build(self) -> Server {
        Server {
            signers: self.signers,
            pre_sign_hooks: self.pre_sign_hooks,
            tss_signature_verifier: self.tss_signature_verifier,
        }
    }
}
