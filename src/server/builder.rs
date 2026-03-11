use crate::server::Server;
use crate::server::pre_sign::PreSignHook;
use crate::signer::Signer;
use crate::verifier::tss::signature::SignatureVerifier;
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer + 'static>>,
    xrpl_signers: HashMap<String, Box<dyn Signer + 'static>>,
    pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    tss_signature_verifier: Option<SignatureVerifier>,
}

impl ServerBuilder {
    pub fn with_evm_signer<T>(&mut self, signer: T)
    where
        T: Signer,
    {
        self.evm_signers.insert(
            signer.address().into(),
            Box::new(signer) as Box<dyn Signer + 'static>,
        );
    }

    pub fn with_xrpl_signer<T>(&mut self, signer: T)
    where
        T: Signer,
    {
        self.xrpl_signers.insert(
            signer.address().into(),
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
            evm_signers: self.evm_signers,
            xrpl_signers: self.xrpl_signers,
            pre_sign_hooks: self.pre_sign_hooks,
            tss_signature_verifier: self.tss_signature_verifier,
        }
    }
}
