use crate::server::Server;
use crate::server::pre_sign::PreSignHook;
use crate::signer::signature::ecdsa::{DerSignature, EcdsaSignature};
use crate::signer::{EvmSigner, Signer, XrplSigner};
use crate::verifier::tss::signature::SignatureVerifier;
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    xrpl_signers: HashMap<String, Box<dyn Signer<DerSignature> + 'static>>,
    evm_pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    xrpl_pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
    tss_signature_verifier: SignatureVerifier,
}

impl ServerBuilder {
    pub fn with_evm_signer<T>(&mut self, signer: T)
    where
        T: Signer<EcdsaSignature> + EvmSigner,
    {
        self.evm_signers.insert(
            signer.evm_address(),
            Box::new(signer) as Box<dyn Signer<EcdsaSignature> + 'static>,
        );
    }

    pub fn with_xrpl_signer<T>(&mut self, signer: T)
    where
        T: Signer<DerSignature> + XrplSigner,
    {
        self.xrpl_signers.insert(
            signer.xrpl_address(),
            Box::new(signer) as Box<dyn Signer<DerSignature> + 'static>,
        );
    }

    pub fn with_evm_pre_sign_hook<P>(&mut self, pre_sign_hook: P)
    where
        P: PreSignHook,
    {
        self.evm_pre_sign_hooks.push(Box::new(pre_sign_hook));
    }

    pub fn with_xrpl_pre_sign_hook<P>(&mut self, pre_sign_hook: P)
    where
        P: PreSignHook,
    {
        self.xrpl_pre_sign_hooks.push(Box::new(pre_sign_hook));
    }

    pub fn with_tss_signture_verifier(&mut self, verifier: SignatureVerifier) {
        self.tss_signature_verifier = verifier;
    }

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
            xrpl_signers: self.xrpl_signers,
            evm_pre_sign_hooks: self.evm_pre_sign_hooks,
            xrpl_pre_sign_hooks: self.xrpl_pre_sign_hooks,
            tss_signature_verifier: self.tss_signature_verifier,
        }
    }
}
