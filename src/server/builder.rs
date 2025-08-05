use crate::server::pre_sign::PreSignHook;
use crate::server::Server;
use crate::signer::signature::ecdsa::EcdsaSignature;
use crate::signer::{EvmSigner, Signer};
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    pre_sign_hooks: Vec<Box<dyn PreSignHook>>,
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

    pub fn with_pre_sign_hook<P>(&mut self, pre_sign_hook: P)
    where
        P: PreSignHook,
    {
        self.pre_sign_hooks.push(Box::new(pre_sign_hook));
    }

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
            pre_sign_hooks: self.pre_sign_hooks,
        }
    }
}
