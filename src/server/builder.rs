use crate::server::Server;
use crate::signer::signature::ecdsa::EcdsaSignature;
use crate::signer::{EvmSigner, Signer};
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
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

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
        }
    }
}
