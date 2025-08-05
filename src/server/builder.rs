use crate::server::verifier::Verifier;
use crate::server::Server;
use crate::signer::signature::ecdsa::EcdsaSignature;
use crate::signer::{EvmSigner, Signer};
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer<EcdsaSignature> + 'static>>,
    price_verifier: Option<Box<dyn Verifier>>,
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

    pub fn with_verifier<V>(&mut self, verifier: V)
    where
        V: Verifier,
    {
        self.price_verifier = Some(Box::new(verifier));
    }

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
            price_verifier: self.price_verifier,
        }
    }
}
