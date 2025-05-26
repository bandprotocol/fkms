use crate::server::Server;
use crate::server::utils::public_key_to_evm_address;
use crate::signer::Signer;
use k256::ecdsa;
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn Signer<ecdsa::Signature> + 'static>>,
}

impl ServerBuilder {
    pub fn with_evm_signer<T>(mut self, signer: T) -> Self
    where
        T: Signer<ecdsa::Signature>,
    {
        let address = public_key_to_evm_address(signer.public_key());
        self.evm_signers.insert(
            address,
            Box::new(signer) as Box<dyn Signer<ecdsa::Signature>>,
        );
        self
    }

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
        }
    }
}
