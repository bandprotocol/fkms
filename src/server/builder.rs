use crate::server::Server;
use crate::server::utils::public_key_to_evm_address;
use crate::signer::provider::SigningProvider;
use k256::ecdsa;
use std::collections::HashMap;

#[derive(Default)]
pub struct ServerBuilder {
    evm_signers: HashMap<String, Box<dyn SigningProvider<ecdsa::Signature> + 'static>>,
}

impl ServerBuilder {
    pub fn with_evm_signer<T>(mut self, signer: T) -> anyhow::Result<Self>
    where
        T: SigningProvider<ecdsa::Signature>,
    {
        let address = public_key_to_evm_address(signer.public_key());
        self.evm_signers.insert(
            address,
            Box::new(signer) as Box<dyn SigningProvider<ecdsa::Signature>>,
        );
        Ok(self)
    }

    pub fn build(self) -> Server {
        Server {
            evm_signers: self.evm_signers,
        }
    }
}
