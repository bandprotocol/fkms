use crate::signer::signature::Signature;
use k256::ecdsa;
use k256::ecdsa::signature::SignatureEncoding;

impl Signature for (ecdsa::Signature, ecdsa::RecoveryId) {
    fn into_vec(self) -> Vec<u8> {
        let mut sig = self.0.to_der().to_vec();
        sig.push(self.1.to_byte());
        sig
    }
}
