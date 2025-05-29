use crate::signer::signature::Signature;
use k256::ecdsa;

impl Signature for (ecdsa::Signature, ecdsa::RecoveryId) {
    fn into_vec(self) -> Vec<u8> {
        let (r, s) = self.0.split_bytes();
        let mut sig = Vec::with_capacity(65);
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&s);
        sig.push(self.1.to_byte());
        sig
    }
}
