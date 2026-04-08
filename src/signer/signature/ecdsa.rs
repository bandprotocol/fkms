use crate::signer::signature::Signature;
use k256::ecdsa;

pub type EcdsaSignature = (ecdsa::Signature, ecdsa::RecoveryId);
pub type DerSignature = ecdsa::DerSignature;
pub type P256Signature = p256::ecdsa::Signature;

impl Signature for EcdsaSignature {
    fn into_vec(self) -> Vec<u8> {
        let (r, s) = self.0.split_bytes();
        let mut sig = Vec::with_capacity(65);
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&s);
        sig.push(self.1.to_byte());
        sig
    }
}

impl Signature for DerSignature {
    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Signature for P256Signature {
    fn into_vec(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
