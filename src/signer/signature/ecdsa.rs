use crate::signer::signature::{RecoveryId, Signature};
use k256::ecdsa;
use k256::ecdsa::signature::SignatureEncoding;

impl Signature for ecdsa::Signature {
    fn into_vec(self) -> Vec<u8> {
        self.to_der().to_vec()
    }
}

impl RecoveryId for ecdsa::RecoveryId {
    fn to_byte(self) -> u8 {
        self.to_byte()
    }
}
