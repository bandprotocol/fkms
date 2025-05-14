use crate::signer::signature::Signature;
use k256::ecdsa;
use k256::ecdsa::signature::SignatureEncoding;

impl Signature for ecdsa::Signature {
    fn into_vec(self) -> Vec<u8> {
        self.to_der().to_vec()
    }
}
