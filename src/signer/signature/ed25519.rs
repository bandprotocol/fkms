use crate::signer::signature::Signature;

pub type Ed25519Signature = ed25519_dalek::Signature;

impl Signature for Ed25519Signature {
    fn into_vec(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
