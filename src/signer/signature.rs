pub mod ecdsa;
pub mod ed25519;

pub trait Signature {
    fn into_vec(self) -> Vec<u8>;
}
