pub mod ecdsa;

pub trait Signature {
    fn into_vec(self) -> Vec<u8>;
}
