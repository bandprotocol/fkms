pub mod ecdsa;

pub trait Signature {
    fn into_vec(self) -> Vec<u8>;
}

pub trait RecoveryId {
    fn to_byte(self) -> u8;
}
