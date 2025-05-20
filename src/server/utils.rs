use sha3::Digest;

pub fn public_key_to_evm_address(public_key: &[u8]) -> String {
    let hash = sha3::Keccak256::digest(public_key);
    format!("0x{}", hex::encode(&hash[12..]))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_public_key_to_evm_address_1() {
        let pk = hex::decode("04b01ab5a1640da9ad9f9593c9e3d90a68a6a64b9fa4742edb13acb15e93ebee20ae14072003dd69a1eaf060bb74a90e27acd3e66fdb234b5225c665e2a26f52e7").unwrap();
        let address = public_key_to_evm_address(&pk[1..]);
        let expected = "0x29754940a23e3571db50103dd379e1ec15597611";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_2() {
        let pk = hex::decode("0470d624fa6823e50a874d65580961696626059fc2fc7d698813e24550ab51f1e5eb58b15735e50318a1c9f79c2d6b5a5c7fe34b64c99e59c207b0bb7f7c492b83").unwrap();
        let address = public_key_to_evm_address(&pk[1..]);
        let expected = "0x151df313e367d60af962bd1fbd2508cf8da1fed6";
        assert_eq!(address, expected);
    }

    #[test]
    fn test_public_key_to_evm_address_3() {
        let pk = hex::decode("0409cb1cab6bd46b7b050bf8427850340bc6906b88957d584432f6fc6510688f4a7c01b45e009bd1d700b4486325c915a6d25ba69722c8ded9da0ab76941870e3d").unwrap();
        let address = public_key_to_evm_address(&pk[1..]);
        let expected = "0xf9c62d223a203c8160f19be3588e41d9d6e67a59";
        assert_eq!(address, expected);
    }
}
