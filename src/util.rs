use sha3::Digest;

pub fn evm_address_from_pub_key(pub_key: &[u8]) -> String {
    // Keccak256 hash the public key
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&pub_key[1..]); // Skip the first byte (0x04)
    let hash = hasher.finalize().to_vec();
    format!("0x{}", hex::encode(&hash[12..]))
}
