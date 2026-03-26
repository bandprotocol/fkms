use anyhow::anyhow;
use k256::sha2::{Digest, Sha256};

/// Builds the unsigned Stellar Transaction XDR for a Soroban contract invocation
/// that relays price data (signals) on-chain.
///
/// The transaction invokes the `relay` function on `contract_address` with the
/// provided signals, resolve_time, and request_id from the tunnel packet.
///
/// Returns the raw Transaction XDR bytes (not an envelope).
pub fn build_unsigned_tx(
    source_account: &str,
    contract_address: &str,
    fee: u32,
    sequence: u64,
    signals: &[(String, u64)],
    resolve_time: u64,
    request_id: u64,
) -> anyhow::Result<Vec<u8>> {
    let source_key = decode_stellar_address(source_account)?;
    let contract_hash = decode_stellar_contract_address(contract_address)?;

    let mut tx = Vec::new();

    // SourceAccount: MuxedAccount (type KEY_TYPE_ED25519 = 0)
    tx.extend_from_slice(&0u32.to_be_bytes()); // KEY_TYPE_ED25519
    tx.extend_from_slice(&source_key);

    // Fee: uint32
    tx.extend_from_slice(&fee.to_be_bytes());

    // SeqNum: SequenceNumber (int64)
    tx.extend_from_slice(&sequence.to_be_bytes());

    // Cond: Preconditions (type PRECOND_NONE = 0)
    tx.extend_from_slice(&0u32.to_be_bytes());

    // Memo: Memo (type MEMO_NONE = 0)
    tx.extend_from_slice(&0u32.to_be_bytes());

    // Operations: array of 1 operation
    tx.extend_from_slice(&1u32.to_be_bytes());

    // Operation.sourceAccount: optional (absent = 0)
    tx.extend_from_slice(&0u32.to_be_bytes());

    // Operation.body: OperationType INVOKE_HOST_FUNCTION = 24
    tx.extend_from_slice(&24u32.to_be_bytes());

    // InvokeHostFunctionOp.hostFunction: HOST_FUNCTION_TYPE_INVOKE_CONTRACT = 0
    tx.extend_from_slice(&0u32.to_be_bytes());

    // InvokeContractArgs: contractAddress (SC_ADDRESS_TYPE_CONTRACT = 1) + functionName + args
    // contractAddress
    tx.extend_from_slice(&1u32.to_be_bytes()); // SC_ADDRESS_TYPE_CONTRACT
    tx.extend_from_slice(&contract_hash);

    // functionName: "relay" as SCSymbol (XDR variable-length string)
    let func_name = b"relay";
    tx.extend_from_slice(&(func_name.len() as u32).to_be_bytes());
    tx.extend_from_slice(func_name);
    // XDR padding to 4-byte boundary
    let padding = (4 - (func_name.len() % 4)) % 4;
    tx.extend_from_slice(&vec![0u8; padding]);

    // args: array of 3 SCVal arguments
    tx.extend_from_slice(&3u32.to_be_bytes());

    // arg[0]: signals as SCVal Map<Symbol, U64>
    encode_signals_map(&mut tx, signals);

    // arg[1]: resolve_time as SCVal U64
    encode_sc_val_u64(&mut tx, resolve_time);

    // arg[2]: request_id as SCVal U64
    encode_sc_val_u64(&mut tx, request_id);

    // auth: array of 0 SorobanAuthorizationEntry
    tx.extend_from_slice(&0u32.to_be_bytes());

    // Ext: TransactionExt (type 0 = no extra)
    tx.extend_from_slice(&0u32.to_be_bytes());

    Ok(tx)
}

/// Computes the Stellar transaction hash used as the Ed25519 signing payload.
///
/// The hash is computed as SHA-256(network_id || envelope_type_tx || unsigned_tx_xdr),
/// where network_id = SHA-256(network_passphrase) and envelope_type_tx is the
/// big-endian 32-bit encoding of ENVELOPE_TYPE_TX (2).
pub fn compute_tx_hash(network_passphrase: &str, unsigned_tx: &[u8]) -> Vec<u8> {
    let network_id = Sha256::digest(network_passphrase.as_bytes());
    // ENVELOPE_TYPE_TX = 2 (XDR big-endian int32)
    let envelope_type_tx: [u8; 4] = [0, 0, 0, 2];

    let mut hasher = Sha256::new();
    hasher.update(network_id);
    hasher.update(envelope_type_tx);
    hasher.update(unsigned_tx);
    hasher.finalize().to_vec()
}

/// Encodes a signed Stellar TransactionEnvelope in XDR format, ready for broadcast.
///
/// Wraps the unsigned transaction with the Ed25519 signature as a
/// `TransactionV1Envelope` (ENVELOPE_TYPE_TX = 2):
///   [envelope_type(4)] [unsigned_tx] [sig_count(4)] [hint(4)] [sig_len(4)] [signature(64)]
pub fn encode_signed_envelope(
    unsigned_tx: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if public_key.len() != 32 {
        return Err(anyhow!(
            "Ed25519 public key must be 32 bytes, got {}",
            public_key.len()
        ));
    }
    if signature.len() != 64 {
        return Err(anyhow!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        ));
    }

    let mut envelope = Vec::new();

    // ENVELOPE_TYPE_TX = 2 (XDR union discriminant)
    envelope.extend_from_slice(&2u32.to_be_bytes());

    // Transaction XDR body
    envelope.extend_from_slice(unsigned_tx);

    // DecoratedSignature array: length = 1
    envelope.extend_from_slice(&1u32.to_be_bytes());

    // SignatureHint: last 4 bytes of the public key
    envelope.extend_from_slice(&public_key[28..32]);

    // Signature: XDR variable-length opaque (4-byte length prefix + data)
    envelope.extend_from_slice(&64u32.to_be_bytes());
    envelope.extend_from_slice(signature);

    Ok(envelope)
}

/// Decodes a Stellar G... (ED25519) address to the 32-byte public key.
fn decode_stellar_address(address: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = stellar_base32_decode(address)?;
    // Expected: 1 byte version + 32 bytes key + 2 bytes checksum = 35 bytes
    if decoded.len() != 35 {
        return Err(anyhow!(
            "Invalid Stellar address length: expected 35 decoded bytes, got {}",
            decoded.len()
        ));
    }
    // Version byte for ED25519 public key: 6 << 3 = 48
    if decoded[0] != 48 {
        return Err(anyhow!(
            "Invalid Stellar address version byte: expected 48 (G...), got {}",
            decoded[0]
        ));
    }

    // Verify checksum
    let expected_checksum = stellar_crc16_xmodem(&decoded[..33]);
    let actual_checksum = u16::from_le_bytes([decoded[33], decoded[34]]);
    if expected_checksum != actual_checksum {
        return Err(anyhow!("Invalid Stellar address checksum"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[1..33]);
    Ok(key)
}

/// Decodes a Stellar C... (contract) address to the 32-byte contract hash.
fn decode_stellar_contract_address(address: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = stellar_base32_decode(address)?;
    // Expected: 1 byte version + 32 bytes hash + 2 bytes checksum = 35 bytes
    if decoded.len() != 35 {
        return Err(anyhow!(
            "Invalid Stellar contract address length: expected 35 decoded bytes, got {}",
            decoded.len()
        ));
    }
    // Version byte for Contract: 2 << 3 = 16
    if decoded[0] != 16 {
        return Err(anyhow!(
            "Invalid Stellar contract address version byte: expected 16 (C...), got {}",
            decoded[0]
        ));
    }

    // Verify checksum
    let expected_checksum = stellar_crc16_xmodem(&decoded[..33]);
    let actual_checksum = u16::from_le_bytes([decoded[33], decoded[34]]);
    if expected_checksum != actual_checksum {
        return Err(anyhow!("Invalid Stellar contract address checksum"));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&decoded[1..33]);
    Ok(hash)
}

/// Encodes an SCVal representing a Map<Symbol, U64> of signals.
fn encode_signals_map(buf: &mut Vec<u8>, signals: &[(String, u64)]) {
    // SCV_MAP = 14
    buf.extend_from_slice(&14u32.to_be_bytes());
    // Optional present (1 = Some)
    buf.extend_from_slice(&1u32.to_be_bytes());
    // Map length
    buf.extend_from_slice(&(signals.len() as u32).to_be_bytes());

    for (symbol, price) in signals {
        // Key: SCV_SYMBOL = 15
        buf.extend_from_slice(&15u32.to_be_bytes());
        let sym_bytes = symbol.as_bytes();
        buf.extend_from_slice(&(sym_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(sym_bytes);
        // XDR padding
        let padding = (4 - (sym_bytes.len() % 4)) % 4;
        buf.extend_from_slice(&vec![0u8; padding]);

        // Value: SCV_U64 = 5
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&price.to_be_bytes());
    }
}

/// Encodes an SCVal U64 value.
fn encode_sc_val_u64(buf: &mut Vec<u8>, value: u64) {
    // SCV_U64 = 5
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.extend_from_slice(&value.to_be_bytes());
}

fn stellar_crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn stellar_base32_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;
    let mut result = Vec::new();

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| anyhow!("Invalid base32 character: {}", ch))?;
        buffer = (buffer << 5) | val as u64;
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            result.push(((buffer >> bits_in_buffer) & 0xFF) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tx_hash_deterministic() {
        let network_passphrase = "Test SDF Network ; September 2015";
        let unsigned_tx = b"test transaction data";

        let hash = compute_tx_hash(network_passphrase, unsigned_tx);
        assert_eq!(hash.len(), 32);

        // Verify deterministic
        let hash2 = compute_tx_hash(network_passphrase, unsigned_tx);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_tx_hash_different_passphrase() {
        let unsigned_tx = b"test transaction data";

        let hash_test = compute_tx_hash("Test SDF Network ; September 2015", unsigned_tx);
        let hash_public = compute_tx_hash(
            "Public Global Stellar Network ; September 2015",
            unsigned_tx,
        );

        assert_ne!(hash_test, hash_public);
    }

    #[test]
    fn test_compute_tx_hash_different_tx() {
        let network_passphrase = "Test SDF Network ; September 2015";

        let hash1 = compute_tx_hash(network_passphrase, b"tx1");
        let hash2 = compute_tx_hash(network_passphrase, b"tx2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_encode_signed_envelope_structure() {
        let unsigned_tx = vec![0xAA; 48]; // mock 48-byte tx
        let public_key = vec![0xBB; 32];
        let signature = vec![0xCC; 64];

        let envelope = encode_signed_envelope(&unsigned_tx, &public_key, &signature).unwrap();

        // envelope_type(4) + tx(48) + sig_count(4) + hint(4) + sig_len(4) + sig(64) = 128
        assert_eq!(envelope.len(), 128);

        // Check envelope type = 2
        assert_eq!(&envelope[0..4], &[0, 0, 0, 2]);

        // Check unsigned tx body
        assert_eq!(&envelope[4..52], &unsigned_tx[..]);

        // Check signature count = 1
        assert_eq!(&envelope[52..56], &[0, 0, 0, 1]);

        // Check hint = last 4 bytes of public key
        assert_eq!(&envelope[56..60], &[0xBB, 0xBB, 0xBB, 0xBB]);

        // Check signature length = 64
        assert_eq!(&envelope[60..64], &[0, 0, 0, 64]);

        // Check signature
        assert_eq!(&envelope[64..128], &signature[..]);
    }

    #[test]
    fn test_encode_signed_envelope_invalid_pubkey() {
        let result = encode_signed_envelope(&[0; 48], &[0; 31], &[0; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_signed_envelope_invalid_signature() {
        let result = encode_signed_envelope(&[0; 48], &[0; 32], &[0; 63]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_stellar_address_roundtrip() {
        // Use a well-known test address: GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7
        // This is a valid Stellar public key address
        let key = [0u8; 32]; // zero key for testing
        // Build a valid G... address from the zero key
        let mut payload = Vec::with_capacity(35);
        payload.push(6 << 3); // version byte for ED25519
        payload.extend_from_slice(&key);
        let checksum = stellar_crc16_xmodem(&payload);
        payload.extend_from_slice(&checksum.to_le_bytes());

        let address = stellar_base32_encode(&payload);
        let decoded = decode_stellar_address(&address).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_decode_stellar_contract_address_roundtrip() {
        let hash = [0xABu8; 32];
        let mut payload = Vec::with_capacity(35);
        payload.push(2 << 3); // version byte for Contract
        payload.extend_from_slice(&hash);
        let checksum = stellar_crc16_xmodem(&payload);
        payload.extend_from_slice(&checksum.to_le_bytes());

        let address = stellar_base32_encode(&payload);
        let decoded = decode_stellar_contract_address(&address).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_build_unsigned_tx_produces_output() {
        // Build valid test addresses
        let source_key = [0u8; 32];
        let source_address = build_test_stellar_address(6 << 3, &source_key);

        let contract_hash = [0xABu8; 32];
        let contract_address = build_test_stellar_address(2 << 3, &contract_hash);

        let signals = vec![
            ("CS:BTC-USD".to_string(), 67758920310332u64),
            ("CS:ETH-USD".to_string(), 3500000000000u64),
        ];

        let tx = build_unsigned_tx(
            &source_address,
            &contract_address,
            100,
            42,
            &signals,
            1700000000,
            99,
        )
        .unwrap();

        assert!(!tx.is_empty());
        // Verify the tx starts with source account (KEY_TYPE_ED25519 = 0 + 32 bytes key)
        assert_eq!(&tx[0..4], &[0, 0, 0, 0]); // KEY_TYPE_ED25519
        assert_eq!(&tx[4..36], &source_key);
    }

    #[test]
    fn test_build_unsigned_tx_deterministic() {
        let source_address = build_test_stellar_address(6 << 3, &[0u8; 32]);
        let contract_address = build_test_stellar_address(2 << 3, &[0xABu8; 32]);
        let signals = vec![("CS:BTC-USD".to_string(), 100u64)];

        let tx1 = build_unsigned_tx(&source_address, &contract_address, 100, 1, &signals, 1000, 1)
            .unwrap();
        let tx2 = build_unsigned_tx(&source_address, &contract_address, 100, 1, &signals, 1000, 1)
            .unwrap();

        assert_eq!(tx1, tx2);
    }

    // Helper to build a valid Stellar StrKey address for testing.
    fn build_test_stellar_address(version_byte: u8, key: &[u8; 32]) -> String {
        let mut payload = Vec::with_capacity(35);
        payload.push(version_byte);
        payload.extend_from_slice(key);
        let checksum = stellar_crc16_xmodem(&payload);
        payload.extend_from_slice(&checksum.to_le_bytes());
        stellar_base32_encode(&payload)
    }

    fn stellar_base32_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for &byte in data {
            buffer = (buffer << 8) | byte as u64;
            bits_in_buffer += 8;
            while bits_in_buffer >= 5 {
                bits_in_buffer -= 5;
                let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        if bits_in_buffer > 0 {
            let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        result
    }
}
