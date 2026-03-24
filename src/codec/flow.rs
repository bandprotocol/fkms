use anyhow::anyhow;
use rlp::RlpStream;
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

// Flow transaction domain tag: "FLOW-V0.0-transaction" right-padded with null bytes to 32 bytes
const FLOW_TRANSACTION_DOMAIN_TAG: &[u8] =
    b"FLOW-V0.0-transaction\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// Builds the RLP-encoded transaction payload used for signing.
#[allow(clippy::too_many_arguments)]
pub fn build_payload_rlp(
    signals: &[(String, u64)],
    address: &str,
    compute_limit: u64,
    block_id: &str,
    key_index: u32,
    sequence: u64,
    script: &[u8],
    resolve_time: u64,
    request_id: u64,
) -> anyhow::Result<Vec<u8>> {
    let address = parse_flow_address(address)?;
    let block_id = parse_block_id(block_id)?;
    let args = build_cadence_arguments(signals, resolve_time, request_id)?;

    Ok(encode_payload_rlp(
        script,
        &args,
        &block_id,
        compute_limit,
        &address,
        key_index,
        sequence,
        &address,
        &[address],
    ))
}

/// Builds the Cadence JSON-encoded arguments list for the transaction.
///
/// Encodes signals as a Cadence `Dictionary`, followed by `resolve_time`
/// and `request_id` as `UInt64` values.
pub fn build_transaction_envelope_hash(payload_rlp: &[u8]) -> anyhow::Result<Vec<u8>> {
    let envelope_rlp = encode_envelope_rlp(payload_rlp);

    let tx = [FLOW_TRANSACTION_DOMAIN_TAG, &envelope_rlp].concat();

    Ok(Sha3_256::digest(&tx).to_vec())
}

/// Encodes the fully signed transaction into RLP format for submission to the Flow network.
///
/// Combines the payload RLP with an empty payload signatures list and a single
/// envelope signature containing the signer's key index and signature bytes.
pub fn encode_signed_transaction(
    payload_rlp: &[u8],
    key_index: u32,
    signature: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut stream = RlpStream::new_list(3);
    stream.append_raw(payload_rlp, 1);
    stream.begin_list(0);
    stream.begin_list(1);
    stream.begin_list(3);
    stream.append(&0u64);
    stream.append(&(key_index as u64));
    stream.append(&signature);

    Ok(stream.out().to_vec())
}

fn encode_envelope_rlp(payload_rlp: &[u8]) -> Vec<u8> {
    let mut stream = RlpStream::new_list(2);
    stream.append_raw(payload_rlp, 1);
    stream.begin_list(0);
    stream.out().to_vec()
}

// RLP-encode the 9-field payload (used for both signing hash and signed transaction).
#[allow(clippy::too_many_arguments)]
fn encode_payload_rlp(
    script: &[u8],
    args: &[Vec<u8>],
    block_id: &[u8],
    compute_limit: u64,
    proposer_address: &[u8],
    key_index: u32,
    sequence: u64,
    payer_address: &[u8],
    authorizers: &[[u8; 8]],
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);

    stream.append(&script);
    stream.begin_list(args.len());
    for arg in args {
        stream.append(arg);
    }
    stream.append(&block_id);
    stream.append(&compute_limit);
    stream.append(&proposer_address);
    stream.append(&key_index);
    stream.append(&sequence);
    stream.append(&payer_address);
    stream.begin_list(authorizers.len());
    for auth in authorizers {
        stream.append(&auth.as_slice());
    }

    stream.out().to_vec()
}

// Build the Cadence JSON-encoded arguments list.
fn build_cadence_arguments(
    signals: &[(String, u64)],
    resolve_time: u64,
    request_id: u64,
) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(vec![
        serde_json::to_vec(&cadence_dict(signals))?,
        serde_json::to_vec(&cadence_uint64(resolve_time))?,
        serde_json::to_vec(&cadence_uint64(request_id))?,
    ])
}

fn cadence_dict(signals: &[(String, u64)]) -> Value {
    let pairs: Vec<Value> = signals
        .iter()
        .map(|(symbol, price)| {
            json!({
                "key": cadence_string(symbol),
                "value": cadence_uint64(*price),
            })
        })
        .collect();

    json!({
        "type": "Dictionary",
        "value": pairs,
    })
}

fn cadence_uint64(v: u64) -> Value {
    json!({
        "type": "UInt64",
        "value": v.to_string(),
    })
}

fn cadence_string(s: &str) -> Value {
    json!({
        "type": "String",
        "value": s,
    })
}

// Parse a Flow address (hex, with or without "0x" prefix) into 8 bytes.
fn parse_flow_address(address: &str) -> anyhow::Result<[u8; 8]> {
    let hex_str = address.strip_prefix("0x").unwrap_or(address);
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("Invalid Flow address hex '{}': {}", address, e))?;
    if bytes.len() != 8 {
        return Err(anyhow!(
            "Flow address must be 8 bytes, got {} bytes for '{}'",
            bytes.len(),
            address
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// Parse a hex-encoded 32-byte block ID.
fn parse_block_id(block_id: &str) -> anyhow::Result<Vec<u8>> {
    let hex_str = block_id.strip_prefix("0x").unwrap_or(block_id);
    let bytes =
        hex::decode(hex_str).map_err(|e| anyhow!("Invalid block_id hex '{}': {}", block_id, e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "block_id must be 32 bytes, got {} bytes",
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_tag_length() {
        assert_eq!(FLOW_TRANSACTION_DOMAIN_TAG.len(), 32);
        assert!(FLOW_TRANSACTION_DOMAIN_TAG.starts_with(b"FLOW-V0.0-transaction"));
    }

    #[test]
    fn test_parse_flow_address_with_prefix() {
        let addr = parse_flow_address("0x1234567890abcdef").unwrap();
        assert_eq!(addr, [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_parse_flow_address_without_prefix() {
        let addr = parse_flow_address("1234567890abcdef").unwrap();
        assert_eq!(addr, [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_parse_flow_address_wrong_length() {
        assert!(parse_flow_address("0x1234").is_err());
    }

    #[test]
    fn test_parse_block_id() {
        let block_id = "a".repeat(64);
        let bytes = parse_block_id(&block_id).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_cadence_dict_encoding() {
        let signals = vec![("BTC-USD".to_string(), 100_000_000_000u64)];
        let val = cadence_dict(&signals);
        assert_eq!(val["type"], "Dictionary");
        let pairs = val["value"].as_array().unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0]["key"]["type"], "String");
        assert_eq!(pairs[0]["key"]["value"], "BTC-USD");
        assert_eq!(pairs[0]["value"]["type"], "UInt64");
        assert_eq!(pairs[0]["value"]["value"], "100000000000");
    }

    #[test]
    fn test_build_transaction_envelope_hash_produces_32_bytes() {
        let signals = vec![
            ("BTC-USD".to_string(), 100_000_000_000u64),
            ("ETH-USD".to_string(), 5_000_000_000u64),
        ];
        let block_id = "a".repeat(64);
        let script = b"import BandOracle from 0x1234\ntransaction {}";

        let payload_rlp = build_payload_rlp(
            &signals,
            "0x1234567890abcdef",
            1000,
            &block_id,
            0,
            42,
            script,
            1_700_000_000,
            99,
        )
        .unwrap();

        let hash = build_transaction_envelope_hash(&payload_rlp).unwrap();

        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_encode_signed_transaction_is_valid_rlp() {
        let signals = vec![("BTC-USD".to_string(), 100_000_000_000u64)];
        let block_id = "a".repeat(64);
        let script = b"transaction {}";
        let signature = vec![0u8; 64]; // dummy 64-byte P-256 signature

        let payload_rlp = build_payload_rlp(
            &signals,
            "0x1234567890abcdef",
            1000,
            &block_id,
            0,
            0,
            script,
            1_700_000_000,
            1,
        )
        .unwrap();

        let tx_blob = encode_signed_transaction(&payload_rlp, 0, &signature).unwrap();

        assert!(!tx_blob.is_empty());
        // Verify it decodes as RLP list with 3 items
        let rlp = rlp::Rlp::new(&tx_blob);
        assert!(rlp.is_list());
        assert_eq!(rlp.item_count().unwrap(), 3);
    }
}
