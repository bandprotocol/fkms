use anyhow::anyhow;
use k256::sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    AccountId, ContractId, DecoratedSignature, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, ScVec, SequenceNumber,
    Signature, SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, WriteXdr,
};


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

    // arg[0]: from as ScVal Address (account)
    let arg_from = ScVal::Address(ScAddress::Account(AccountId(
        XdrPublicKey::PublicKeyTypeEd25519(Uint256(source_key)),
    )));

    // arg[1]: signals as ScVal Vec<Vec<(Symbol, U64)>>
    let signal_vals = signals
        .iter()
        .map(|(sym, price)| {
            let sym_val = ScVal::Symbol(ScSymbol(
                sym.as_str()
                    .try_into()
                    .map_err(|_| anyhow!("symbol too long: {}", sym))?,
            ));
            let price_val = ScVal::U64(*price);
            let inner = ScVec(
                vec![sym_val, price_val]
                    .try_into()
                    .map_err(|_| anyhow!("failed to build signal tuple"))?,
            );
            Ok(ScVal::Vec(Some(inner)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let arg_signals = ScVal::Vec(Some(ScVec(
        signal_vals
            .try_into()
            .map_err(|_| anyhow!("failed to build signals vec"))?,
    )));

    // arg[2]: resolve_time as ScVal U64
    let arg_resolve_time = ScVal::U64(resolve_time);

    // arg[3]: request_id as ScVal U64
    let arg_request_id = ScVal::U64(request_id);

    let args = vec![arg_from, arg_signals, arg_resolve_time, arg_request_id]
        .try_into()
        .map_err(|_| anyhow!("failed to build args vec"))?;

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_hash))),
                function_name: ScSymbol(
                    "relay"
                        .try_into()
                        .map_err(|_| anyhow!("invalid function name"))?,
                ),
                args,
            }),
            auth: vec![]
                .try_into()
                .map_err(|_| anyhow!("failed to build auth vec"))?,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_key)),
        fee,
        seq_num: SequenceNumber(sequence as i64),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op]
            .try_into()
            .map_err(|_| anyhow!("failed to build operations vec"))?,
        ext: TransactionExt::V0,
    };

    tx.to_xdr(Limits::none())
        .map_err(|e| anyhow!("failed to encode transaction XDR: {e}"))
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
/// Decodes `unsigned_tx` back to a `Transaction`, wraps it in a `TransactionV1Envelope`
/// with the Ed25519 signature, and returns the XDR-encoded envelope bytes.
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

    let tx = Transaction::from_xdr(unsigned_tx, Limits::none())
        .map_err(|e| anyhow!("failed to decode transaction XDR: {e}"))?;

    let hint: [u8; 4] = public_key[28..32].try_into().unwrap();
    let sig_bytes: Signature = signature
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("failed to encode signature bytes"))?;

    let envelope: TransactionEnvelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: sig_bytes,
        }]
        .try_into()
        .map_err(|_| anyhow!("failed to build signatures vec"))?,
    });

    envelope
        .to_xdr(Limits::none())
        .map_err(|e| anyhow!("failed to encode envelope XDR: {e}"))
}

/// Decodes a Stellar G... (ED25519) address to the 32-byte public key.
fn decode_stellar_address(address: &str) -> anyhow::Result<[u8; 32]> {
    stellar_strkey::ed25519::PublicKey::from_string(address)
        .map(|pk| pk.0)
        .map_err(|e| anyhow!("invalid Stellar address: {e}"))
}

/// Decodes a Stellar C... (contract) address to the 32-byte contract hash.
fn decode_stellar_contract_address(address: &str) -> anyhow::Result<[u8; 32]> {
    stellar_strkey::Contract::from_string(address)
        .map(|c| c.0)
        .map_err(|e| anyhow!("invalid Stellar contract address: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_tx(source_address: &str, contract_address: &str) -> Vec<u8> {
        build_unsigned_tx(source_address, contract_address, 100, 1, &[], 0, 0).unwrap()
    }

    #[test]
    fn test_compute_tx_hash_deterministic() {
        let network_passphrase = "Test SDF Network ; September 2015";
        let unsigned_tx = b"test transaction data";

        let hash = compute_tx_hash(network_passphrase, unsigned_tx);
        assert_eq!(hash.len(), 32);

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
    fn test_decode_stellar_address_roundtrip() {
        let key = [0u8; 32];
        let address = stellar_strkey::ed25519::PublicKey(key).to_string();
        let decoded = decode_stellar_address(&address).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_decode_stellar_contract_address_roundtrip() {
        let hash = [0xABu8; 32];
        let address = stellar_strkey::Contract(hash).to_string();
        let decoded = decode_stellar_contract_address(&address).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_build_unsigned_tx_produces_output() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();

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
        let decoded = Transaction::from_xdr(&tx, Limits::none()).unwrap();
        assert_eq!(decoded.fee, 100);
        assert_eq!(decoded.seq_num, SequenceNumber(42));
        assert!(matches!(decoded.cond, Preconditions::None));
        assert!(matches!(decoded.ext, TransactionExt::V0));
    }

    #[test]
    fn test_build_unsigned_tx_deterministic() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();
        let signals = vec![("CS:BTC-USD".to_string(), 100u64)];

        let tx1 = build_unsigned_tx(&source_address, &contract_address, 100, 1, &signals, 1000, 1)
            .unwrap();
        let tx2 = build_unsigned_tx(&source_address, &contract_address, 100, 1, &signals, 1000, 1)
            .unwrap();

        assert_eq!(tx1, tx2);
    }

    #[test]
    fn test_encode_signed_envelope_roundtrip() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();
        let unsigned_tx = build_test_tx(&source_address, &contract_address);

        let public_key = vec![0xBBu8; 32];
        let signature = vec![0xCCu8; 64];

        let envelope = encode_signed_envelope(&unsigned_tx, &public_key, &signature).unwrap();

        let decoded = TransactionEnvelope::from_xdr(&envelope, Limits::none()).unwrap();
        match decoded {
            TransactionEnvelope::Tx(env) => {
                assert_eq!(env.signatures.len(), 1);
                assert_eq!(env.signatures[0].hint, SignatureHint([0xBB; 4]));
            }
            _ => panic!("expected TransactionEnvelope::Tx"),
        }
    }

    #[test]
    fn test_encode_signed_envelope_invalid_pubkey() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();
        let unsigned_tx = build_test_tx(&source_address, &contract_address);

        let result = encode_signed_envelope(&unsigned_tx, &[0; 31], &[0; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_signed_envelope_invalid_signature() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();
        let unsigned_tx = build_test_tx(&source_address, &contract_address);

        let result = encode_signed_envelope(&unsigned_tx, &[0; 32], &[0; 63]);
        assert!(result.is_err());
    }
}
