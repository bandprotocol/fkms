use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use k256::sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    AccountId, ContractId, DecoratedSignature, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, ScVec, SequenceNumber,
    Signature, SignatureHint, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanTransactionData, TimeBounds, TimePoint,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    WriteXdr,
};
use tokio::task::JoinSet;

const TX_TIMEOUT_SECS: u64 = 300;

// ── helpers ──────────────────────────────────────────────────────────────────

fn timeout_precondition() -> Preconditions {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Preconditions::Time(TimeBounds {
        min_time: TimePoint(0),
        max_time: TimePoint(now + TX_TIMEOUT_SECS),
    })
}

fn build_signal_vals(signals: &[(String, u64)]) -> anyhow::Result<Vec<ScVal>> {
    signals
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
        .collect()
}

fn build_invoke_op(contract_hash: [u8; 32], args: VecM<ScVal>) -> anyhow::Result<Operation> {
    let invoke_args = InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash(contract_hash))),
        function_name: ScSymbol(
            "relay"
                .try_into()
                .map_err(|_| anyhow!("invalid function name"))?,
        ),
        args,
    };

    let auth_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke_args.clone()),
            sub_invocations: vec![]
                .try_into()
                .map_err(|_| anyhow!("failed to build sub_invocations"))?,
        },
    };

    Ok(Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: vec![auth_entry]
                .try_into()
                .map_err(|_| anyhow!("failed to build auth vec"))?,
        }),
    })
}

// ── public API ────────────────────────────────────────────────────────────────

/// Builds an unsigned transaction with `TransactionExt::V0` for use as the
/// simulation payload. `sequence` is written into the transaction as provided,
/// so callers must pass the next valid account sequence number (for example,
/// the current on-chain sequence plus 1).
pub fn build_base_tx(
    source_account: &str,
    contract_address: &str,
    fee: u32,
    sequence: i64,
    signals: &[(String, u64)],
    resolve_time: u64,
    request_id: u64,
) -> anyhow::Result<Transaction> {
    let source_key = decode_stellar_address(source_account)?;
    let contract_hash = decode_stellar_contract_address(contract_address)?;

    let arg_from = ScVal::Address(ScAddress::Account(AccountId(
        XdrPublicKey::PublicKeyTypeEd25519(Uint256(source_key)),
    )));
    let signal_vals = build_signal_vals(signals)?;
    let arg_signals = ScVal::Vec(Some(ScVec(
        signal_vals
            .try_into()
            .map_err(|_| anyhow!("failed to build signals vec"))?,
    )));
    let arg_resolve_time = ScVal::U64(resolve_time);
    let arg_request_id = ScVal::U64(request_id);

    let args = vec![arg_from, arg_signals, arg_resolve_time, arg_request_id]
        .try_into()
        .map_err(|_| anyhow!("failed to build args vec"))?;

    let op = build_invoke_op(contract_hash, args)?;

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_key)),
        fee,
        seq_num: SequenceNumber(sequence),
        cond: timeout_precondition(),
        memo: Memo::None,
        operations: vec![op]
            .try_into()
            .map_err(|_| anyhow!("failed to build operations vec"))?,
        ext: TransactionExt::V0,
    };
    Ok(tx)
}

/// Simulates `base_tx` against a single `rpc_url` and returns the
/// `SorobanTransactionData` plus the minimum resource fee reported by the node.
async fn simulate_transaction_single(
    rpc_url: &str,
    envelope_b64: &str,
) -> anyhow::Result<(SorobanTransactionData, i64)> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": { "transaction": envelope_b64 }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("simulateTransaction request failed: {e}"))?;

    let resp = resp
        .error_for_status()
        .map_err(|e| anyhow!("simulateTransaction HTTP error: {e}"))?;

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow!("failed to parse simulateTransaction response: {e}"))?;

    if let Some(err) = resp_json.get("error") {
        return Err(anyhow!("simulateTransaction RPC error: {}", err));
    }

    let result = resp_json
        .get("result")
        .ok_or_else(|| anyhow!("missing result in simulateTransaction response"))?;

    if let Some(err) = result.get("error") {
        return Err(anyhow!("simulateTransaction execution error: {}", err));
    }

    // Decode SorobanTransactionData from the base64 XDR in the response.
    let tx_data_b64 = result
        .get("transactionData")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing transactionData in simulateTransaction response"))?;

    let tx_data_xdr = general_purpose::STANDARD
        .decode(tx_data_b64)
        .map_err(|e| anyhow!("failed to decode transactionData base64: {e}"))?;

    let soroban_data = SorobanTransactionData::from_xdr(&tx_data_xdr, Limits::none())
        .map_err(|e| anyhow!("failed to decode SorobanTransactionData XDR: {e}"))?;

    // minResourceFee may arrive as a JSON string or number.
    let min_resource_fee: i64 = match result.get("minResourceFee") {
        Some(v) if v.is_string() => v
            .as_str()
            .ok_or_else(|| anyhow!("minResourceFee is not a string"))?
            .parse::<i64>()
            .map_err(|_| anyhow!("invalid minResourceFee string"))?,
        Some(v) if v.is_i64() => v
            .as_i64()
            .ok_or_else(|| anyhow!("minResourceFee is not an i64"))?,
        Some(v) if v.is_u64() => {
            v.as_u64()
                .ok_or_else(|| anyhow!("minResourceFee is not a u64"))? as i64
        }
        _ => {
            return Err(anyhow!(
                "missing or invalid minResourceFee in simulateTransaction response"
            ));
        }
    };

    Ok((soroban_data, min_resource_fee))
}

/// Simulates `base_tx` against all `rpc_urls` concurrently and returns the
/// result from whichever node responds successfully first.
pub async fn simulate_transaction(
    rpc_urls: &[String],
    base_tx: &Transaction,
) -> anyhow::Result<(SorobanTransactionData, i64)> {
    if rpc_urls.is_empty() {
        return Err(anyhow!("rpc_urls must not be empty"));
    }

    let base_tx_xdr = base_tx
        .to_xdr(Limits::none())
        .map_err(|e| anyhow!("failed to encode transaction XDR: {e}"))?;

    // Wrap the bare Transaction in an unsigned envelope for the RPC call.
    let tx = Transaction::from_xdr(base_tx_xdr, Limits::none())
        .map_err(|e| anyhow!("failed to decode tx for simulation: {e}"))?;

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![]
            .try_into()
            .map_err(|_| anyhow!("failed to build empty signatures for simulation"))?,
    });

    let envelope_xdr = envelope
        .to_xdr(Limits::none())
        .map_err(|e| anyhow!("failed to encode envelope for simulation: {e}"))?;
    let envelope_b64 = general_purpose::STANDARD.encode(&envelope_xdr);

    let mut tasks = JoinSet::new();

    for url in rpc_urls {
        let url = url.clone();
        let envelope_b64 = envelope_b64.clone();
        tasks.spawn(async move { simulate_transaction_single(&url, &envelope_b64).await });
    }

    let mut last_err = anyhow!("all rpc_urls failed");
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(val)) => {
                tasks.abort_all();
                return Ok(val);
            }
            Ok(Err(e)) => last_err = e,
            Err(e) => last_err = anyhow!("simulation task failed: {e}"),
        }
    }
    Err(last_err)
}

/// Builds the final unsigned transaction with `TransactionExt::V1` using the
/// `SorobanTransactionData` returned by simulation.
///
/// `base_fee`       – user-configured inclusion fee (stroops, typically 100)
/// `min_resource_fee` – from `simulate_transaction`; added to `base_fee` to
///                      produce the transaction's total fee field.
pub fn build_unsigned_tx(
    tx: &mut Transaction,
    soroban_data: SorobanTransactionData,
    min_resource_fee: i64,
) -> anyhow::Result<Vec<u8>> {
    let base_fee = tx.fee;

    // total fee = inclusion fee + resource fee (both are required by the network).
    let total_fee = u32::try_from(base_fee as i64 + min_resource_fee).map_err(|_| {
        anyhow!("fee overflow: base_fee={base_fee} + min_resource_fee={min_resource_fee}")
    })?;

    tx.fee = total_fee;
    tx.ext = TransactionExt::V1(soroban_data);

    tx.to_xdr(Limits::none())
        .map_err(|e| anyhow!("failed to encode transaction XDR: {e}"))
}

/// Computes the Stellar transaction hash used as the Ed25519 signing payload.
///
/// SHA-256(network_id || ENVELOPE_TYPE_TX || unsigned_tx_xdr)
pub fn compute_tx_hash(network_passphrase: &str, unsigned_tx: &[u8]) -> Vec<u8> {
    let network_id = Sha256::digest(network_passphrase.as_bytes());
    let envelope_type_tx: [u8; 4] = [0, 0, 0, 2]; // ENVELOPE_TYPE_TX = 2

    let mut hasher = Sha256::new();
    hasher.update(network_id);
    hasher.update(envelope_type_tx);
    hasher.update(unsigned_tx);
    hasher.finalize().to_vec()
}

/// Encodes a signed TransactionEnvelope XDR ready for broadcast.
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

    let hint: [u8; 4] = public_key[28..32]
        .try_into()
        .map_err(|_| anyhow!("failed to extract signature hint from public key"))?;
    let sig_bytes: Signature = signature
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("failed to encode signature bytes"))?;

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
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

// ── address helpers ───────────────────────────────────────────────────────────

fn decode_stellar_address(address: &str) -> anyhow::Result<[u8; 32]> {
    stellar_strkey::ed25519::PublicKey::from_string(address)
        .map(|pk| pk.0)
        .map_err(|e| anyhow!("invalid Stellar address: {e}"))
}

fn decode_stellar_contract_address(address: &str) -> anyhow::Result<[u8; 32]> {
    stellar_strkey::Contract::from_string(address)
        .map(|c| c.0)
        .map_err(|e| anyhow!("invalid Stellar contract address: {e}"))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_tx(source_address: &str, contract_address: &str) -> Vec<u8> {
        build_base_tx(source_address, contract_address, 100, 1, &[], 0, 0)
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap()
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
    fn test_build_base_tx_produces_output() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();

        let signals = vec![
            ("CS:BTC-USD".to_string(), 67758920310332u64),
            ("CS:ETH-USD".to_string(), 3500000000000u64),
        ];

        let tx = build_base_tx(
            &source_address,
            &contract_address,
            100,
            42,
            &signals,
            1700000000,
            99,
        )
        .unwrap();

        assert_eq!(tx.fee, 100);
        // sequence is stored as current+1
        assert_eq!(tx.seq_num, SequenceNumber(42));
        assert!(matches!(tx.cond, Preconditions::Time(_)));
        assert!(matches!(tx.ext, TransactionExt::V0));
    }

    #[test]
    fn test_build_base_tx_deterministic() {
        let source_address = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        let contract_address = stellar_strkey::Contract([0xABu8; 32]).to_string();
        let signals = vec![("CS:BTC-USD".to_string(), 100u64)];

        let tx1 = build_base_tx(
            &source_address,
            &contract_address,
            100,
            1,
            &signals,
            1000,
            1,
        )
        .unwrap()
        .to_xdr(Limits::none())
        .unwrap();
        let tx2 = build_base_tx(
            &source_address,
            &contract_address,
            100,
            1,
            &signals,
            1000,
            1,
        )
        .unwrap()
        .to_xdr(Limits::none())
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
