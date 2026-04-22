use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use alloy_sol_types::{SolCall, sol};

sol! {
    struct Tss {
        bytes message;
        address randomAddr;
        uint256 signature;
    }
}

sol! {
    function relay(bytes message, address randomAddr, uint256 signature) external;
}

/// Builds the ABI-encoded calldata for the tunnel router `relay(bytes,address,uint256)` function.
pub fn create_relay_calldata(
    message: &[u8],
    random_addr: &[u8],
    signature_s: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let call = relayCall {
        message: message.to_vec().into(),
        randomAddr: Address::from_slice(random_addr),
        signature: U256::from_be_slice(signature_s),
    };

    Ok(SolCall::abi_encode(&call))
}

/// Parameters needed to build an EVM transaction.
pub struct EvmTxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Address,
    pub calldata: Bytes,
    pub gas_limit: u64,
    /// Legacy tx: gas price (None for EIP-1559)
    pub gas_price: Option<u128>,
    /// EIP-1559: max fee per gas (None for Legacy)
    pub gas_fee_cap: Option<u128>,
    /// EIP-1559: max priority fee per gas (None for Legacy)
    pub gas_tip_cap: Option<u128>,
}

/// Computes the signing hash for the transaction (Keccak256 of the signing payload).
pub fn compute_signing_hash(params: &EvmTxParams) -> anyhow::Result<[u8; 32]> {
    match (params.gas_price, params.gas_fee_cap, params.gas_tip_cap) {
        (Some(gas_price), None, None) => {
            let tx = build_legacy_tx(params, gas_price);
            Ok(tx.signature_hash().into())
        }
        (None, Some(gas_fee_cap), Some(gas_tip_cap)) => {
            let tx = build_eip1559_tx(params, gas_fee_cap, gas_tip_cap);
            Ok(tx.signature_hash().into())
        }
        _ => Err(anyhow::anyhow!(
            "Ambiguous gas fields: supply gas_price (legacy) OR gas_fee_cap+gas_tip_cap (EIP-1559)"
        )),
    }
}

/// Builds the complete EIP-2718 encoded signed transaction from params and a 65-byte signature.
/// The signature bytes are in go-ethereum format: [r(32)][s(32)][v(1)].
pub fn encode_signed_tx(params: &EvmTxParams, sig_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(sig_bytes.len() == 65, "signature must be 65 bytes");

    // parity is the recovery bit: non-zero means true (odd y)
    let sig = Signature::from_bytes_and_parity(&sig_bytes[..64], sig_bytes[64] != 0);

    let envelope = match (params.gas_price, params.gas_fee_cap, params.gas_tip_cap) {
        (Some(gas_price), None, None) => {
            let tx = build_legacy_tx(params, gas_price);
            let hash = tx.signature_hash();
            let signed = alloy_consensus::Signed::new_unchecked(tx, sig, hash);
            TxEnvelope::Legacy(signed)
        }
        (None, Some(gas_fee_cap), Some(gas_tip_cap)) => {
            let tx = build_eip1559_tx(params, gas_fee_cap, gas_tip_cap);
            let hash = tx.signature_hash();
            let signed = alloy_consensus::Signed::new_unchecked(tx, sig, hash);
            TxEnvelope::Eip1559(signed)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Ambiguous gas fields: supply gas_price (legacy) OR gas_fee_cap+gas_tip_cap (EIP-1559)"
            ));
        }
    };

    Ok(envelope.encoded_2718())
}

fn build_legacy_tx(params: &EvmTxParams, gas_price: u128) -> TxLegacy {
    TxLegacy {
        chain_id: Some(params.chain_id),
        nonce: params.nonce,
        gas_price,
        gas_limit: params.gas_limit,
        to: TxKind::Call(params.to),
        value: U256::ZERO,
        input: params.calldata.clone(),
    }
}

fn build_eip1559_tx(params: &EvmTxParams, gas_fee_cap: u128, gas_tip_cap: u128) -> TxEip1559 {
    TxEip1559 {
        chain_id: params.chain_id,
        nonce: params.nonce,
        max_fee_per_gas: gas_fee_cap,
        max_priority_fee_per_gas: gas_tip_cap,
        gas_limit: params.gas_limit,
        to: TxKind::Call(params.to),
        value: U256::ZERO,
        input: params.calldata.clone(),
        access_list: Default::default(),
    }
}
