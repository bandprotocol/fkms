use std::str;

use alloy_sol_types::{SolValue, sol};
use anyhow::Context;
use rlp::Rlp;

const EIP1559_TX_PREFIX: u8 = 0x02;

pub struct EvmTx {
    pub tx_type: u8,
    pub tss: Tss,
}

sol! {
    struct Tss {
        bytes message;
        address randomAddr;
        uint256 signature;
    }
}

pub fn decode_tx(encoded_tx: &[u8]) -> anyhow::Result<EvmTx> {
    let tx_type = *encoded_tx.first().with_context(|| "Empty tx data")?;

    let calldata = match tx_type {
        EIP1559_TX_PREFIX => {
            let r = Rlp::new(&encoded_tx[1..]);
            r.val_at::<Vec<u8>>(7)
        }
        _ => {
            let r = Rlp::new(encoded_tx);
            r.val_at::<Vec<u8>>(5)
        }
    }?;

    let tss: Tss =
        SolValue::abi_decode_params_validate(&calldata).with_context(|| "Failed to decode abi")?;

    Ok(EvmTx { tx_type, tss })
}
