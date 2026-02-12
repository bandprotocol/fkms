use crate::codec::evm::decode_tx;

pub fn verify_message(encoded_tx: &[u8], tss_message: &[u8]) -> Result<(), anyhow::Error> {
    let evm_tx = decode_tx(encoded_tx)?;
    if tss_message != evm_tx.tss.message.as_ref() {
        return Err(anyhow::anyhow!("TSS message does not match"));
    }

    Ok(())
}
