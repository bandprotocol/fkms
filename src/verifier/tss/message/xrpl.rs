use crate::codec::tss::decode_tss_message;
use crate::codec::xrpl::decode_prices_from_encoded_tx;

pub fn verify_message(encoded_tx: &[u8], tss_message: &[u8]) -> Result<(), anyhow::Error> {
    let tx_prices = decode_prices_from_encoded_tx(encoded_tx)?;
    let tss_message = decode_tss_message(tss_message)?;

    if tx_prices != tss_message.signal_prices()? {
        return Err(anyhow::anyhow!("Prices do not match"));
    }
    Ok(())
}
