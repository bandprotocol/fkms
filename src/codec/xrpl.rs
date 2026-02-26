use anyhow::anyhow;
use serde_json::{Value, json};
use xrpl::core::binarycodec;

pub fn create_signing_payload(
    signals: &[(String, u64)],
    account: String,
    oracle_id: u64,
    fee: String,
    sequence: u64,
    last_updated_time: u64,
    signing_pub_key: String,
) -> anyhow::Result<Value> {
    Ok(json!(
        {
            "TransactionType": "OracleSet",
            "Account": account,
            "OracleDocumentID": oracle_id,
            "Provider": str_to_hex("Band Protocol", 40)?,
            "AssetClass": str_to_hex("Currency", 40)?,
            "LastUpdateTime": last_updated_time,
            "PriceData": signals
                .iter()
                .map(|(signal, price)| create_price_data(signal, price))
                .collect::<anyhow::Result<Vec<Value>>>()?,
            "Sequence": sequence,
            "Fee": fee,
            "SigningPubKey": signing_pub_key,
        }
    ))
}

pub fn encode_for_signing(tx: &Value) -> anyhow::Result<Vec<u8>> {
    let encoded_tx = binarycodec::encode_for_signing(tx)?;

    Ok(hex::decode(encoded_tx)?)
}

pub fn encode_with_signature(tx: &mut Value, signature: String) -> anyhow::Result<Vec<u8>> {
    let tx_obj = tx
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Transaction must be a JSON object"))?;

    tx_obj.insert("TxnSignature".into(), Value::String(signature));

    let encoded_tx = binarycodec::encode(tx_obj)?;

    Ok(hex::decode(encoded_tx)?)
}

fn create_price_data(signal_id: &str, price: &u64) -> anyhow::Result<Value> {
    let (base, quote) = extract_base_quote(signal_id)?;
    Ok(json!({
        "PriceData": {
            "AssetPrice": format!("{:x}", price),
            "BaseAsset": str_to_hex(&base, 40)?,
            "QuoteAsset": str_to_hex(&quote, 40)?,
            "Scale": 9,
        }
    }))
}

fn extract_base_quote(signal: &str) -> anyhow::Result<(String, String)> {
    let parts = signal.split(':').collect::<Vec<&str>>();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid signal format, expected: {}, actual: {}",
            "CS:BASE-QUOTE",
            signal
        ));
    }
    let base_quote = parts[1].split('-').collect::<Vec<&str>>();
    if base_quote.len() != 2 {
        return Err(anyhow!(
            "Invalid base-quote format, expected: {}, actual: {}",
            "BASE-QUOTE",
            parts[1]
        ));
    }
    Ok((base_quote[0].to_string(), base_quote[1].to_string()))
}

fn str_to_hex(s: &str, length: usize) -> anyhow::Result<String> {
    // Convert characters to Hex uppercase
    let mut hex_str = s.chars().fold(String::new(), |mut acc, c| {
        acc.push_str(&format!("{:02X}", c as u32));
        acc
    });

    // Validate length (Error if hex is already longer than target)
    if length != 0 && hex_str.len() > length {
        return Err(anyhow!(
            "The hex string length ({}) is longer than expected ({}).",
            hex_str.len(),
            length
        ));
    }

    // Right-pad with '0' until target length is reached
    while length != 0 && hex_str.len() < length {
        hex_str.push('0');
    }

    Ok(hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_signing_payload_success() {
        let signals = vec![
            ("CS:BTC-USD".to_string(), 65000),
            ("CS:ETH-USD".to_string(), 3500),
        ];

        let result = create_signing_payload(
            &signals,
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string(),
            1,
            "10".to_string(),
            100,
            761234567,
            "03EDAD0E3390D421E03D8114B00D09B607994D9969F21516A0F1F0E75691D80C9C".to_string(),
        );

        assert!(
            result.is_ok(),
            "Payload creation failed: {:?}",
            result.err()
        );

        let payload = result.unwrap();

        // Verify Top-level fields
        assert_eq!(payload["TransactionType"], "OracleSet");
        assert_eq!(payload["Sequence"], 100);
        assert_eq!(payload["Fee"], "10");

        // Verify PriceData nesting
        let price_data_list = payload["PriceData"]
            .as_array()
            .expect("PriceData should be an array");
        assert_eq!(price_data_list.len(), 2);

        // Verify specific hex conversion (BTC in hex is 425443)
        let first_base = price_data_list[0]["PriceData"]["BaseAsset"]
            .as_str()
            .unwrap();
        assert!(first_base.starts_with("425443"));
        assert_eq!(first_base.len(), 40);
    }

    #[test]
    fn test_extract_base_quote_valid() {
        let (base, quote) = extract_base_quote("CS:XRP-USD").unwrap();
        assert_eq!(base, "XRP");
        assert_eq!(quote, "USD");
    }

    #[test]
    fn test_extract_base_quote_invalid_format() {
        // Missing colon
        assert!(extract_base_quote("BTC-USD").is_err());
        // Missing dash
        assert!(extract_base_quote("CS:BTCUSD").is_err());
    }

    #[test]
    fn test_str_to_hex_padding() {
        // "XRP" -> 585250...
        let hex = str_to_hex("XRP", 10).unwrap();
        assert_eq!(hex, "5852500000");
        assert_eq!(hex.len(), 10);
    }

    #[test]
    fn test_str_to_hex_too_long_error() {
        // "This string is long" is 19 chars -> 38 hex chars.
        // Setting max length to 10 should fail.
        let result = str_to_hex("This string is long", 10);
        assert!(result.is_err());
    }
}
