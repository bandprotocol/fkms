use anyhow::anyhow;
use serde_json::{Value, json};
use xrpl::core::binarycodec;

pub fn create_signing_payload(
    signals: &[(String, u64)],
    account: &str,
    oracle_id: u64,
    fee: &str,
    sequence: u64,
    last_update_time: i64,
    signing_pub_key: &str,
) -> anyhow::Result<Value> {
    let last_update_time: u64 = last_update_time
        .try_into()
        .map_err(|_| anyhow::anyhow!("Timestamp must be non-negative"))?;

    Ok(json!(
        {
            // TransactionType: 51 (OracleSet)
            "TransactionType": 51,
            "Account": account,
            "OracleDocumentID": oracle_id,
            "Provider": str_to_hex("Band Protocol", None)?,
            "AssetClass": str_to_hex("currency", None)?,
            "LastUpdateTime": last_update_time,
            "PriceDataSeries": signals
                .iter()
                .map(|(base, price)| create_price_data(base.clone(), price))
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

fn create_price_data(base: String, price: &u64) -> anyhow::Result<Value> {
    let quote = "USD".to_string();
    let base = if base.len() == 3 {
        base
    } else {
        str_to_hex(&base, Some(40))?
    };

    Ok(json!({
        "PriceData": {
            "AssetPrice": format!("{:016X}", price),
            "BaseAsset": base,
            "QuoteAsset": quote,
            "Scale": 9,
        }
    }))
}

// only supports ASCII characters
fn str_to_hex(s: &str, length: Option<usize>) -> anyhow::Result<String> {
    // Convert characters to Hex uppercase
    let mut hex_str = s.chars().fold(String::new(), |mut acc, c| {
        acc.push_str(&format!("{:02X}", c as u32));
        acc
    });

    // Validate length (Error if hex is already longer than target)
    if let Some(length) = length {
        if hex_str.len() > length {
            return Err(anyhow!(
                "The hex string length ({}) is longer than expected ({}).",
                hex_str.len(),
                length
            ));
        }

        // Right-pad with '0' until target length is reached
        while hex_str.len() < length {
            hex_str.push('0');
        }
    }

    Ok(hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_signing_payload_success() {
        let signals = vec![
            ("BTC".to_string(), 67758920310332u64),
            ("XRP".to_string(), 1410834569u64),
        ];

        // Ripple Epoch for 2026-02-26 is approx 825330000
        let last_update = 825330000;

        let result = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            869,
            "10",
            14580274,
            last_update,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        );

        assert!(
            result.is_ok(),
            "Payload creation failed: {:?}",
            result.err()
        );
        let payload = result.unwrap();

        // Verify TransactionType (Should be OracleSet or 32)
        // If library converts 51 to OracleSet, this passes.
        assert!(payload["TransactionType"] == "OracleSet" || payload["TransactionType"] == 51);

        // Verify Field Names (Crucial for temMALFORMED)
        assert!(
            payload.get("OracleDocumentID").is_some(),
            "Field 'OracleDocumentID' missing"
        );
        assert!(
            payload.get("PriceDataSeries").is_some(),
            "Field 'PriceDataSeries' missing"
        );
        assert!(
            payload.get("LastUpdateTime").is_some(),
            "Field 'LastUpdateTime' missing"
        );

        // Verify PriceDataSeries content
        let series = payload["PriceDataSeries"].as_array().unwrap();
        assert_eq!(series.len(), 2);

        // Verify BTC entry (BaseAsset should be "BTC" as per your logic for len == 3)
        let btc_entry = &series[0]["PriceData"];
        assert_eq!(btc_entry["BaseAsset"], "BTC");
        assert_eq!(btc_entry["QuoteAsset"], "USD");

        // Verify price is a string (to avoid JSON float issues)
        assert!(btc_entry["AssetPrice"].is_string());
    }

    #[test]
    fn test_str_to_hex_for_assets() {
        // WBTC is 4 chars, so your logic calls str_to_hex(..., 40)
        let hex_val = str_to_hex("WBTC", Some(40)).unwrap();

        // "W" = 57, "B" = 42, "T" = 54, "C" = 43
        assert!(hex_val.starts_with("57425443"));
        assert_eq!(hex_val.len(), 40);
        assert!(hex_val.ends_with('0')); // Ensure right padding
    }

    #[test]
    fn test_str_to_hex_no_length_constraint() {
        // Should convert without adding any padding or validation
        let result = str_to_hex("ABC", None).unwrap();
        assert_eq!(result, "414243");
    }

    #[test]
    fn test_asset_price_is_hex_string() {
        // AssetPrice must be a 16-char uppercase hex string (XRPL UInt64 canonical format)
        let signals = vec![("BTC".to_string(), 67758920310332u64)];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let price_str = payload["PriceDataSeries"][0]["PriceData"]["AssetPrice"]
            .as_str()
            .expect("AssetPrice must be a string");

        // Must be exactly 16 hex characters
        assert_eq!(
            price_str.len(),
            16,
            "AssetPrice must be 16 chars, got: {price_str}"
        );
        assert!(
            price_str.chars().all(|c| c.is_ascii_hexdigit()),
            "AssetPrice must be hex, got: {price_str}"
        );

        // 67758920310332 decimal == 0x3DA05A601E3C hex
        assert_eq!(price_str, "00003DA05A601E3C");
    }

    #[test]
    fn test_asset_price_zero() {
        let signals = vec![("BTC".to_string(), 0u64)];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let price_str = payload["PriceDataSeries"][0]["PriceData"]["AssetPrice"]
            .as_str()
            .unwrap();
        assert_eq!(price_str, "0000000000000000");
    }

    #[test]
    fn test_asset_price_max_u64() {
        let signals = vec![("BTC".to_string(), u64::MAX)];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let price_str = payload["PriceDataSeries"][0]["PriceData"]["AssetPrice"]
            .as_str()
            .unwrap();
        assert_eq!(price_str, "FFFFFFFFFFFFFFFF");
    }

    #[test]
    fn test_non_3char_base_asset_is_hex_encoded() {
        // WBTC (4 chars) should be hex-encoded and right-padded to 40 chars
        let signals = vec![("WBTC".to_string(), 1_000_000_000u64)];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let entry = &payload["PriceDataSeries"][0]["PriceData"];
        let base = entry["BaseAsset"].as_str().unwrap();
        // "WBTC" hex = 57425443, right-padded to 40 chars
        assert_eq!(base.len(), 40);
        assert!(base.starts_with("57425443"));
        assert_eq!(entry["QuoteAsset"], "USD");
    }

    #[test]
    fn test_negative_timestamp_is_rejected() {
        let signals = vec![("BTC".to_string(), 1_000u64)];
        let result = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            -1,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        );
        assert!(result.is_err(), "Negative timestamp should be rejected");
    }

    #[test]
    fn test_str_to_hex_too_long_is_rejected() {
        // "Band Protocol" is 13 chars = 26 hex chars, fits in None but fails with Some(10)
        let result = str_to_hex("Band Protocol", Some(10));
        assert!(result.is_err());
    }

    #[test]
    fn test_scale_is_always_9() {
        let signals = vec![("ETH".to_string(), 2_500_000_000_000u64)];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let scale = payload["PriceDataSeries"][0]["PriceData"]["Scale"]
            .as_u64()
            .unwrap();
        assert_eq!(scale, 9);
    }

    #[test]
    fn test_empty_signals_produces_empty_series() {
        let signals: Vec<(String, u64)> = vec![];
        let payload = create_signing_payload(
            &signals,
            "rpJ8fpF16aB8a4rmhkZNaXCWq3zweEzKrB",
            1,
            "10",
            100,
            825330000,
            "02d5a397a10de2c485fa5592ffd86a7b5744bc221e24f71196acd32eb66b14264c",
        )
        .unwrap();

        let series = payload["PriceDataSeries"].as_array().unwrap();
        assert!(series.is_empty());
    }
}
