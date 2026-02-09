use anyhow::Context;
use serde::Deserialize;
use serde_json::Value;
use xrpl::core::binarycodec::{encode, encode_for_signing};
use xrpl_binary_codec::deserializer::Deserializer;
use xrpl_binary_codec::serializer::field_id::TypeCode;
use xrpl_binary_codec::serializer::field_info::field_info_lookup;

const XRPL_PREFIX: &[u8] = &[0x53, 0x54, 0x58, 0x00];

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct PriceDataSeriesWrapper {
    // This matches the top-level "PriceDataSeries" key in your JSON
    price_data_series: Vec<PriceDataWrapper>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct PriceDataWrapper {
    price_data: PriceData,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct PriceData {
    base_asset: String,
    quote_asset: String,
    asset_price: String,
}

pub fn decode_prices_from_encoded_tx(encoded_tx: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    let tx = deserialize_tx(encoded_tx)?;
    let price_data_series: PriceDataSeriesWrapper = serde_json::from_value(tx)?;

    let mut prices = Vec::with_capacity(price_data_series.price_data_series.len());
    for price_data in price_data_series.price_data_series {
        let base = hex_to_string(&price_data.price_data.base_asset)?;
        let quote = hex_to_string(&price_data.price_data.quote_asset)?;
        let signal_id = convert_base_quote_to_signal(&base, &quote);
        prices.push((signal_id, str_to_u64(&price_data.price_data.asset_price)?));
    }

    Ok(prices)
}

pub fn encode_tx_with_fields(
    tx: &mut Value,
    fields: Vec<(String, Value)>,
    is_encoded_for_signing: bool,
) -> anyhow::Result<Vec<u8>> {
    let tx_obj = tx
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Transaction must be a JSON object"))?;

    for (key, value) in fields {
        tx_obj.insert(key, value);
    }

    let encoded_tx = if is_encoded_for_signing {
        encode_for_signing(&tx)?
    } else {
        encode(&tx)?
    };

    Ok(hex::decode(encoded_tx)?)
}

pub fn deserialize_tx(encoded_tx: &[u8]) -> anyhow::Result<Value> {
    // Validate length and prefix
    let bytes = match encoded_tx.starts_with(XRPL_PREFIX) {
        true => encoded_tx
            .get(XRPL_PREFIX.len()..)
            .with_context(|| "Calldata too short")?,
        false => encoded_tx,
    };
    let mut deserializer = Deserializer::new(bytes.to_vec(), field_info_lookup());
    let tx = deserializer.to_json(&TypeCode::Object, bytes)?;
    Ok(tx)
}

fn convert_base_quote_to_signal(base_asset: &str, quote_asset: &str) -> String {
    format!("CS:{}-{}", base_asset, quote_asset)
}

fn hex_to_string(hex_str: &str) -> anyhow::Result<String> {
    if hex_str.len() == 3 {
        return Ok(hex_str.to_string());
    }
    // 1. Remove trailing '0's added by the padding logic in Go
    let trimmed = hex_str.trim_end_matches('0');

    // 2. If the resulting length is odd, the last byte was likely a character
    // whose hex representation ended in 0 (e.g., 'P' is 0x50).
    // Hex strings must be even to be decoded.
    let normalized = if !trimmed.len().is_multiple_of(2) {
        format!("{}0", trimmed)
    } else {
        trimmed.to_string()
    };

    // 3. Decode hex to bytes
    let bytes = hex::decode(normalized)?;

    // 4. Convert bytes to String
    let result = String::from_utf8(bytes)?;

    Ok(result)
}

fn str_to_u64(price_str: &str) -> anyhow::Result<u64> {
    price_str.parse().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_prices_from_encoded_tx_full() {
        // Your provided hex encoded transaction
        let encoded_hex = "535458001200332400de7a1c2f69897baf201b00e0ff2c20330000000168400000000000000c701c0863757272656e6379701d0d42616e642050726f746f636f6c81140e54d919c94cda274dde1cc05d5a49de2ccb0d51f018e0203017000040604ee8898d041009011a0000000000000000000000004254430000000000021a0000000000000000000000005553440000000000e1e0203017000001e5f24e2d80041009011a0000000000000000000000004554480000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9a2e0d041009011a524c555344000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b977670041009011a5553444300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9107cd041009011a5553445400000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000402a7e37b280041009011a5742544300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000000055d7e4b2041009011a0000000000000000000000000000000000000000021a0000000000000000000000005553440000000000e1f1";
        let encoded_tx = hex::decode(encoded_hex).expect("Failed to decode test hex");

        // Execute decoding
        let prices =
            decode_prices_from_encoded_tx(&encoded_tx).expect("Failed to decode prices from tx");

        // Expected output data
        let expected = vec![
            ("CS:BTC-USD".to_string(), 70782384900493u64),
            ("CS:ETH-USD".to_string(), 2087124348288u64),
            ("CS:RLUSD-USD".to_string(), 999960077u64),
            ("CS:USDC-USD".to_string(), 999782000u64),
            ("CS:USDT-USD".to_string(), 999360461u64),
            ("CS:WBTC-USD".to_string(), 70551250383488u64),
            ("CS:XRP-USD".to_string(), 1440212146u64),
        ];

        assert_eq!(prices.len(), expected.len(), "Price list length mismatch");

        for (i, (signal, price)) in prices.iter().enumerate() {
            assert_eq!(signal, &expected[i].0, "Signal mismatch at index {}", i);
            assert_eq!(price, &expected[i].1, "Price mismatch at index {}", i);
        }
    }

    #[test]
    fn test_deserialize_tx_structure() {
        // Raw XRPL binary blob provided in your example
        let encoded_hex = "535458001200332400de7a1c2f69897baf201b00e0ff2c20330000000168400000000000000c701c0863757272656e6379701d0d42616e642050726f746f636f6c81140e54d919c94cda274dde1cc05d5a49de2ccb0d51f018e0203017000040604ee8898d041009011a0000000000000000000000004254430000000000021a0000000000000000000000005553440000000000e1e0203017000001e5f24e2d80041009011a0000000000000000000000004554480000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9a2e0d041009011a524c555344000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b977670041009011a5553444300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9107cd041009011a5553445400000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000402a7e37b280041009011a5742544300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000000055d7e4b2041009011a0000000000000000000000000000000000000000021a0000000000000000000000005553440000000000e1f1";
        let encoded_tx = hex::decode(encoded_hex).expect("Invalid hex");

        let json_value = deserialize_tx(&encoded_tx).expect("Deserialization failed");

        // 1. Check that it is an object
        assert!(json_value.is_object(), "Resulting JSON should be an object");

        // 2. Verify specific XRPL fields exist (Sequence is common)
        // Note: Field names depend on the deserializer's PascalCase/camelCase config
        assert!(json_value.get("Sequence").is_some() || json_value.get("sequence").is_some());

        // 3. Drill down into the PriceDataSeries
        let series = json_value
            .get("PriceDataSeries")
            .or_else(|| json_value.get("price_data_series"))
            .expect("PriceDataSeries field missing from deserialized JSON");

        assert!(series.is_array(), "PriceDataSeries should be an array");

        // 4. Validate the first element structure
        let first_entry = &series[0];
        let price_data = first_entry
            .get("PriceData")
            .or_else(|| first_entry.get("price_data"))
            .expect("Entry missing PriceData sub-object");

        assert!(price_data.get("BaseAsset").is_some() || price_data.get("base_asset").is_some());
        assert!(price_data.get("AssetPrice").is_some() || price_data.get("asset_price").is_some());
    }

    #[test]
    fn test_deserialize_tx_no_prefix() {
        // Same hex but removing the 53545800 prefix
        let encoded_hex = "1200332400de7a1c2f69897baf201b00e0ff2c20330000000168400000000000000c701c0863757272656e6379701d0d42616e642050726f746f636f6c81140e54d919c94cda274dde1cc05d5a49de2ccb0d51f018e0203017000040604ee8898d041009011a0000000000000000000000004254430000000000021a0000000000000000000000005553440000000000e1e0203017000001e5f24e2d80041009011a0000000000000000000000004554480000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9a2e0d041009011a524c555344000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b977670041009011a5553444300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e0203017000000003b9107cd041009011a5553445400000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000402a7e37b280041009011a5742544300000000000000000000000000000000021a0000000000000000000000005553440000000000e1e02030170000000055d7e4b2041009011a0000000000000000000000000000000000000000021a0000000000000000000000005553440000000000e1f1";
        let encoded_tx = hex::decode(encoded_hex).expect("Invalid hex");

        // Should still succeed because the match arms handle both cases
        let result = deserialize_tx(&encoded_tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_convert_base_quote_to_signal() {
        assert_eq!(convert_base_quote_to_signal("BTC", "USD"), "CS:BTC-USD");
        assert_eq!(convert_base_quote_to_signal("ETH", "EUR"), "CS:ETH-EUR");
        assert_eq!(convert_base_quote_to_signal("", ""), "CS:-");
    }

    #[test]
    fn test_hex_to_string() {
        // Case 1: Standard 3-character currency (e.g., XRP or USD in some systems)
        assert_eq!(hex_to_string("XRP").unwrap(), "XRP");

        // Case 2: Even length hex (BTC = 425443)
        assert_eq!(hex_to_string("425443").unwrap(), "BTC");

        // Case 3: Trailing zeros with even length (ETH + padding -> 45544800)
        // 45544800 -> trims to 455448 -> "ETH"
        assert_eq!(hex_to_string("45544800").unwrap(), "ETH");

        // Case 4: Character ending in 0 (P = 0x50)
        // "XRP" hex is 585250. Trimming trailing 0 results in 58525 (odd length)
        // Logic should re-attach the 0 to get 585250.
        assert_eq!(hex_to_string("585250").unwrap(), "XRP");

        // Case 5: Complex padding
        // "USDC" = 55534443. If padded with many zeros: 555344430000
        assert_eq!(hex_to_string("555344430000").unwrap(), "USDC");

        // Case 6: Invalid hex
        assert!(hex_to_string("GHI123").is_err());
    }

    #[test]
    fn test_str_to_u64() {
        // Standard case
        assert_eq!(str_to_u64("1000000000").unwrap(), 1_000_000_000u64);

        // Max u64
        assert_eq!(str_to_u64("18446744073709551615").unwrap(), u64::MAX);

        // Leading zeros
        assert_eq!(str_to_u64("000123").unwrap(), 123u64);

        // Error: Non-numeric
        assert!(str_to_u64("123a").is_err());

        // Error: Overflow
        assert!(str_to_u64("18446744073709551616").is_err());

        // Error: Empty string
        assert!(str_to_u64("").is_err());
    }
}
