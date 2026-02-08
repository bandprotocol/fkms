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
