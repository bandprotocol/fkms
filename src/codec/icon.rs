use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconTx {
    pub version: String,
    pub from: String,
    pub to: String,
    pub step_limit: String,
    pub timestamp: String,
    pub nid: String,
    pub data_type: String,
    pub data: IconData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IconData {
    pub method: String,
    pub params: IconParams,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconParams {
    pub symbols: Vec<String>,
    pub rates: Vec<String>,
    pub resolve_time: String,
    #[serde(rename = "requestID")]
    pub request_id: String,
}

pub fn create_signing_payload(
    relayer: &str,
    contract_address: &str,
    step_limit: u64,
    signals: &[(String, u64)],
    network_id: &str,
    resolved_time: u64,
    request_id: u64,
) -> anyhow::Result<IconTx> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH when creating ICON signing payload")?
        .as_micros() as i64;
    let timestamp_hex = format!("0x{:x}", timestamp);
    let step_limit_hex = format!("0x{:x}", step_limit);
    Ok(IconTx {
        version: "0x3".to_string(),
        from: relayer.to_string(),
        to: contract_address.to_string(),
        timestamp: timestamp_hex,
        step_limit: step_limit_hex,
        nid: network_id.to_string(),
        data_type: "call".to_string(),
        data: IconData {
            method: "relay".to_string(),
            params: IconParams {
                symbols: signals.iter().map(|(s, _)| s.clone()).collect(),
                rates: signals.iter().map(|(_, r)| r.to_string()).collect(),
                resolve_time: resolved_time.to_string(),
                request_id: request_id.to_string(),
            },
        },
    })
}

/// Escape special characters in a string value per the ICON canonical serialization spec.
/// Backslash and period must be escaped with a leading backslash.
fn escape_icon_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '.' => out.push_str("\\."),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '[' => out.push_str("\\["),
            ']' => out.push_str("\\]"),
            '\0' => {} // null not allowed; skip
            _ => out.push(c),
        }
    }
    out
}

/// Serialize a JSON value using ICON's canonical serialization rules:
/// - String: escaped string
/// - Null: "\0"
/// - Array: "[v1.v2.v3]"
/// - Object: "{k1.v1.k2.v2}" with keys sorted alphabetically
fn serialize_icon_value(value: &Value) -> anyhow::Result<String> {
    match value {
        Value::Null => Ok("\\0".to_string()),
        Value::String(s) => Ok(escape_icon_string(s)),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(arr) => {
            let parts: anyhow::Result<Vec<String>> =
                arr.iter().map(serialize_icon_value).collect();
            Ok(format!("[{}]", parts?.join(".")))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for k in keys {
                let v = &obj[k];
                parts.push(escape_icon_string(k));
                parts.push(serialize_icon_value(v)?);
            }
            Ok(format!("{{{}}}", parts.join(".")))
        }
    }
}

/// Encode the transaction for signing using ICON's canonical serialization format.
///
/// The format matches goloop's `calcHash()`:
///   icx_sendTransaction.data.<canonical_data>.dataType.<type>.from.<addr>.nid.<id>
///   .stepLimit.<hex>.timestamp.<hex>.to.<addr>.version.<ver>
///
/// All top-level fields are appended in alphabetical order (data, dataType, from, nid,
/// stepLimit, timestamp, to, version).  The `data` field is serialized using the
/// ICON canonical object/array format.
pub fn encode_tx_for_signing(tx: &IconTx) -> anyhow::Result<Vec<u8>> {
    let mut out = String::new();
    out.push_str("icx_sendTransaction");

    // data field – serialize using canonical format
    let data_value = serde_json::to_value(&tx.data)
        .with_context(|| "Failed to serialize IconData to JSON value")?;
    let canonical_data = serialize_icon_value(&data_value)
        .with_context(|| "Failed to canonicalize IconData")?;
    out.push_str(".data.");
    out.push_str(&canonical_data);

    // dataType
    out.push_str(".dataType.");
    out.push_str(&escape_icon_string(&tx.data_type));

    // from
    out.push_str(".from.");
    out.push_str(&escape_icon_string(&tx.from));

    // nid
    out.push_str(".nid.");
    out.push_str(&escape_icon_string(&tx.nid));

    // stepLimit
    out.push_str(".stepLimit.");
    out.push_str(&escape_icon_string(&tx.step_limit));

    // timestamp
    out.push_str(".timestamp.");
    out.push_str(&escape_icon_string(&tx.timestamp));

    // to
    out.push_str(".to.");
    out.push_str(&escape_icon_string(&tx.to));

    // version
    out.push_str(".version.");
    out.push_str(&escape_icon_string(&tx.version));

    Ok(out.into_bytes())
}

pub fn sign_tx(tx: &IconTx, signature: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Encode signature as base64
    let signature_b64 = general_purpose::STANDARD.encode(signature);

    // Add signature to transaction
    let mut tx_value =
        serde_json::to_value(tx).with_context(|| "Failed to serialize transaction")?;

    if let Some(obj) = tx_value.as_object_mut() {
        obj.insert("signature".to_string(), Value::String(signature_b64));
    }

    let signed_tx =
        serde_json::to_vec(&tx_value).with_context(|| "Failed to encode signed transaction")?;

    Ok(signed_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx() -> IconTx {
        IconTx {
            version: "0x3".to_string(),
            from: "hx123...".to_string(),
            to: "cx456...".to_string(),
            timestamp: "0x1234567890".to_string(),
            step_limit: "0x186a0".to_string(),
            nid: "0x1".to_string(),
            data_type: "call".to_string(),
            data: IconData {
                method: "relay".to_string(),
                params: IconParams {
                    symbols: vec!["BTC".to_string(), "ETH".to_string()],
                    rates: vec!["50000".to_string(), "3000".to_string()],
                    resolve_time: "1234567890".to_string(),
                    request_id: "123".to_string(),
                },
            },
        }
    }

    #[test]
    fn test_create_signing_payload() {
        let relayer = "hx123...";
        let contract_address = "cx456...";
        let step_limit = 100000;
        let signals = vec![("BTC".to_string(), 50000u64), ("ETH".to_string(), 3000u64)];
        let network_id = "0x1";
        let resolved_time = 1234567890u64;
        let request_id = 123u64;

        let tx = create_signing_payload(
            relayer,
            contract_address,
            step_limit,
            &signals,
            network_id,
            resolved_time,
            request_id,
        )
        .unwrap();

        assert_eq!(tx.version, "0x3");
        assert_eq!(tx.from, relayer);
        assert_eq!(tx.to, contract_address);
        assert_eq!(tx.step_limit, "0x186a0"); // 100000 in hex
        assert_eq!(tx.nid, network_id);
        assert_eq!(tx.data_type, "call");
        assert_eq!(tx.data.method, "relay");
        assert_eq!(tx.data.params.symbols, vec!["BTC", "ETH"]);
        assert_eq!(tx.data.params.rates, vec!["50000", "3000"]);
        assert_eq!(tx.data.params.resolve_time, resolved_time.to_string());
        assert_eq!(tx.data.params.request_id, request_id.to_string());
    }

    #[test]
    fn test_encode_tx_for_signing_canonical_format() {
        let tx = make_test_tx();
        let signing_data = encode_tx_for_signing(&tx).unwrap();
        let signing_str = String::from_utf8(signing_data).unwrap();

        // Must start with "icx_sendTransaction"
        assert!(signing_str.starts_with("icx_sendTransaction"));

        // Must NOT contain raw JSON braces at the top level (not plain JSON)
        // The canonical format starts with "icx_sendTransaction.data.{..." not "icx_sendTransaction.{"
        assert!(signing_str.starts_with("icx_sendTransaction.data.{"));

        // Check field order: data, dataType, from, nid, stepLimit, timestamp, to, version
        let data_pos = signing_str.find(".data.").unwrap();
        let data_type_pos = signing_str.find(".dataType.").unwrap();
        let from_pos = signing_str.find(".from.").unwrap();
        let nid_pos = signing_str.find(".nid.").unwrap();
        let step_limit_pos = signing_str.find(".stepLimit.").unwrap();
        let timestamp_pos = signing_str.find(".timestamp.").unwrap();
        let to_pos = signing_str.find(".to.").unwrap();
        let version_pos = signing_str.find(".version.").unwrap();

        assert!(data_pos < data_type_pos);
        assert!(data_type_pos < from_pos);
        assert!(from_pos < nid_pos);
        assert!(nid_pos < step_limit_pos);
        assert!(step_limit_pos < timestamp_pos);
        assert!(timestamp_pos < to_pos);
        assert!(to_pos < version_pos);

        // Check that addresses appear (dots are escaped as "\." in canonical format)
        assert!(signing_str.contains("hx123\\.\\.\\."));
        assert!(signing_str.contains("cx456\\.\\.\\."));
        assert!(signing_str.contains("0x186a0"));
        assert!(signing_str.contains("0x1234567890"));
        assert!(signing_str.contains("0x1"));
        assert!(signing_str.contains("0x3"));

        // Must NOT contain "signature" in the signing payload
        assert!(!signing_str.contains("signature"));

        // Must NOT look like plain JSON (no top-level {"version":...})
        assert!(!signing_str.contains("{\"version\""));
    }

    #[test]
    fn test_encode_tx_for_signing_exact_output() {
        let tx = make_test_tx();
        let signing_data = encode_tx_for_signing(&tx).unwrap();
        let signing_str = String::from_utf8(signing_data).unwrap();

        // The from/to fields are "hx123..." and "cx456..." — the "." in them gets escaped as "\."
        // Let's build the expected string carefully:
        let expected = "icx_sendTransaction\
            .data.{method.relay.params.{rates.[50000.3000].requestID.123.resolveTime.1234567890.symbols.[BTC.ETH]}}\
            .dataType.call\
            .from.hx123\\.\\.\\.\
            .nid.0x1\
            .stepLimit.0x186a0\
            .timestamp.0x1234567890\
            .to.cx456\\.\\.\\.\
            .version.0x3";

        assert_eq!(signing_str, expected);
    }

    #[test]
    fn test_sign_tx() {
        let tx = make_test_tx();

        let signature = vec![0x01, 0x02, 0x03, 0x04];
        let signed_tx = sign_tx(&tx, &signature).unwrap();
        let signed_tx_str = String::from_utf8(signed_tx).unwrap();

        // Should contain all original fields in JSON form
        assert!(signed_tx_str.contains("\"version\":\"0x3\""));
        assert!(signed_tx_str.contains("\"from\":\"hx123...\""));
        assert!(signed_tx_str.contains("\"to\":\"cx456...\""));
        assert!(signed_tx_str.contains("\"timestamp\":\"0x1234567890\""));
        assert!(signed_tx_str.contains("\"stepLimit\":\"0x186a0\""));
        assert!(signed_tx_str.contains("\"nid\":\"0x1\""));
        assert!(signed_tx_str.contains("\"dataType\":\"call\""));
        assert!(signed_tx_str.contains("\"method\":\"relay\""));
        assert!(signed_tx_str.contains("\"symbols\":[\"BTC\",\"ETH\"]"));
        assert!(signed_tx_str.contains("\"rates\":[\"50000\",\"3000\"]"));
        assert!(signed_tx_str.contains("\"resolveTime\":\"1234567890\""));
        assert!(signed_tx_str.contains("\"requestID\":\"123\""));

        // Should contain signature field with base64 encoded value
        let expected_signature_b64 = general_purpose::STANDARD.encode(&signature);
        assert!(signed_tx_str.contains(&format!("\"signature\":\"{expected_signature_b64}\"")));
    }

    #[test]
    fn test_escape_icon_string() {
        // Dots get escaped
        assert_eq!(escape_icon_string("hx123.abc"), "hx123\\.abc");
        // Backslashes get escaped
        assert_eq!(escape_icon_string("a\\b"), "a\\\\b");
        // Braces get escaped
        assert_eq!(escape_icon_string("{foo}"), "\\{foo\\}");
        // Normal strings unchanged
        assert_eq!(escape_icon_string("helloworld"), "helloworld");
    }

    #[test]
    fn test_serialize_icon_value_array() {
        let v = serde_json::json!(["AVAX", "BTC", "ETH"]);
        let s = serialize_icon_value(&v).unwrap();
        assert_eq!(s, "[AVAX.BTC.ETH]");
    }

    #[test]
    fn test_serialize_icon_value_dict_sorted() {
        // Keys must come out sorted: b < a would be wrong; a < b is correct
        let v = serde_json::json!({"b": "2", "a": "1"});
        let s = serialize_icon_value(&v).unwrap();
        assert_eq!(s, "{a.1.b.2}");
    }
}
