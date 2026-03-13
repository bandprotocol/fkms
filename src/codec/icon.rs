use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconTx {
    pub version: String,
    pub from: String,
    pub to: String,
    pub timestamp: String,
    pub step_limit: String,
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
    resolved_time: i64,
    request_id: u64,
) -> anyhow::Result<Value> {
    Ok(json!({
        "version": "0x3",
        "from": relayer,
        "to": contract_address,
        "timestamp": format!("0x{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_micros()),
        "stepLimit": format!("0x{:x}", step_limit),
        "nid": network_id,
        "dataType": "call",
        "data": {
            "method": "relay",
            "params": {
                "symbols": signals.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>(),
                "rates": signals.iter().map(|(_, p)| format!("0x{p:x}")).collect::<Vec<_>>(),
                "resolveTime": format!("0x{:x}", resolved_time),
                "requestID": format!("0x{:x}", request_id),
            }
        }
    }))
}

pub fn decode_tx(encoded_tx: &[u8]) -> anyhow::Result<IconTx> {
    let tx_json: Value =
        serde_json::from_slice(encoded_tx).with_context(|| "Failed to parse transaction JSON")?;

    let tx: IconTx =
        serde_json::from_value(tx_json).with_context(|| "Failed to deserialize transaction")?;

    Ok(tx)
}

pub fn encode_tx_for_signing(tx: &IconTx) -> anyhow::Result<Vec<u8>> {
    // Create a copy of the transaction without signature for signing
    let mut tx_for_signing =
        serde_json::to_value(tx).with_context(|| "Failed to serialize transaction for signing")?;

    // Remove signature field if it exists
    if let Some(obj) = tx_for_signing.as_object_mut() {
        obj.remove("signature");
    }

    let serialized = serde_json::to_string(&tx_for_signing)
        .with_context(|| "Failed to serialize transaction to string")?;

    // Prepend "icx_sendTransaction." as per ICON specification
    let message = format!("icx_sendTransaction.{serialized}");

    Ok(message.into_bytes())
}

pub fn sign_tx(tx: &mut IconTx, signature: &[u8]) -> anyhow::Result<Vec<u8>> {
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
    use serde_json::json;

    #[test]
    fn test_decode_tx() {
        let tx_json = json!({
            "version": "0x3",
            "from": "hx123...",
            "to": "cx456...",
            "timestamp": "0x123456789",
            "stepLimit": "0x100000",
            "nid": "0x1",
            "dataType": "call",
            "data": {
                "method": "relay",
                "params": {
                    "symbols": ["BTC", "ETH"],
                    "rates": ["50000", "3000"],
                    "resolveTime": "1234567890",
                    "requestID": "123"
                }
            }
        });

        let encoded = serde_json::to_vec(&tx_json).unwrap();
        let tx = decode_tx(&encoded).unwrap();

        assert_eq!(tx.version, "0x3");
        assert_eq!(tx.from, "hx123...");
        assert_eq!(tx.to, "cx456...");
        assert_eq!(tx.timestamp, "0x123456789");
        assert_eq!(tx.step_limit, "0x100000");
        assert_eq!(tx.nid, "0x1");
        assert_eq!(tx.data_type, "call");
        assert_eq!(tx.data.method, "relay");
        assert_eq!(tx.data.params.symbols, vec!["BTC", "ETH"]);
        assert_eq!(tx.data.params.rates, vec!["50000", "3000"]);
        assert_eq!(tx.data.params.resolve_time, "1234567890");
        assert_eq!(tx.data.params.request_id, "123");
    }

    #[test]
    fn test_encode_tx_for_signing() {
        let tx = IconTx {
            version: "0x3".to_string(),
            from: "hx123...".to_string(),
            to: "cx456...".to_string(),
            timestamp: "0x123456789".to_string(),
            step_limit: "0x100000".to_string(),
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
        };

        let signing_data = encode_tx_for_signing(&tx).unwrap();
        let signing_str = String::from_utf8(signing_data).unwrap();

        // Should start with "icx_sendTransaction."
        assert!(signing_str.starts_with("icx_sendTransaction."));

        // Should contain all fields except signature
        assert!(signing_str.contains(r#""version":"0x3""#));
        assert!(signing_str.contains(r#""from":"hx123...""#));
        assert!(signing_str.contains(r#""to":"cx456...""#));
        assert!(signing_str.contains(r#""timestamp":"0x123456789""#));
        assert!(signing_str.contains(r#""stepLimit":"0x100000""#));
        assert!(signing_str.contains(r#""nid":"0x1""#));
        assert!(signing_str.contains(r#""dataType":"call""#));
        assert!(signing_str.contains(r#""method":"relay""#));
        assert!(signing_str.contains(r#""symbols":["BTC","ETH"]"#));
        assert!(signing_str.contains(r#""rates":["50000","3000"]"#));
        assert!(signing_str.contains(r#""resolveTime":"1234567890""#));
        assert!(signing_str.contains(r#""requestID":"123""#));
        assert!(!signing_str.contains("signature"));
    }
}
