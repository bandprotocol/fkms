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
    step_limit: i64,
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

    #[test]
    fn test_create_signing_payload() {
        let relayer = "hx123...";
        let contract_address = "cx456...";
        let step_limit = 100000;
        let signals = vec![("BTC".to_string(), 50000), ("ETH".to_string(), 3000)];
        let network_id = "0x1";
        let resolved_time = 1234567890;
        let request_id = 123;

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
    fn test_encode_tx_for_signing() {
        let tx = IconTx {
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
        };

        let signing_data = encode_tx_for_signing(&tx).unwrap();
        let signing_str = String::from_utf8(signing_data).unwrap();

        // Should start with "icx_sendTransaction."
        assert!(signing_str.starts_with("icx_sendTransaction."));

        // Should contain all fields except signature
        assert!(signing_str.contains(r#""version":"0x3""#));
        assert!(signing_str.contains(r#""from":"hx123...""#));
        assert!(signing_str.contains(r#""to":"cx456...""#));
        assert!(signing_str.contains(r#""timestamp":"0x1234567890""#));
        assert!(signing_str.contains(r#""stepLimit":"0x186a0""#));
        assert!(signing_str.contains(r#""nid":"0x1""#));
        assert!(signing_str.contains(r#""dataType":"call""#));
        assert!(signing_str.contains(r#""method":"relay""#));
        assert!(signing_str.contains(r#""symbols":["BTC","ETH"]"#));
        assert!(signing_str.contains(r#""rates":["50000","3000"]"#));
        assert!(signing_str.contains(r#""resolveTime":"1234567890""#));
        assert!(signing_str.contains(r#""requestID":"123""#));
        assert!(!signing_str.contains("signature"));
    }

    #[test]
    fn test_sign_tx() {
        let tx = IconTx {
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
        };

        let signature = vec![0x01, 0x02, 0x03, 0x04];
        let signed_tx = sign_tx(&tx, &signature).unwrap();
        let signed_tx_str = String::from_utf8(signed_tx).unwrap();

        // Should contain all original fields
        assert!(signed_tx_str.contains(r#""version":"0x3""#));
        assert!(signed_tx_str.contains(r#""from":"hx123...""#));
        assert!(signed_tx_str.contains(r#""to":"cx456...""#));
        assert!(signed_tx_str.contains(r#""timestamp":"0x1234567890""#));
        assert!(signed_tx_str.contains(r#""stepLimit":"0x186a0""#));
        assert!(signed_tx_str.contains(r#""nid":"0x1""#));
        assert!(signed_tx_str.contains(r#""dataType":"call""#));
        assert!(signed_tx_str.contains(r#""method":"relay""#));
        assert!(signed_tx_str.contains(r#""symbols":["BTC","ETH"]"#));
        assert!(signed_tx_str.contains(r#""rates":["50000","3000"]"#));
        assert!(signed_tx_str.contains(r#""resolveTime":"1234567890""#));
        assert!(signed_tx_str.contains(r#""requestID":"123""#));

        // Should contain signature field with base64 encoded value
        let expected_signature_b64 = general_purpose::STANDARD.encode(&signature);
        assert!(signed_tx_str.contains(&format!(r#""signature":"{expected_signature_b64}""#)));
    }
}
