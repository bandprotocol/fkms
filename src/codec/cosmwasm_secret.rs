use anyhow::{Context, Result, anyhow};
use cmac::{Cmac, Mac};
use cosmrs::{
    AccountId, Any,
    crypto::secp256k1,
    tx::{Body, Fee, SignDoc, SignerInfo},
};
use hkdf::Hkdf;
use prost::Message;
use rand::RngCore;
use serde_json::json;
use sha2::Sha256;
use std::str;
use x25519_dalek::{PublicKey, StaticSecret};

use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

const HKDF_SALT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x4b, 0xea, 0xd8, 0xdf, 0x69, 0x99,
    0x08, 0x52, 0xc2, 0x02, 0xdb, 0x0e, 0x00, 0x97, 0xc1, 0xa1, 0x2e, 0xa6, 0x37, 0xd7, 0xe9, 0x6d,
];

// Secret compute uses this exact type url for MsgExecuteContract.
const SECRET_MSG_EXECUTE_CONTRACT_TYPE_URL: &str = "/secret.compute.v1beta1.MsgExecuteContract";

// ---- Protobuf types (minimal subset) ----

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Coin {
    #[prost(string, tag = "1")]
    pub denom: String,
    #[prost(string, tag = "2")]
    pub amount: String,
}

// Matches: secret.compute.v1beta1.MsgExecuteContract
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgExecuteContract {
    // sender sdk.AccAddress (20 bytes)
    #[prost(bytes, tag = "1")]
    pub sender: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub contract: Vec<u8>,
    // encrypted bytes (nonce||pubkey||ciphertext)
    #[prost(bytes, tag = "3")]
    pub msg: Vec<u8>,
    // optional on chain; empty is fine
    #[prost(string, tag = "4")]
    pub callback_code_hash: String,
    // repeated sent_funds; empty for oracle relays
    #[prost(message, repeated, tag = "5")]
    pub sent_funds: Vec<Coin>,
    #[prost(bytes, tag = "6")]
    pub callback_sig: Vec<u8>,
}

// ---- Public helpers used by fkms service.rs ----

pub fn secret_execute_msg_json(
    symbols: Vec<String>,
    rates: Vec<u64>,
    resolve_time: u64,
    request_id: u64,
) -> Result<Vec<u8>> {
    let rates_str = rates.iter().map(|r| r.to_string()).collect::<Vec<String>>();
    let obj = json!({
        "relay": {
            "symbols": symbols,
            "rates": rates_str,
            "resolve_time": resolve_time,
            "request_id": request_id,
        }
    });

    serde_json::to_vec(&obj).context("failed to serialize secret execute msg json")
}

pub fn decode_acc_address_bech32(addr: &str) -> Result<Vec<u8>> {
    let account_id: AccountId = addr
        .parse()
        .map_err(|e| anyhow!("failed to parse bech32 account id: {e}"))?;
    let bytes = account_id.to_bytes();
    if bytes.len() != 20 {
        return Err(anyhow!(
            "invalid account address length: expected 20 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

pub fn encrypt_secret_execute_msg(
    code_hash: &str,
    encryption_pubkey_hex: &str,
    execute_msg_json: &[u8],
) -> Result<Vec<u8>> {
    let encryption_pubkey_hex = encryption_pubkey_hex.trim_start_matches("0x");
    let receiver_pubkey_bytes =
        hex::decode(encryption_pubkey_hex).with_context(|| "invalid hex pubkey")?;
    if receiver_pubkey_bytes.len() != 32 {
        return Err(anyhow!(
            "invalid x25519 pubkey length: expected 32, got {}",
            receiver_pubkey_bytes.len()
        ));
    }
    let receiver_pubkey = PublicKey::from(
        <[u8; 32]>::try_from(receiver_pubkey_bytes.as_slice())
            .map_err(|_| anyhow!("pubkey should be 32 bytes"))?,
    );

    let mut plaintext = Vec::with_capacity(code_hash.len() + execute_msg_json.len());
    plaintext.extend_from_slice(code_hash.as_bytes());
    plaintext.extend_from_slice(execute_msg_json);

    offline_encrypt_secret_message(&plaintext, &receiver_pubkey)
}

pub fn sign_secret_tx(
    signer_private_key: &[u8],
    sender_address_bech32: &str,
    contract_address_bech32: &str,
    encrypted_execute_msg: Vec<u8>,
    chain_id: &str,
    account_number: u64,
    sequence: u64,
    gas_limit: u64,
    gas_prices: &str,
    memo: &str,
) -> Result<Vec<u8>> {
    let sender_bytes = decode_acc_address_bech32(sender_address_bech32)?;
    let contract_bytes = decode_acc_address_bech32(contract_address_bech32)?;

    // Build secret MsgExecuteContract protobuf bytes.
    let msg = MsgExecuteContract {
        sender: sender_bytes,
        contract: contract_bytes,
        msg: encrypted_execute_msg,
        callback_code_hash: "".to_string(),
        sent_funds: vec![],
        callback_sig: vec![],
    };
    let msg_bytes = msg.encode_to_vec();

    let msg_any = Any {
        type_url: SECRET_MSG_EXECUTE_CONTRACT_TYPE_URL.to_string(),
        value: msg_bytes,
    };

    let tx_body = Body::new(vec![msg_any], memo.to_string(), 0u16);

    let fee_coin = parse_gas_prices_to_fee_coin(gas_prices, gas_limit)?;
    let signing_key = secp256k1::SigningKey::from_slice(signer_private_key)
        .map_err(|e| anyhow!("invalid signer private key: {e}"))?;

    let signer_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence);

    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(fee_coin, gas_limit));

    let chain_id = chain_id
        .parse()
        .map_err(|e| anyhow!("invalid chain_id {chain_id}: {e}"))?;

    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)
        .map_err(|e| anyhow!("failed to create SignDoc: {e}"))?;
    let tx_signed = sign_doc
        .sign(&signing_key)
        .map_err(|e| anyhow!("failed to sign SignDoc: {e}"))?;

    tx_signed
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize signed tx: {e}"))
}

fn offline_encrypt_secret_message(
    plaintext: &[u8],
    receiver_pubkey: &PublicKey,
) -> Result<Vec<u8>> {
    // 1) Generate txSender priv/pub
    // 2) Generate nonce(32)
    // 3) hkdf(txEncryptionIkm = X25519(txSenderPrivKey, receiverPubKey) || nonce, hkdfSalt)
    // 4) encryptData(AES-CMAC-SIV, aesEncryptionKey, txSenderPubKey, plaintext, nonce)
    // 5) output = nonce(32) || txSenderPubKey(32) || ciphertext

    let mut tx_sender_privkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut tx_sender_privkey);
    let tx_sender_static = StaticSecret::from(tx_sender_privkey);
    let tx_sender_pubkey = PublicKey::from(&tx_sender_static);

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let tx_encryption_ikm = tx_sender_static.diffie_hellman(receiver_pubkey);

    let mut ikm = Vec::with_capacity(32 + 32);
    ikm.extend_from_slice(tx_encryption_ikm.as_bytes());
    ikm.extend_from_slice(&nonce);

    let hk = Hkdf::<Sha256>::new(Some(&HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;

    let aes_encryption_key = okm; // 32 bytes

    let ciphertext = encrypt_data_cmac_siv(&aes_encryption_key, plaintext)?;

    let mut out = Vec::with_capacity(32 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(tx_sender_pubkey.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn encrypt_data_cmac_siv(aes_encryption_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (cmac_key, ctr_key) = aes_encryption_key.split_at(16);
    let cmac_key: &[u8; 16] = cmac_key.try_into().expect("16 bytes");
    let ctr_key: &[u8; 16] = ctr_key.try_into().expect("16 bytes");

    // Associated data items list contains a single empty slice.
    let associated_data_items: Vec<&[u8]> = vec![&[]];
    let siv_tag = s2v_aes_cmac_siv(cmac_key, &associated_data_items, plaintext)?;

    // SIV => CTR IV with top bits cleared in last two 32-bit words.
    let mut ctr_iv = siv_tag;
    zero_iv_bits(&mut ctr_iv);

    // Encrypt with AES-CTR, producing ciphertext = siv_tag || encrypted(plaintext)
    let mut buf = plaintext.to_vec();
    let mut stream_cipher = Ctr128BE::<Aes128>::new_from_slices(ctr_key, &ctr_iv)
        .map_err(|e| anyhow!("failed to create AES-CTR cipher: {e}"))?;
    stream_cipher.apply_keystream(&mut buf);

    let mut out = Vec::with_capacity(16 + buf.len());
    out.extend_from_slice(&siv_tag);
    out.extend_from_slice(&buf);

    Ok(out)
}

fn zero_iv_bits(iv: &mut [u8; 16]) {
    // "We zero-out the top bit in each of the last two 32-bit words of the IV"
    // — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv[16 - 8] &= 0x7f;
    iv[16 - 4] &= 0x7f;
}

fn s2v_aes_cmac_siv(
    cmac_key: &[u8; 16],
    associated_data_items: &[&[u8]],
    plaintext: &[u8],
) -> Result<[u8; 16]> {
    // Port of miscreant.go's Cipher.s2v for AES-CMAC-SIV-256.
    // block size is 16.
    let block_size = 16usize;
    let zeros = [0u8; 16];
    let mut d = cmac_digest(cmac_key, &zeros)?;

    for v in associated_data_items {
        let tmp = cmac_digest(cmac_key, v)?;
        d = dbl_128(&d);
        xor_inplace(&mut d, &tmp);
    }

    if plaintext.len() >= block_size {
        let n = plaintext.len() - block_size;
        let mut mac = cmac_init(cmac_key)?;
        mac.update(&plaintext[..n]);

        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(&plaintext[n..]);
        xor_inplace(&mut tmp, &d);
        mac.update(&tmp);

        let result = mac.finalize().into_bytes();
        Ok(result.into())
    } else {
        let mut tmp = [0u8; 16];
        tmp[..plaintext.len()].copy_from_slice(plaintext);
        tmp[plaintext.len()] = 0x80;
        let d2 = dbl_128(&d);
        xor_inplace(&mut tmp, &d2);

        let mut mac = cmac_init(cmac_key)?;
        mac.update(&tmp);
        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }
}

fn xor_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn dbl_128(d: &[u8; 16]) -> [u8; 16] {
    // CMAC subkey doubling in GF(2^128) with Rb=0x87.
    let msb = (d[0] & 0x80) != 0;
    let mut out = [0u8; 16];

    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (d[i] << 1) | carry;
        carry = if (d[i] & 0x80) != 0 { 1 } else { 0 };
    }

    if msb {
        out[15] ^= 0x87;
    }
    out
}

fn cmac_init(key: &[u8; 16]) -> Result<Cmac<Aes128>> {
    let mac = Cmac::<Aes128>::new_from_slice(key).map_err(|e| anyhow!("CMAC init failed: {e}"))?;
    Ok(mac)
}

fn cmac_digest(key: &[u8; 16], data: &[u8]) -> Result<[u8; 16]> {
    let mut mac = cmac_init(key)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

fn parse_gas_prices_to_fee_coin(gas_prices: &str, gas_limit: u64) -> Result<cosmrs::Coin> {
    let gas_prices = gas_prices.trim();
    if gas_prices.is_empty() {
        return Err(anyhow!("gas_prices is empty"));
    }

    // Split numeric part vs denom part.
    let mut idx = 0usize;
    for (i, ch) in gas_prices.char_indices() {
        if ch.is_ascii_digit() || ch == '.' {
            idx = i + ch.len_utf8();
        } else {
            break;
        }
    }
    if idx == 0 || idx >= gas_prices.len() {
        return Err(anyhow!("invalid gas_prices format: {gas_prices}"));
    }
    let (num_str, denom) = gas_prices.split_at(idx);
    let denom = denom.to_string();
    let num_str = num_str;

    let (int_part, frac_part) = if let Some(dot) = num_str.find('.') {
        (&num_str[..dot], &num_str[dot + 1..])
    } else {
        (num_str, "")
    };

    let scale: u128 = if frac_part.is_empty() {
        1
    } else {
        10u128.pow(frac_part.len() as u32)
    };

    let int_part_val: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse()?
    };
    let frac_part_val: u128 = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse()?
    };

    let amount_scaled = int_part_val
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("gas_prices amount overflow"))?
        .checked_add(frac_part_val)
        .ok_or_else(|| anyhow!("gas_prices amount overflow"))?;

    let fee_scaled = amount_scaled
        .checked_mul(gas_limit as u128)
        .ok_or_else(|| anyhow!("fee overflow"))?;
    let fee_amount = fee_scaled / scale;

    let coin = cosmrs::Coin {
        denom: denom
            .parse()
            .map_err(|e| anyhow!("invalid denom in gas_prices: {e}"))?,
        amount: fee_amount,
    };

    Ok(coin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_acc_address_bech32_length() {
        // This is just to ensure decoding/length logic works with a sample;
        // address correctness is not asserted here.
        // Replace with a real Secret Network address if needed.
        let _ = decode_acc_address_bech32("secret1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3d4r"); // should error
    }

    #[test]
    fn test_secret_execute_msg_json_shape() {
        let symbols = vec!["BTC".to_string(), "ETH".to_string()];
        let rates = vec![67758920310332u64, 1410834569u64];
        let json_bz = secret_execute_msg_json(symbols, rates, 10, 20).unwrap();
        let s = str::from_utf8(&json_bz).unwrap();
        assert!(s.contains("\"relay\""));
        assert!(s.contains("\"symbols\""));
        assert!(s.contains("\"rates\""));
        // resolve_time and request_id must be JSON numbers, not strings
        assert!(s.contains("\"resolve_time\":10"));
        assert!(s.contains("\"request_id\":20"));
    }
}
