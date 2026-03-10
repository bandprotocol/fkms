use std::str;

use alloy_sol_types::{SolValue, sol};
use anyhow::Context;

#[derive(Debug, PartialEq, Eq)]
enum EncodingType {
    FixedPoint,
    Tick,
}

// Constants for tick to price conversion
const TICK_OFFSET: u64 = 262144; // 2^18
// MAX_TICK is set to ensure 1.0001^(MAX_TICK - TICK_OFFSET) * 10^9 never exceeds u64::MAX
const MAX_TICK: u64 = 498537;

// TSS message layout constants
// The TSS message layout:
// - Bytes 0-51: TSS header (52 bytes of header fields - signatures, metadata, etc.)
// - Bytes 52-55: encoding type prefix (4 bytes - fixed point or tick encoding)
// - Bytes 56+: ABI encoded packet data
const TSS_HEADER_LEN: usize = 52;

const ENCODER_FIXED_POINT_ABI_PREFIX: [u8; 4] = [0xcb, 0xa0, 0xad, 0x5a];
const ENCODER_TICK_ABI_PREFIX: [u8; 4] = [0xdb, 0x99, 0xb2, 0xb3];

sol! {
    struct SignalPrice {
        bytes32 signal;
        uint64 price;
    }
}

sol! {
    struct Packet {
        uint64 sequence;
        SignalPrice[] signals;
        int64 timestamp;
    }
}

pub struct TssMessage {
    pub packet: TunnelPacket,
}

#[derive(Clone)]
pub struct TunnelPacket {
    pub sequence: u64,
    pub signals: Vec<TunnelSignalPrice>,
    pub timestamp: i64,
}

#[derive(Clone)]
pub struct TunnelSignalPrice {
    pub signal: String,
    pub price: u64,
}

pub fn decode_tss_message(tss_message: &[u8]) -> anyhow::Result<TssMessage> {
    let encoding_prefix = tss_message
        .get(TSS_HEADER_LEN..TSS_HEADER_LEN + 4)
        .with_context(|| "Missing encoding prefix")?;
    let packet_data = tss_message
        .get(TSS_HEADER_LEN + 4..)
        .with_context(|| "Missing packet data")?;

    let encoding_type = match encoding_prefix.try_into() {
        Ok(ENCODER_FIXED_POINT_ABI_PREFIX) => EncodingType::FixedPoint,
        Ok(ENCODER_TICK_ABI_PREFIX) => EncodingType::Tick,
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown encoding prefix: {:02x}{:02x}{:02x}{:02x}",
                encoding_prefix[0],
                encoding_prefix[1],
                encoding_prefix[2],
                encoding_prefix[3]
            ));
        }
    };

    let packet: Packet =
        SolValue::abi_decode_validate(packet_data).with_context(|| "Failed to decode abi")?;

    let tunnel_packet = decode_packet(packet, &encoding_type)?;

    Ok(TssMessage {
        packet: tunnel_packet,
    })
}

fn decode_packet(packet: Packet, encoding_type: &EncodingType) -> anyhow::Result<TunnelPacket> {
    let is_tick_encoding = *encoding_type == EncodingType::Tick;

    let mut signals = Vec::with_capacity(packet.signals.len());

    for sp in packet.signals {
        // Trim leading 0x00 bytes from the fixed-width bytes32 signal ID
        let raw: [u8; 32] = sp.signal.into();
        let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
        let signal_id = str::from_utf8(&raw[start..])
            .with_context(|| "Failed to parse signal_id due to invalid utf8")?
            .to_string();

        let price = if is_tick_encoding && sp.price != 0 {
            tick_to_price(sp.price)?
        } else {
            sp.price
        };

        signals.push(TunnelSignalPrice {
            signal: signal_id,
            price,
        });
    }

    Ok(TunnelPacket {
        sequence: packet.sequence,
        signals,
        timestamp: packet.timestamp,
    })
}

/// Converts the tick to a price with 10^9 precision.
/// Calculates 1.0001^(tick - TICK_OFFSET) using an efficient power function.
/// MAX_TICK is set low enough to guarantee no u64 overflow.
fn tick_to_price(tick: u64) -> anyhow::Result<u64> {
    if tick < 1 {
        return Err(anyhow::anyhow!("tick below threshold: {} < 1", tick));
    }
    if tick > MAX_TICK {
        return Err(anyhow::anyhow!(
            "tick above threshold: {} > {}",
            tick,
            MAX_TICK
        ));
    }

    // Calculate the effective tick after subtracting the offset
    let effective_tick = tick as i64 - TICK_OFFSET as i64;

    // Use f64::powf for efficient calculation
    let tick_const = 1.0001_f64;
    let price_ratio = tick_const.powf(effective_tick as f64);

    // Check for invalid result (overflow shouldn't happen due to MAX_TICK constraint)
    if !price_ratio.is_finite() || price_ratio <= 0.0 {
        return Err(anyhow::anyhow!(
            "price calculation resulted in invalid value"
        ));
    }

    // Scale to 10^9 precision
    let price_scaled = price_ratio * 1_000_000_000.0;

    // Convert to u64 (no overflow possible due to MAX_TICK constraint)
    let price_u64 = price_scaled.round() as u64;

    // Ensure tick-encoded prices never round to 0 to prevent bypassing price checks
    if price_u64 == 0 {
        return Err(anyhow::anyhow!(
            "tick {} produces price that rounds to 0, which could bypass comparison checks",
            tick
        ));
    }

    Ok(price_u64)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tick_to_price_conversion() {
        // Test tick at offset (should give price = 1.0 * 10^9)
        let price_offset = tick_to_price(TICK_OFFSET).expect("Failed to convert offset tick");
        assert_eq!(price_offset, 1_000_000_000); // Should be exactly 1.0 with 10^9 precision

        // Test positive effective tick (tick > TICK_OFFSET)
        let tick_positive = TICK_OFFSET + 1;
        let price_positive = tick_to_price(tick_positive).expect("Failed to convert positive tick");

        // Test negative effective tick (tick < TICK_OFFSET)
        let tick_negative = TICK_OFFSET - 1;
        let price_negative = tick_to_price(tick_negative).expect("Failed to convert negative tick");

        // Basic assertions
        assert!(price_offset > 0);
        assert!(
            price_positive > price_offset,
            "Expected {} > {}",
            price_positive,
            price_offset
        );
        assert!(
            price_negative < price_offset,
            "Expected {} < {}",
            price_negative,
            price_offset
        );

        // Test tick below threshold should return error
        let result = tick_to_price(0u64);
        assert!(result.is_err());

        // Test tick above threshold should return error
        let result = tick_to_price(MAX_TICK + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_prices_fixed_point_encoding() {
        // Create test packet with fixed point encoding
        let packet = Packet {
            sequence: 123u64,
            signals: vec![
                SignalPrice {
                    signal: {
                        let mut signal = [0u8; 32];
                        let signal_str = b"BTC-USD";
                        signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                        signal.into()
                    },
                    price: 50000000000000u64, // 50,000 with 10^9 precision
                },
                SignalPrice {
                    signal: {
                        let mut signal = [0u8; 32];
                        let signal_str = b"ETH-USD";
                        signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                        signal.into()
                    },
                    price: 3000000000000u64, // 3,000 with 10^9 precision
                },
            ],
            timestamp: 1234567890i64,
        };

        // Encode packet
        let packet_encoded = packet.abi_encode();

        // Create TSS message with fixed point prefix
        let mut tss_message = vec![0x00; TSS_HEADER_LEN];
        tss_message.extend_from_slice(&ENCODER_FIXED_POINT_ABI_PREFIX); // Fixed point prefix
        tss_message.extend_from_slice(&packet_encoded);

        // Test extraction
        let result = decode_tss_message(&tss_message).expect("Failed to decode tss message");

        let signals = &result.packet.signals;
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].signal, "BTC-USD");
        assert_eq!(signals[0].price, 50000000000000u64);
        assert_eq!(signals[1].signal, "ETH-USD");
        assert_eq!(signals[1].price, 3000000000000u64);
    }

    #[test]
    fn test_extract_prices_tick_encoding() {
        // Create test packet with tick encoding
        let packet = Packet {
            sequence: 456u64,
            signals: vec![
                SignalPrice {
                    signal: {
                        let mut signal = [0u8; 32];
                        let signal_str = b"USDC-USD";
                        signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                        signal.into()
                    },
                    price: TICK_OFFSET, // Tick at offset (should give 1.0)
                },
                SignalPrice {
                    signal: {
                        let mut signal = [0u8; 32];
                        let signal_str = b"DAI-USD";
                        signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                        signal.into()
                    },
                    price: (TICK_OFFSET + 100), // Tick slightly above offset
                },
            ],
            timestamp: 9876543210i64,
        };

        // Encode packet
        let packet_encoded = packet.abi_encode();

        // Create TSS message with tick encoding prefix
        let mut tss_message = vec![0x00; TSS_HEADER_LEN];
        tss_message.extend_from_slice(&ENCODER_TICK_ABI_PREFIX); // Tick encoding prefix
        tss_message.extend_from_slice(&packet_encoded);

        // Test extraction
        let result = decode_tss_message(&tss_message).expect("Failed to decode tss message");

        let signals = &result.packet.signals;
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].signal, "USDC-USD");
        assert_eq!(signals[0].price, 1_000_000_000u64); // Should be exactly 1.0 with 10^9 precision
        assert_eq!(signals[1].signal, "DAI-USD");
        // The second price should be slightly higher than 1.0 due to positive tick
        assert!(signals[1].price > 1_000_000_000u64);
    }

    #[test]
    fn test_decode_tss_message_unknown_encoding() {
        // Create test packet
        let packet = Packet {
            sequence: 789u64,
            signals: vec![SignalPrice {
                signal: {
                    let mut signal = [0u8; 32];
                    let signal_str = b"TEST-USD";
                    signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                    signal.into()
                },
                price: 1000u64,
            }],
            timestamp: 1111111111i64,
        };

        // Encode packet
        let packet_encoded = packet.abi_encode();

        // Create TSS message with unknown encoding prefix
        let mut tss_message = vec![0x00; TSS_HEADER_LEN];
        tss_message.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // Unknown prefix
        tss_message.extend_from_slice(&packet_encoded);

        // Test should return error for unknown encoding
        let result = decode_tss_message(&tss_message);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Unknown encoding prefix")
        );
    }

    #[test]
    fn test_extract_prices_tick_max_bound() {
        // Create test packet with tick value > MAX_TICK
        let packet = Packet {
            sequence: 999u64,
            signals: vec![SignalPrice {
                signal: {
                    let mut signal = [0u8; 32];
                    let signal_str = b"MAX-TICK-TEST";
                    signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                    signal.into()
                },
                price: MAX_TICK + 1, // This exceeds MAX_TICK bound
            }],
            timestamp: 2222222222i64,
        };

        // Encode packet
        let packet_encoded = packet.abi_encode();

        // Create TSS message with tick encoding prefix
        let mut tss_message = vec![0x00; TSS_HEADER_LEN];
        tss_message.extend_from_slice(&ENCODER_TICK_ABI_PREFIX);
        tss_message.extend_from_slice(&packet_encoded);

        // decode_tss_message now fails eagerly when tick is invalid
        let result = decode_tss_message(&tss_message);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("tick above threshold")
        );
    }

    #[test]
    fn test_extract_prices_tick_rounds_to_zero() {
        // Create test packet with tick=1 which produces price that rounds to 0
        let packet = Packet {
            sequence: 888u64,
            signals: vec![SignalPrice {
                signal: {
                    let mut signal = [0u8; 32];
                    let signal_str = b"ZERO-PRICE";
                    signal[32 - signal_str.len()..].copy_from_slice(signal_str);
                    signal.into()
                },
                price: 1u64, // This rounds to zero and should be rejected
            }],
            timestamp: 3333333333i64,
        };

        // Encode packet
        let packet_encoded = packet.abi_encode();

        // Create TSS message with tick encoding prefix
        let mut tss_message = vec![0x00; TSS_HEADER_LEN];
        tss_message.extend_from_slice(&ENCODER_TICK_ABI_PREFIX);
        tss_message.extend_from_slice(&packet_encoded);

        // decode_tss_message now fails eagerly when tick produces price of 0
        let result = decode_tss_message(&tss_message);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("rounds to 0"));
    }
}
