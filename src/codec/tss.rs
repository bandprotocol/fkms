use std::str;

use alloy_sol_types::{SolValue, sol};
use anyhow::Context;

const ENCODER_FIXED_POINT_ABI_PREFIX: &[u8] = &[0xcb, 0xa0, 0xad, 0x5a];
const ENCODER_TICK_ABI_PREFIX: &[u8] = &[0xdb, 0x99, 0xb2, 0xb3];

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
    encoding_prefix: Vec<u8>,
    packet: Packet,
}

pub fn decode_tss_message(tss_message: &[u8]) -> anyhow::Result<TssMessage> {
    let encoding_prefix = tss_message
        .get(TSS_HEADER_LEN..TSS_HEADER_LEN + 4)
        .with_context(|| "Missing encoding prefix")?
        .to_vec();
    let packet_data = tss_message
        .get(TSS_HEADER_LEN + 4..)
        .with_context(|| "Missing packet data")?
        .to_vec();

    let packet: Packet =
        SolValue::abi_decode_validate(&packet_data).with_context(|| "Failed to decode abi")?;

    Ok(TssMessage {
        encoding_prefix,
        packet,
    })
}

impl TssMessage {
    pub fn signal_prices(&self) -> anyhow::Result<Vec<(String, u64)>> {
        // Validate encoding type and determine if tick encoding is used
        let is_tick_encoding = match self.encoding_prefix.as_slice() {
            ENCODER_TICK_ABI_PREFIX => true,
            ENCODER_FIXED_POINT_ABI_PREFIX => false,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown encoding prefix: {:02x}{:02x}{:02x}{:02x}",
                    self.encoding_prefix[0],
                    self.encoding_prefix[1],
                    self.encoding_prefix[2],
                    self.encoding_prefix[3]
                ));
            }
        };

        let mut prices = Vec::with_capacity(self.packet.signals.len());

        for signal_price in &self.packet.signals {
            // trim leading 0x00 bytes
            let start = signal_price
                .signal
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(signal_price.signal.len());
            let signal_id_bytes = &signal_price.signal[start..];

            let signal_id = str::from_utf8(signal_id_bytes)
                .with_context(|| "Failed to parse signal_id due to invalid utf8")?
                .to_string();

            let price = if is_tick_encoding && signal_price.price != 0 {
                // Convert tick to price
                tick_to_price(signal_price.price)?
            } else {
                // Use price as-is for fixed point encoding and unavailable case
                signal_price.price
            };

            prices.push((signal_id, price));
        }

        Ok(prices)
    }
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
