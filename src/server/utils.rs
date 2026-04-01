use crate::codec::tss::TunnelSignalPrice;

/// Filters a signal to extract base asset from USD pairs with price > 0.
/// Expected format: "PREFIX:BASE-USD"
/// Returns Some((base_asset, price)) for valid USD pairs with price > 0, None otherwise.
pub fn filter_usd_signal(sp: &TunnelSignalPrice) -> Option<(String, u64)> {
    // Only process signals with price > 0
    if sp.price == 0 {
        return None;
    }

    let parts: Vec<&str> = sp.signal.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let base_quote: Vec<&str> = parts[1].split('-').collect();
    if base_quote.len() == 2 && base_quote[1] == "USD" && sp.price > 0 && base_quote[0] == "USDC" {
        Some((base_quote[0].to_string(), sp.price))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_usd_signal_valid_btc() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC-USD".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, Some(("BTC".to_string(), 65000)));
    }

    #[test]
    fn test_filter_usd_signal_valid_eth() {
        let signal = TunnelSignalPrice {
            signal: "CS:ETH-USD".to_string(),
            price: 3500,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, Some(("ETH".to_string(), 3500)));
    }

    #[test]
    fn test_filter_usd_signal_price_zero() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC-USD".to_string(),
            price: 0,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_price_one() {
        let signal = TunnelSignalPrice {
            signal: "CS:USDC-USD".to_string(),
            price: 1,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, Some(("USDC".to_string(), 1)));
    }

    #[test]
    fn test_filter_usd_signal_non_usd_pair() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC-EUR".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_missing_colon() {
        let signal = TunnelSignalPrice {
            signal: "CS-USD".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_multiple_colons() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC:USD".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_missing_dash() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTCUSD".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_empty_base() {
        let signal = TunnelSignalPrice {
            signal: ":-USD".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, Some(("".to_string(), 65000)));
    }

    #[test]
    fn test_filter_usd_signal_multiple_dashes() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC-USD-TEST".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_lowercase() {
        let signal = TunnelSignalPrice {
            signal: "cs:btc-usd".to_string(),
            price: 65000,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, None);
    }

    #[test]
    fn test_filter_usd_signal_large_price() {
        let signal = TunnelSignalPrice {
            signal: "CS:BTC-USD".to_string(),
            price: u64::MAX,
        };
        let result = filter_usd_signal(&signal);
        assert_eq!(result, Some(("BTC".to_string(), u64::MAX)));
    }
}
