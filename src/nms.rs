//! NMS interface monitoring math (pure core). Turns SNMP interface counter
//! samples into bandwidth and utilization, handling counter wrap, and applies
//! thresholds / link-state to a verdict. The SNMP walk that produces the
//! samples and the sample storage are separate layers; this is unit-tested with
//! no devices.

use serde::Serialize;

/// Delta between two monotonic counter reads, accounting for wrap at
/// `width_bits` (32 for ifInOctets, 64 for ifHCInOctets).
pub fn counter_delta(prev: u64, cur: u64, width_bits: u32) -> u64 {
    if cur >= prev {
        return cur - prev;
    }
    // Wrapped: (2^width - prev + cur) mod 2^width.
    let width = width_bits.clamp(1, 64);
    if width == 64 {
        // 2^64 doesn't fit u64; compute in u128.
        let modulus: u128 = 1u128 << 64;
        ((modulus - prev as u128 + cur as u128) % modulus) as u64
    } else {
        let modulus: u128 = 1u128 << width;
        (((cur as u128) + modulus - (prev as u128)) % modulus) as u64
    }
}

/// Bits per second from two octet reads `delta_seconds` apart. `None` when the
/// interval is not positive.
pub fn bandwidth_bps(
    prev_octets: u64,
    cur_octets: u64,
    delta_seconds: f64,
    width_bits: u32,
) -> Option<f64> {
    if delta_seconds.is_nan() || delta_seconds <= 0.0 {
        return None;
    }
    let bytes = counter_delta(prev_octets, cur_octets, width_bits) as f64;
    Some(bytes * 8.0 / delta_seconds)
}

/// Link utilization percentage given throughput and link speed (bps). `None`
/// when the speed is unknown/zero. Capped at 100 to absorb counter jitter.
pub fn utilization_pct(bps: f64, speed_bps: f64) -> Option<f64> {
    if speed_bps.is_nan() || speed_bps <= 0.0 {
        return None;
    }
    Some((bps / speed_bps * 100.0).min(100.0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IfVerdict {
    Ok,
    Warn,
    Critical,
    Down,
}

/// Verdict for an interface: Down wins over any utilization band; otherwise
/// util% against warn/crit thresholds. Unknown utilization reads as Ok (no
/// speed to judge against).
pub fn evaluate(util_pct: Option<f64>, oper_up: bool, warn_pct: f64, crit_pct: f64) -> IfVerdict {
    if !oper_up {
        return IfVerdict::Down;
    }
    match util_pct {
        Some(u) if u >= crit_pct => IfVerdict::Critical,
        Some(u) if u >= warn_pct => IfVerdict::Warn,
        _ => IfVerdict::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_delta_and_wrap() {
        assert_eq!(counter_delta(100, 150, 64), 50);
        // 32-bit wrap: prev near max, cur small.
        assert_eq!(counter_delta(u32::MAX as u64 - 9, 0, 32), 10);
        // 64-bit wrap.
        assert_eq!(counter_delta(u64::MAX - 4, 5, 64), 10);
    }

    #[test]
    fn bandwidth_and_utilization() {
        // 1_000_000 bytes in 10s = 800_000 bps.
        let bps = bandwidth_bps(0, 1_000_000, 10.0, 64).unwrap();
        assert!((bps - 800_000.0).abs() < 1.0);
        // on a 1 Mbit/s link that's 80%.
        let u = utilization_pct(bps, 1_000_000.0).unwrap();
        assert!((u - 80.0).abs() < 0.01);
        // non-positive interval / unknown speed -> None
        assert!(bandwidth_bps(0, 10, 0.0, 64).is_none());
        assert!(utilization_pct(500.0, 0.0).is_none());
    }

    #[test]
    fn utilization_capped_at_100() {
        assert_eq!(utilization_pct(2_000_000.0, 1_000_000.0).unwrap(), 100.0);
    }

    #[test]
    fn verdict_prioritises_down_then_thresholds() {
        assert_eq!(evaluate(Some(10.0), false, 70.0, 90.0), IfVerdict::Down);
        assert_eq!(evaluate(Some(95.0), true, 70.0, 90.0), IfVerdict::Critical);
        assert_eq!(evaluate(Some(75.0), true, 70.0, 90.0), IfVerdict::Warn);
        assert_eq!(evaluate(Some(10.0), true, 70.0, 90.0), IfVerdict::Ok);
        assert_eq!(evaluate(None, true, 70.0, 90.0), IfVerdict::Ok);
    }
}
