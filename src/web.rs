//! Web estate monitoring (pure core) for the ~200 client sites.
//!
//! Three testable cores: TLS-expiry → severity, security-header grading, and
//! content change/defacement detection (normalize + stable hash + baseline
//! diff). The live HTTPS GET and TLS peer-cert peek are the seam; they feed
//! these functions, which decide what to alert on — so a client changing their
//! site unexpectedly is caught.

use serde::Serialize;

use crate::domain::Severity;

/// Severity from days until certificate expiry (negative = already expired).
pub fn cert_expiry_severity(days: i64) -> Severity {
    if days < 0 {
        Severity::Critical
    } else if days <= 7 {
        Severity::High
    } else if days <= 14 {
        Severity::Medium
    } else if days <= 30 {
        Severity::Low
    } else {
        Severity::Info
    }
}

const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
];

/// Security headers absent from the response (given the present header names).
pub fn missing_security_headers(present: &[String]) -> Vec<&'static str> {
    let have: Vec<String> = present.iter().map(|s| s.to_ascii_lowercase()).collect();
    SECURITY_HEADERS
        .iter()
        .filter(|(h, _)| !have.iter().any(|p| p == h))
        .map(|(_, label)| *label)
        .collect()
}

/// A→F grade from how many of the five security headers are missing.
pub fn header_grade(missing_count: usize) -> char {
    match missing_count {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        _ => 'F',
    }
}

/// Collapse whitespace so cosmetic reformatting doesn't look like a change.
pub fn normalize_body(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Stable FNV-1a hash (hex). Stable across builds — baselines stay valid after
/// upgrades, unlike the std default hasher.
pub fn content_hash(normalized: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in normalized.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeVerdict {
    FirstBaseline,
    Unchanged,
    Changed,
}

pub fn change_verdict(baseline: Option<&str>, current: &str) -> ChangeVerdict {
    match baseline {
        None => ChangeVerdict::FirstBaseline,
        Some(b) if b == current => ChangeVerdict::Unchanged,
        Some(_) => ChangeVerdict::Changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_bands() {
        assert_eq!(cert_expiry_severity(-1), Severity::Critical);
        assert_eq!(cert_expiry_severity(3), Severity::High);
        assert_eq!(cert_expiry_severity(10), Severity::Medium);
        assert_eq!(cert_expiry_severity(25), Severity::Low);
        assert_eq!(cert_expiry_severity(90), Severity::Info);
    }

    #[test]
    fn header_grading() {
        let present = vec![
            "Strict-Transport-Security".to_string(),
            "X-Frame-Options".to_string(),
        ];
        let missing = missing_security_headers(&present);
        assert!(missing.contains(&"CSP"));
        assert!(!missing.contains(&"HSTS"));
        assert_eq!(missing.len(), 3);
        assert_eq!(header_grade(0), 'A');
        assert_eq!(header_grade(3), 'D');
        assert_eq!(header_grade(5), 'F');
    }

    #[test]
    fn normalize_ignores_whitespace_only_changes() {
        assert_eq!(
            normalize_body("<h1>Ciao</h1>\n  <p>x</p>"),
            normalize_body("<h1>Ciao</h1> <p>x</p>")
        );
        assert_eq!(
            content_hash(&normalize_body("a  b")),
            content_hash(&normalize_body("a\tb"))
        );
    }

    #[test]
    fn detects_real_content_change() {
        let base = content_hash(&normalize_body("<h1>Benvenuti</h1>"));
        let same = content_hash(&normalize_body("<h1>Benvenuti</h1>  "));
        let defaced = content_hash(&normalize_body("<h1>HACKED</h1>"));
        assert_eq!(change_verdict(None, &base), ChangeVerdict::FirstBaseline);
        assert_eq!(change_verdict(Some(&base), &same), ChangeVerdict::Unchanged);
        assert_eq!(
            change_verdict(Some(&base), &defaced),
            ChangeVerdict::Changed
        );
    }
}
