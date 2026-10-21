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

/// First dotted-numeric version token (needs a dot), e.g. in "WordPress 6.4.2".
fn dotted(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            let tok = tok.trim_matches('.').to_string();
            if tok.contains('.') {
                return Some(tok);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The `<meta name="generator" content="...">` value, if present.
pub fn meta_generator(body: &str) -> Option<String> {
    let l = body.to_ascii_lowercase();
    let i = l
        .find("name=\"generator\"")
        .or_else(|| l.find("name='generator'"))?;
    let ci = l[i..].find("content=")? + i + "content=".len();
    let s = body.get(ci..)?;
    let q = s.as_bytes().first().copied()?;
    if q == b'"' || q == b'\'' {
        let end = s[1..].find(q as char)?;
        Some(s[1..1 + end].trim().to_string())
    } else {
        None
    }
}

/// Detect a common CMS from the Server / X-Generator headers and the body;
/// returns the CMS name and an optional version (from the generator meta tag).
pub fn detect_cms(server: &str, x_generator: &str, body: &str) -> Option<(String, Option<String>)> {
    let l = body.to_ascii_lowercase();
    let gen = meta_generator(body).unwrap_or_default();
    let gl = gen.to_ascii_lowercase();
    let xg = x_generator.to_ascii_lowercase();
    let sv = server.to_ascii_lowercase();
    if gl.contains("wordpress")
        || l.contains("wp-content")
        || l.contains("wp-includes")
        || l.contains("/wp-json")
    {
        return Some(("WordPress".into(), dotted(&gen)));
    }
    if gl.contains("joomla") || xg.contains("joomla") || l.contains("/media/jui/") {
        return Some(("Joomla".into(), dotted(&gen)));
    }
    if gl.contains("drupal")
        || xg.contains("drupal")
        || sv.contains("drupal")
        || l.contains("drupal.settings")
        || l.contains("/sites/all/")
    {
        return Some(("Drupal".into(), dotted(&gen)));
    }
    None
}

/// Raw `href`/`src` attribute values in the HTML — a cheap, case-insensitive
/// extractor good enough for a shallow same-host crawl. Values keep their case.
pub fn extract_hrefs(body: &str) -> Vec<String> {
    let lb = body.to_ascii_lowercase();
    let mut out = Vec::new();
    for attr in ["href=", "src="] {
        let mut from = 0;
        while let Some(rel) = lb[from..].find(attr) {
            let i = from + rel + attr.len();
            from = i;
            let Some(s) = body.get(i..) else { break };
            let Some(&q) = s.as_bytes().first() else {
                break;
            };
            if (q == b'"' || q == b'\'') && s.len() > 1 {
                if let Some(end) = s[1..].find(q as char) {
                    let val = s[1..1 + end].trim();
                    if !val.is_empty() {
                        out.push(val.to_string());
                    }
                    from = i + 1 + end + 1;
                }
            }
        }
    }
    out
}

/// Resource references loaded over plain HTTP — mixed content when the page
/// itself is HTTPS (can be blocked or tampered with in transit).
pub fn mixed_content(body: &str) -> Vec<String> {
    extract_hrefs(body)
        .into_iter()
        .filter(|h| h.starts_with("http://"))
        .collect()
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

    #[test]
    fn detects_wordpress_with_version() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2" />
            <link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>"#;
        let (cms, ver) = detect_cms("nginx", "", body).unwrap();
        assert_eq!(cms, "WordPress");
        assert_eq!(ver.as_deref(), Some("6.4.2"));
        // body markers alone (no generator) still detect WordPress.
        let (cms2, _) = detect_cms("", "", "<a href='/wp-includes/js/x.js'>").unwrap();
        assert_eq!(cms2, "WordPress");
    }

    #[test]
    fn extracts_links_and_mixed_content() {
        let body = r#"<a HREF="/listproducts.php?cat=1">x</a>
            <script src='https://cdn.example/app.js'></script>
            <link href="http://cdn.example/style.css" rel="stylesheet">"#;
        let hrefs = extract_hrefs(body);
        assert!(hrefs.iter().any(|h| h == "/listproducts.php?cat=1"));
        assert!(hrefs.iter().any(|h| h.ends_with("app.js")));
        let mixed = mixed_content(body);
        assert_eq!(mixed, vec!["http://cdn.example/style.css".to_string()]);
    }
}
