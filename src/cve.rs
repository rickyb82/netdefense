//! CVE model, RouterOS version matching, and NVD feed parsing.
//!
//! The valuable part for a MikroTik fleet is correlation: given the CVEs that
//! affect RouterOS and the version each device runs, decide exactly which
//! devices a freshly published CVE hits. That logic is pure and tested here;
//! fetching the feed over the network lives behind it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::Severity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cve {
    pub id: String,
    pub published: String,
    pub severity: Severity,
    pub summary: String,
    /// Lowercased product token this CVE is matched against, e.g. `routeros`.
    pub product: String,
    /// Affected range, RouterOS version semantics.
    pub version_start_incl: Option<String>,
    pub version_end_excl: Option<String>,
}

/// A dotted-numeric version (RouterOS: `6.49.7`, `7.11.2`, `6.48`). Any trailing
/// non-numeric suffix (`7.1rc4`, `6.49.7 (stable)`) is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosVersion(Vec<u32>);

impl RosVersion {
    pub fn parse(s: &str) -> Option<RosVersion> {
        let mut parts = Vec::new();
        for seg in s.trim().split('.') {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                break;
            }
            match digits.parse::<u32>() {
                Ok(n) => parts.push(n),
                Err(_) => break,
            }
        }
        if parts.is_empty() {
            return None;
        }
        // Normalise trailing zeros so 7.1 and 7.1.0 compare equal both by Ord
        // (which pads) and by derived PartialEq (which compares the vectors).
        while parts.len() > 1 && *parts.last().unwrap() == 0 {
            parts.pop();
        }
        Some(RosVersion(parts))
    }
}

impl PartialOrd for RosVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RosVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl Cve {
    /// Does this CVE affect `version`? The caller has already matched product.
    /// An unparsable device version is treated as affected (fail safe — surface
    /// it rather than hide it).
    pub fn affects(&self, version: &str) -> bool {
        let Some(ver) = RosVersion::parse(version) else {
            return true;
        };
        if let Some(start) = self
            .version_start_incl
            .as_deref()
            .and_then(RosVersion::parse)
        {
            if ver < start {
                return false;
            }
        }
        if let Some(end) = self.version_end_excl.as_deref().and_then(RosVersion::parse) {
            if ver >= end {
                return false;
            }
        }
        true
    }
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse an NVD 2.0 API JSON response into CVEs that reference `product_token`
/// (e.g. `routeros`). Malformed entries are skipped rather than failing.
pub fn parse_nvd(json: &str, product_token: &str) -> Vec<Cve> {
    let token = product_token.to_ascii_lowercase();
    let Ok(root) = serde_json::from_str::<Value>(json) else {
        return vec![];
    };
    let mut out = Vec::new();
    let empty = Vec::new();
    for item in root["vulnerabilities"].as_array().unwrap_or(&empty) {
        let cve = &item["cve"];
        let Some(id) = cve["id"].as_str() else {
            continue;
        };

        let summary = cve["descriptions"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["lang"].as_str() == Some("en")))
            .and_then(|d| d["value"].as_str())
            .unwrap_or("")
            .to_string();

        let severity = nvd_severity(cve);
        let (start, end, matched) = nvd_version_range(cve, &token);
        if !matched {
            continue;
        }

        out.push(Cve {
            id: id.to_string(),
            published: cve["published"].as_str().unwrap_or("").to_string(),
            severity,
            summary,
            product: token.clone(),
            version_start_incl: start,
            version_end_excl: end,
        });
    }
    out
}

fn nvd_severity(cve: &Value) -> Severity {
    for metric in ["cvssMetricV31", "cvssMetricV30"] {
        if let Some(sev) = cve["metrics"][metric][0]["cvssData"]["baseSeverity"].as_str() {
            return severity_from_str(sev);
        }
    }
    // CVSS v2 carries severity one level up.
    if let Some(sev) = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"].as_str() {
        return severity_from_str(sev);
    }
    Severity::Info
}

/// Scan the CVE's CPE configurations for a match on `token`; return its
/// version bounds and whether any node matched the product.
fn nvd_version_range(cve: &Value, token: &str) -> (Option<String>, Option<String>, bool) {
    let empty = Vec::new();
    for cfg in cve["configurations"].as_array().unwrap_or(&empty) {
        for node in cfg["nodes"].as_array().unwrap_or(&empty) {
            for m in node["cpeMatch"].as_array().unwrap_or(&empty) {
                let criteria = m["criteria"].as_str().unwrap_or("").to_ascii_lowercase();
                if !criteria.contains(token) {
                    continue;
                }
                let start = m["versionStartIncluding"].as_str().map(str::to_string);
                let end = m["versionEndExcluding"].as_str().map(str::to_string);
                return (start, end, true);
            }
        }
    }
    (None, None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering_pads_components() {
        assert!(RosVersion::parse("6.49").unwrap() < RosVersion::parse("6.49.7").unwrap());
        assert!(RosVersion::parse("7.11.2").unwrap() > RosVersion::parse("6.49.7").unwrap());
        assert_eq!(
            RosVersion::parse("7.1").unwrap(),
            RosVersion::parse("7.1.0").unwrap()
        );
        assert!(RosVersion::parse("7.1rc4").unwrap() == RosVersion::parse("7.1").unwrap());
    }

    fn cve(start: Option<&str>, end: Option<&str>) -> Cve {
        Cve {
            id: "CVE-2023-0001".into(),
            published: "2023-01-01".into(),
            severity: Severity::High,
            summary: "x".into(),
            product: "routeros".into(),
            version_start_incl: start.map(str::to_string),
            version_end_excl: end.map(str::to_string),
        }
    }

    #[test]
    fn affects_respects_fixed_in_version() {
        // Affected 6.0 (incl) .. 6.49.8 (excl): fixed in 6.49.8.
        let c = cve(Some("6.0"), Some("6.49.8"));
        assert!(c.affects("6.49.7")); // vulnerable
        assert!(!c.affects("6.49.8")); // patched
        assert!(!c.affects("7.11.2")); // different branch, above range
        assert!(!c.affects("5.26")); // below start
    }

    #[test]
    fn unparsable_version_is_surfaced() {
        assert!(cve(Some("6.0"), Some("6.49.8")).affects("unknown"));
    }

    #[test]
    fn parse_nvd_extracts_routeros_cve() {
        let sample = r#"{
          "vulnerabilities": [
            { "cve": {
                "id": "CVE-2023-41570",
                "published": "2023-10-01T00:00Z",
                "descriptions": [{"lang":"en","value":"RouterOS Winbox issue"}],
                "metrics": {"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},
                "configurations": [{"nodes":[{"cpeMatch":[
                  {"criteria":"cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                   "versionStartIncluding":"6.0","versionEndExcluding":"6.49.8"}
                ]}]}]
            }},
            { "cve": {
                "id": "CVE-2020-0000",
                "descriptions": [{"lang":"en","value":"unrelated product"}],
                "configurations": [{"nodes":[{"cpeMatch":[
                  {"criteria":"cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}
                ]}]}]
            }}
          ]
        }"#;
        let cves = parse_nvd(sample, "routeros");
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].id, "CVE-2023-41570");
        assert_eq!(cves[0].severity, Severity::High);
        assert_eq!(cves[0].version_end_excl.as_deref(), Some("6.49.8"));
        assert!(cves[0].affects("6.49.7"));
    }
}
