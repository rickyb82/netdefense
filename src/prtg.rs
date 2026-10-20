//! PRTG inventory import (pure parser). Reads a PRTG `/api/table.json?content=
//! devices` response and maps it to importable hosts, so an existing PRTG estate
//! can seed netdefense assets (migration path off PRTG). The live HTTP fetch
//! (reqwest, auth via username + passhash from env secrets) is the seam.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrtgDevice {
    pub name: String,
    pub host: String,
    pub group: Option<String>,
    pub active: bool,
}

/// Parse `{"devices":[{device,host,group,active,...}]}`. Rows without a host are
/// skipped. `active` tolerates PRTG's bool, "true"/"false" or "Active" forms.
pub fn parse_table_devices(json: &str) -> Result<Vec<PrtgDevice>> {
    let v: Value = serde_json::from_str(json)?;
    let empty = Vec::new();
    let mut out = Vec::new();
    for d in v["devices"].as_array().unwrap_or(&empty) {
        let host = d["host"].as_str().unwrap_or("").trim().to_string();
        if host.is_empty() {
            continue;
        }
        let active = match &d["active"] {
            Value::Bool(b) => *b,
            Value::String(s) => {
                let s = s.trim();
                !(s.eq_ignore_ascii_case("false") || s == "0" || s.is_empty())
            }
            Value::Number(n) => n.as_i64().unwrap_or(1) != 0,
            _ => true,
        };
        out.push(PrtgDevice {
            name: d["device"].as_str().unwrap_or("").trim().to_string(),
            host,
            group: d["group"]
                .as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            active,
        });
    }
    Ok(out)
}

/// Does `host` look like a bare IP address (→ Host asset) rather than a DNS name
/// (→ Domain asset)? Simple, dependency-free heuristic.
pub fn looks_like_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "prtg-version": "23.4.89",
      "treesize": 3,
      "devices": [
        {"objid": 2001, "device": "Core Router MI", "host": "10.0.0.1", "group": "Milano", "active": "true"},
        {"objid": 2002, "device": "Edge RM", "host": "edge.rm.example", "group": "Roma", "active": true},
        {"objid": 2003, "device": "Spento", "host": "10.0.0.9", "group": "Milano", "active": "false"},
        {"objid": 2004, "device": "Senza host", "host": "", "group": "X", "active": true}
      ]
    }"#;

    #[test]
    fn parses_devices_and_skips_hostless() {
        let d = parse_table_devices(SAMPLE).unwrap();
        assert_eq!(d.len(), 3); // the hostless row is skipped
        assert_eq!(d[0].host, "10.0.0.1");
        assert_eq!(d[0].group.as_deref(), Some("Milano"));
        assert!(d[0].active);
        assert!(!d[2].active); // "false"
    }

    #[test]
    fn ip_vs_dns_classification() {
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(!looks_like_ip("edge.rm.example"));
    }

    #[test]
    fn empty_feed_is_ok() {
        assert!(parse_table_devices(r#"{"devices":[]}"#).unwrap().is_empty());
    }
}
