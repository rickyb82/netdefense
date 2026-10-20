//! Multi-vendor fleet layer: a product catalog (for CVE correlation by CPE
//! token), per-device facts (vendor / product / version / exposed management
//! and VoIP services), an exposure classifier, and CVE↔device correlation.
//!
//! The correlation and classification are pure and tested here; collecting the
//! facts from devices (RouterOS API, SNMP, vendor APIs) is a separate layer.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cve::Cve;
use crate::domain::{Alert, Id, Severity};
use crate::store::Store;

/// A product we can track CVEs for. `cpe_token` is the lowercased substring we
/// match against NVD CPE criteria.
pub struct Product {
    pub key: &'static str,
    pub vendor: &'static str,
    pub label: &'static str,
    pub cpe_token: &'static str,
}

/// The fleet's vendors/products. Extend as the estate grows.
pub fn catalog() -> &'static [Product] {
    &[
        Product {
            key: "routeros",
            vendor: "MikroTik",
            label: "RouterOS / CHR",
            cpe_token: "routeros",
        },
        Product {
            key: "keeneticos",
            vendor: "Keenetic",
            label: "KeeneticOS",
            cpe_token: "keeneticos",
        },
        Product {
            key: "huawei",
            vendor: "Huawei",
            label: "Huawei (VRP/CPE)",
            cpe_token: "huawei",
        },
        Product {
            key: "junos",
            vendor: "Juniper",
            label: "Junos OS",
            cpe_token: "junos",
        },
        Product {
            key: "fritzos",
            vendor: "AVM",
            label: "FRITZ!OS",
            cpe_token: "fritz",
        },
        Product {
            key: "cambium",
            vendor: "Cambium",
            label: "ePMP / Medusa",
            cpe_token: "cambium",
        },
        Product {
            key: "airos",
            vendor: "Ubiquiti",
            label: "airOS / EdgeOS",
            cpe_token: "ubiquiti",
        },
        Product {
            key: "3cx",
            vendor: "3CX",
            label: "3CX PBX",
            cpe_token: "3cx",
        },
        Product {
            key: "cirpack",
            vendor: "Cirpack",
            label: "Cirpack softswitch",
            cpe_token: "cirpack",
        },
    ]
}

/// Facts about one device, used for CVE correlation and exposure reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceFacts {
    pub asset_id: Id,
    pub vendor: String,
    /// Product key from the catalog (e.g. `routeros`, `3cx`).
    pub product: String,
    pub version: Option<String>,
    /// Exposed management/VoIP services as `name/port` tokens, e.g. `winbox/8291`.
    pub mgmt: Vec<String>,
}

/// A classified exposed service — management or VoIP ports that generally must
/// not face the public internet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Exposure {
    pub label: &'static str,
    pub severity: Severity,
    pub note: &'static str,
}

/// Classify an open `port`/`proto` as a sensitive exposure, or `None` if it is
/// not a management/VoIP port worth flagging. Covers the fleet's vendors and
/// the VoIP estate (SIP, 3CX, Asterisk AMI).
pub fn classify(port: u16, proto: &str) -> Option<Exposure> {
    let e = |label, severity, note| {
        Some(Exposure {
            label,
            severity,
            note,
        })
    };
    match (port, proto) {
        (23, _) => e(
            "Telnet",
            Severity::High,
            "management in chiaro — disabilitare",
        ),
        (21, _) => e("FTP", Severity::Medium, "trasferimento in chiaro"),
        (22, _) => e("SSH", Severity::Info, "management — limitare per IP"),
        (80, _) => e(
            "HTTP mgmt",
            Severity::Medium,
            "pannello non cifrato esposto",
        ),
        (443, _) => e(
            "HTTPS mgmt",
            Severity::Low,
            "pannello esposto — limitare per IP",
        ),
        (8080 | 8443, _) => e("Web mgmt alt", Severity::Medium, "pannello esposto"),
        (8291, _) => e(
            "Winbox (MikroTik)",
            Severity::High,
            "Winbox pubblico — chiudere/VPN",
        ),
        (8728 | 8729, _) => e("RouterOS API", Severity::High, "API RouterOS pubblica"),
        (3389, _) => e("RDP", Severity::High, "desktop remoto pubblico"),
        (161, _) => e(
            "SNMP",
            Severity::Medium,
            "SNMP pubblico — community/accesso",
        ),
        (1723, _) => e("PPTP", Severity::Medium, "VPN legacy insicura"),
        (7547, _) => e("TR-069 CWMP", Severity::High, "gestione CPE esposta"),
        // --- VoIP ---
        (5060, _) => e("SIP", Severity::High, "SIP pubblico — toll fraud / flood"),
        (5061, _) => e("SIP-TLS", Severity::Medium, "SIP/TLS esposto"),
        (5038, _) => e(
            "Asterisk AMI",
            Severity::High,
            "interfaccia manager esposta",
        ),
        (5000, _) => e("3CX", Severity::Medium, "3CX esposto"),
        (5001, _) => e("3CX web mgmt", Severity::High, "console 3CX pubblica"),
        (5090, _) => e("3CX tunnel", Severity::Medium, "tunnel 3CX esposto"),
        _ => None,
    }
}

/// Correlate CVEs against device facts: a device is affected when its product
/// matches a CVE's product and the CVE affects its version. Returns
/// `(cve, asset_id)` pairs.
pub fn matches<'a>(cves: &'a [Cve], facts: &[DeviceFacts]) -> Vec<(&'a Cve, Id)> {
    let mut out = Vec::new();
    for f in facts {
        for c in cves {
            if c.product.eq_ignore_ascii_case(&f.product) {
                let affected = match &f.version {
                    Some(v) => c.affects(v),
                    None => c.version_start_incl.is_none() && c.version_end_excl.is_none(),
                };
                if affected {
                    out.push((c, f.asset_id));
                }
            }
        }
    }
    out
}

/// Correlate every stored CVE against every device's facts and raise one alert
/// per newly matched (CVE, device) pair. Returns how many alerts were raised.
/// Idempotent: re-running does not duplicate alerts for pairs already recorded.
pub fn run_correlation(store: &Store) -> Result<usize> {
    let cves = store.list_cves()?;
    let facts = store.list_device_facts()?;
    let mut created = 0;
    for (c, asset_id) in matches(&cves, &facts) {
        if store.record_cve_match(&c.id, asset_id)? {
            let ver = facts
                .iter()
                .find(|f| f.asset_id == asset_id)
                .and_then(|f| f.version.clone())
                .unwrap_or_else(|| "versione sconosciuta".into());
            store.insert_alert(&Alert {
                id: Uuid::new_v4(),
                asset_id,
                scan_id: None,
                severity: c.severity,
                summary: format!("{} · {} ({ver})", c.id, c.product),
                detail: c.summary.clone(),
                created_at: Utc::now(),
            })?;
            created += 1;
        }
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn cve(product: &str, end: Option<&str>) -> Cve {
        Cve {
            id: "CVE-2023-0001".into(),
            published: "2023-01-01".into(),
            severity: Severity::High,
            summary: "x".into(),
            product: product.into(),
            version_start_incl: None,
            version_end_excl: end.map(str::to_string),
        }
    }

    #[test]
    fn classify_flags_voip_and_mgmt() {
        assert_eq!(classify(5060, "udp").unwrap().severity, Severity::High);
        assert_eq!(classify(8291, "tcp").unwrap().severity, Severity::High);
        assert_eq!(classify(5001, "tcp").unwrap().label, "3CX web mgmt");
        assert!(classify(12345, "tcp").is_none());
    }

    #[test]
    fn correlation_matches_product_and_version() {
        let cves = vec![cve("routeros", Some("6.49.8")), cve("3cx", None)];
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let facts = vec![
            DeviceFacts {
                asset_id: a1,
                vendor: "MikroTik".into(),
                product: "routeros".into(),
                version: Some("6.49.7".into()),
                mgmt: vec![],
            },
            DeviceFacts {
                asset_id: a2,
                vendor: "MikroTik".into(),
                product: "routeros".into(),
                version: Some("6.49.8".into()),
                mgmt: vec![],
            },
        ];
        let m = matches(&cves, &facts);
        // Only the 6.49.7 device matches the routeros CVE; no 3CX device present.
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].1, a1);
    }

    #[test]
    fn catalog_covers_the_estate() {
        let keys: Vec<_> = catalog().iter().map(|p| p.key).collect();
        for k in [
            "routeros", "3cx", "cirpack", "junos", "fritzos", "cambium", "airos",
        ] {
            assert!(keys.contains(&k), "missing product {k}");
        }
    }
}
