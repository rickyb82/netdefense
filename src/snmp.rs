//! SNMP-based inventory classification (pure core).
//!
//! Turns a device's `sysDescr.0` (1.3.6.1.2.1.1.1.0) and optional `sysObjectID.0`
//! (1.3.6.1.2.1.1.2.0) into vendor / product / version, mapped onto the
//! `fleet` product keys so CVE correlation works across the whole multi-vendor
//! estate — not just MikroTik. Vendor is decided by the SNMP enterprise number
//! when present (authoritative), else by keywords in sysDescr.
//!
//! This is the pure, unit-tested half. The live SNMP GET/WALK (e.g. via the
//! `csnmp` crate) is a separate collector that feeds these functions and then
//! `store.upsert_device_facts` + `fleet::run_correlation`.

use serde::Serialize;

use crate::domain::Id;
use crate::fleet::DeviceFacts;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnmpIdentity {
    pub vendor: String,
    /// `fleet` product key: routeros / junos / huawei / fritzos / cambium / airos / keeneticos.
    pub product: String,
    pub version: Option<String>,
}

/// IANA enterprise number -> (vendor, fleet product key).
fn vendor_by_enterprise(n: u64) -> Option<(&'static str, &'static str)> {
    match n {
        14988 => Some(("MikroTik", "routeros")),
        2636 => Some(("Juniper", "junos")),
        2011 => Some(("Huawei", "huawei")),
        872 => Some(("AVM", "fritzos")),
        17713 => Some(("Cambium", "cambium")),
        41112 => Some(("Ubiquiti", "airos")),
        8072 => None, // net-snmp: generic, fall through to sysDescr keywords
        _ => None,
    }
}

/// Extract the enterprise number N from a sysObjectID like `1.3.6.1.4.1.N...`.
fn enterprise_of(sys_object_id: &str) -> Option<u64> {
    let rest = sys_object_id.trim().strip_prefix("1.3.6.1.4.1.")?;
    rest.split('.').next()?.parse().ok()
}

fn vendor_by_keyword(d: &str) -> Option<(&'static str, &'static str)> {
    let l = d.to_ascii_lowercase();
    if l.contains("routeros") || l.contains("mikrotik") {
        Some(("MikroTik", "routeros"))
    } else if l.contains("junos") || l.contains("juniper") {
        Some(("Juniper", "junos"))
    } else if l.contains("vrp") || l.contains("huawei") {
        Some(("Huawei", "huawei"))
    } else if l.contains("fritz") {
        Some(("AVM", "fritzos"))
    } else if l.contains("cambium") || l.contains("epmp") || l.contains("medusa") {
        Some(("Cambium", "cambium"))
    } else if l.contains("airos")
        || l.contains("edgeos")
        || l.contains("ubiquiti")
        || l.contains("ubnt")
    {
        Some(("Ubiquiti", "airos"))
    } else if l.contains("keenetic") {
        Some(("Keenetic", "keeneticos"))
    } else {
        None
    }
}

/// The word following `marker` in `s` (up to whitespace), trimmed of trailing
/// punctuation — e.g. version_after("… RouterOS 7.19", "RouterOS ") == "7.19".
fn version_after(s: &str, marker: &str) -> Option<String> {
    // rfind: on strings like "RouterOS CCR1009, RouterOS 7.19" the version
    // follows the LAST marker, not the model after the first one.
    let i = s.rfind(marker)?;
    let tail = s[i + marker.len()..].trim_start();
    let word: String = tail.chars().take_while(|c| !c.is_whitespace()).collect();
    let trimmed = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// First dotted-numeric version token in `s` (needs at least one dot).
fn first_dotted(s: &str) -> Option<String> {
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == '.') {
                i += 1;
            }
            let tok: String = bytes[start..i].iter().collect();
            let tok = tok.trim_matches('.').to_string();
            if tok.contains('.') && tok.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some(tok);
            }
        } else {
            i += 1;
        }
    }
    None
}

fn version_for(product: &str, sysdescr: &str) -> Option<String> {
    match product {
        "routeros" => version_after(sysdescr, "RouterOS "),
        "junos" => version_after(sysdescr, "JUNOS ").or_else(|| version_after(sysdescr, "Junos: ")),
        "huawei" => version_after(sysdescr, "Version "),
        "fritzos" => {
            version_after(sysdescr, "FRITZ!OS ").or_else(|| version_after(sysdescr, "FRITZ!OS: "))
        }
        "keeneticos" => version_after(sysdescr, "KeeneticOS ").or_else(|| first_dotted(sysdescr)),
        _ => first_dotted(sysdescr),
    }
}

/// Classify a device from its sysDescr and optional sysObjectID. Enterprise OID
/// wins over keyword matching. Returns `None` for an unrecognised vendor.
pub fn classify(sysdescr: &str, sys_object_id: Option<&str>) -> Option<SnmpIdentity> {
    let (vendor, product) = sys_object_id
        .and_then(enterprise_of)
        .and_then(vendor_by_enterprise)
        .or_else(|| vendor_by_keyword(sysdescr))?;
    Some(SnmpIdentity {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version_for(product, sysdescr),
    })
}

/// Build `DeviceFacts` for an asset from a classified identity. Management/VoIP
/// exposure is filled separately by the surface scan, so `mgmt` starts empty.
pub fn facts(asset_id: Id, id: &SnmpIdentity) -> DeviceFacts {
    DeviceFacts {
        asset_id,
        vendor: id.vendor.clone(),
        product: id.product.clone(),
        version: id.version.clone(),
        mgmt: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_vendor_sysdescr() {
        let cases = [
            ("RouterOS CCR1009, RouterOS 7.19", None, "MikroTik", "routeros", Some("7.19")),
            ("Juniper Networks, Inc. mx240 ... JUNOS 20.4R3-S2.6 #0:", None, "Juniper", "junos", Some("20.4R3-S2.6")),
            ("Huawei Versatile Routing Platform Software VRP (R) Software, Version 8.180 (NE40E)", None, "Huawei", "huawei", Some("8.180")),
            ("FRITZ!Box 7590 FRITZ!OS 7.57", None, "AVM", "fritzos", Some("7.57")),
            ("Cambium Networks ePMP 3000 Firmware 4.7.0.1", None, "Cambium", "cambium", Some("4.7.0.1")),
            ("Ubiquiti airOS airMAX 8.7.11", None, "Ubiquiti", "airos", Some("8.7.11")),
            ("Keenetic Giga KeeneticOS 3.9.5", None, "Keenetic", "keeneticos", Some("3.9.5")),
        ];
        for (d, oid, vendor, product, ver) in cases {
            let id = classify(d, oid).unwrap_or_else(|| panic!("unclassified: {d}"));
            assert_eq!(id.vendor, vendor, "vendor for {d}");
            assert_eq!(id.product, product, "product for {d}");
            assert_eq!(id.version.as_deref(), ver, "version for {d}");
        }
    }

    #[test]
    fn enterprise_oid_wins_over_keywords() {
        // Enterprise 14988 = MikroTik even if the descr text is vague.
        let id = classify("router, v7.1", Some("1.3.6.1.4.1.14988.1.1.7.3.0")).unwrap();
        assert_eq!(id.product, "routeros");
        assert_eq!(enterprise_of("1.3.6.1.4.1.2636.1.1.1.2.29"), Some(2636));
        assert_eq!(enterprise_of("1.2.3"), None);
    }

    #[test]
    fn unknown_vendor_is_none() {
        assert!(classify("Some generic Linux box 5.10", None).is_none());
    }

    #[test]
    fn net_snmp_enterprise_falls_through_to_keywords() {
        // 8072 (net-snmp) is generic; a RouterOS box behind it still classifies.
        let id = classify("RouterOS 6.49.7", Some("1.3.6.1.4.1.8072.3.2.10")).unwrap();
        assert_eq!(id.product, "routeros");
        assert_eq!(id.version.as_deref(), Some("6.49.7"));
    }
}
