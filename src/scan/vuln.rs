//! Vulnerability scan: correlate the asset's device facts (vendor / product /
//! version) against the stored CVE archive, and flag its exposed management /
//! VoIP services. No external tool — it ties the inventory, the CVE feed and
//! the exposure classifier together. A newly matching CVE appears as a new
//! finding key, so the baseline diff alerts on it.

use anyhow::Result;

use super::FindingDraft;
use crate::domain::{Id, Severity};
use crate::fleet;
use crate::store::Store;

fn draft(key: &str, title: String, detail: String, severity: Severity) -> FindingDraft {
    FindingDraft {
        kind: "vuln".to_string(),
        key: key.to_string(),
        title,
        detail,
        severity,
    }
}

/// Correlate CVEs and exposures for a single asset.
pub fn scan(store: &Store, asset_id: Id) -> Result<Vec<FindingDraft>> {
    let facts: Vec<_> = store
        .list_device_facts()?
        .into_iter()
        .filter(|f| f.asset_id == asset_id)
        .collect();

    if facts.is_empty() {
        return Ok(vec![draft(
            "vuln/no-facts",
            "Nessun fact sul device".into(),
            "Per correlare le CVE serve conoscere vendor/prodotto/versione: esegui una classificazione SNMP o imposta i fact del device.".into(),
            Severity::Info,
        )]);
    }

    let cves = store.list_cves()?;
    let mut out = Vec::new();

    // CVE matches for this asset's product/version.
    for (c, _aid) in fleet::matches(&cves, &facts) {
        let ver = facts
            .iter()
            .find_map(|f| f.version.clone())
            .unwrap_or_else(|| "versione sconosciuta".into());
        out.push(draft(
            &format!("vuln/cve/{}", c.id),
            format!("{} · {} ({ver})", c.id, c.product),
            c.summary.clone(),
            c.severity,
        ));
    }

    // Exposed management / VoIP services recorded as `label/port` facts.
    for f in &facts {
        for tok in &f.mgmt {
            if let Some(port) = tok.rsplit('/').next().and_then(|p| p.parse::<u16>().ok()) {
                if let Some(exp) = fleet::classify(port, "tcp") {
                    out.push(draft(
                        &format!("vuln/exposure/{port}"),
                        format!("Servizio esposto: {}", exp.label),
                        format!("{} (porta {port}) — {}", exp.label, exp.note),
                        exp.severity,
                    ));
                }
            }
        }
    }

    if out.is_empty() {
        out.push(draft(
            "vuln/clean",
            "Nessuna vulnerabilità nota correlata".into(),
            "I fact del device non corrispondono ad alcuna CVE in archivio né a servizi esposti noti.".into(),
            Severity::Info,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::Cve;
    use crate::domain::*;
    use crate::fleet::DeviceFacts;
    use crate::store::Store;
    use chrono::Utc;
    use uuid::Uuid;

    fn mem() -> Store {
        let s = Store::open(":memory:").unwrap();
        s.migrate().unwrap();
        s
    }

    fn seed(s: &Store) -> Id {
        let cid = Uuid::new_v4();
        s.insert_client(&Client {
            id: cid,
            name: "C".into(),
            contact_email: "c@e".into(),
            created_at: Utc::now(),
        })
        .unwrap();
        let aid = Uuid::new_v4();
        s.insert_asset(&Asset {
            id: aid,
            client_id: cid,
            kind: AssetKind::Host,
            value: "203.0.113.1".into(),
            auth_status: AuthStatus::Active,
            authorized_until: None,
            window_start: None,
            window_end: None,
            roe_reference: Some("RoE".into()),
            created_at: Utc::now(),
        })
        .unwrap();
        aid
    }

    #[test]
    fn no_facts_returns_info() {
        let s = mem();
        let aid = seed(&s);
        let out = scan(&s, aid).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key, "vuln/no-facts");
    }

    #[test]
    fn matches_cve_and_flags_exposure() {
        let s = mem();
        let aid = seed(&s);
        s.insert_cve(&Cve {
            id: "CVE-2023-41570".into(),
            published: "2023-10-01".into(),
            severity: Severity::High,
            summary: "RouterOS issue".into(),
            product: "routeros".into(),
            version_start_incl: None,
            version_end_excl: Some("6.49.8".into()),
        })
        .unwrap();
        s.upsert_device_facts(&DeviceFacts {
            asset_id: aid,
            vendor: "MikroTik".into(),
            product: "routeros".into(),
            version: Some("6.49.7".into()),
            mgmt: vec!["winbox/8291".into()],
        })
        .unwrap();

        let out = scan(&s, aid).unwrap();
        assert!(out.iter().any(|f| f.key == "vuln/cve/CVE-2023-41570"));
        assert!(out.iter().any(|f| f.key == "vuln/exposure/8291"));
    }
}
