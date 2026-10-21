//! External attack-surface scan: an nmap sweep with service/version detection.
//!
//! Beyond listing open ports, it reads the version banners (nmap `-sV`) to
//! fingerprint the device (vendor / product / version) — RouterOS and the rest
//! of the fleet — then records that as device facts and correlates CVEs. So a
//! surface scan of a MikroTik yields: the exposed management ports (Winbox /
//! API flagged by severity), the detected RouterOS version, and the CVEs that
//! affect it. Parsing and fingerprinting are pure and unit-tested; nmap is the
//! seam.

use anyhow::{anyhow, Result};

use super::{runner, FindingDraft};
use crate::domain::{Id, Severity};
use crate::snmp::SnmpIdentity;
use crate::store::Store;

/// Ports worth version-probing: common services plus the fleet's management and
/// VoIP ports (Winbox 8291, RouterOS API 8728/8729, SIP, 3CX, TR-069, …).
const FLEET_PORTS: &str = "21,22,23,25,53,80,110,135,139,143,161,443,445,587,\
993,995,1723,2000,3306,3389,5000,5001,5038,5060,5061,5090,7547,8080,8291,8443,8728,8729,10000";

/// One parsed open port from nmap greppable output.
struct PortEntry {
    port: u16,
    proto: String,
    service: String,
    version: String,
}

/// Run an nmap version-detection scan against `target`, record a finding per
/// open port, and — if the banners identify a known product — store device
/// facts and correlate CVEs. `target` has already cleared the gate.
pub async fn scan(
    store: &Store,
    asset_id: Id,
    target: &str,
    timeout_secs: u64,
    deep: bool,
) -> Result<Vec<FindingDraft>> {
    // Quick: the curated fleet/management/VoIP ports with a light version probe
    // (fast). Deep: every TCP port (-p-) with full service/version detection, so
    // nothing is missed and each open port is identified — what the deep scan
    // is for. nmap self-limits with --host-timeout and the runner kill backs it.
    let (args, to): (Vec<String>, u64) = if deep {
        (
            vec![
                "-Pn",
                "-T4",
                "-sV",
                "-p-",
                "--open",
                "--host-timeout",
                "850s",
                "-oG",
                "-",
                target,
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            timeout_secs.max(900),
        )
    } else {
        (
            vec![
                "-Pn",
                "-T4",
                "-sV",
                "--version-light",
                "-p",
                FLEET_PORTS,
                "--open",
                "-oG",
                "-",
                target,
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            timeout_secs,
        )
    };

    let out = runner::run("nmap", &args, to).await;
    if out.not_found {
        return Err(anyhow!("nmap is not installed on the scanner host"));
    }
    if out.timed_out {
        return Err(anyhow!("nmap timed out after {to}s"));
    }
    if out.stdout.trim().is_empty() && !out.stderr.trim().is_empty() {
        return Err(anyhow!("nmap failed: {}", out.stderr.trim()));
    }

    let entries = port_entries(&out.stdout);
    let mut findings = port_findings(&entries);

    // Fingerprint vendor/product/version from the banners and tie it into the
    // inventory + CVE correlation, so the surface scan deepens the picture.
    if let Some(id) = fingerprint(&entries) {
        let ver = id.version.clone().unwrap_or_else(|| "versione n/d".into());
        findings.insert(
            0,
            FindingDraft {
                kind: "fingerprint".to_string(),
                key: format!("os/{}", id.product),
                title: format!("Rilevato {} {} ({ver})", id.vendor, id.product),
                detail: format!(
                    "Fingerprint dai banner nmap: {} {} versione {ver}. Correlazione CVE eseguita.",
                    id.vendor, id.product
                ),
                severity: Severity::Info,
            },
        );
        let facts = crate::fleet::DeviceFacts {
            asset_id,
            vendor: id.vendor,
            product: id.product,
            version: id.version,
            mgmt: mgmt_tokens(&entries),
        };
        store.upsert_device_facts(&facts)?;
        let _ = crate::fleet::run_correlation(store)?;
    }

    Ok(findings)
}

/// Parse nmap `-oG -` output into open-port entries. A port entry looks like
/// `8291/open/tcp//winbox//` or, with `-sV`, `21/open/tcp//ftp//MikroTik router ftpd 6.49.3/`.
fn port_entries(stdout: &str) -> Vec<PortEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let Some(seg) = line
            .split('\t')
            .find_map(|s| s.trim().strip_prefix("Ports:"))
        else {
            continue;
        };
        for entry in seg.split(',') {
            let f: Vec<&str> = entry.trim().split('/').collect();
            // port / state / proto / owner / service / rpcinfo / version / ...
            if f.len() < 3 || f[1] != "open" {
                continue;
            }
            let Ok(port) = f[0].trim().parse::<u16>() else {
                continue;
            };
            out.push(PortEntry {
                port,
                proto: f.get(2).unwrap_or(&"tcp").trim().to_string(),
                service: f.get(4).unwrap_or(&"").trim().to_string(),
                version: f.get(6).unwrap_or(&"").trim().to_string(),
            });
        }
    }
    out
}

/// One finding per open port, with management/VoIP ports flagged by severity.
fn port_findings(entries: &[PortEntry]) -> Vec<FindingDraft> {
    entries
        .iter()
        .map(|e| {
            let svc = if e.version.is_empty() {
                e.service.clone()
            } else if e.service.is_empty() {
                e.version.clone()
            } else {
                format!("{} {}", e.service, e.version)
            };
            let shown = if svc.is_empty() { "servizio n/d" } else { &svc };
            let key = format!("{}/{}", e.proto, e.port);
            match crate::fleet::classify(e.port, &e.proto) {
                Some(exp) => FindingDraft {
                    kind: "open_port".to_string(),
                    key,
                    title: format!("{} esposto · {}/{}", exp.label, e.port, e.proto),
                    detail: format!("{} ({shown})", exp.note),
                    severity: exp.severity,
                },
                None => FindingDraft {
                    kind: "open_port".to_string(),
                    key,
                    title: format!("Porta aperta {}/{} ({shown})", e.port, e.proto),
                    detail: format!("nmap: {}/{} aperta, servizio `{shown}`", e.port, e.proto),
                    severity: Severity::Info,
                },
            }
        })
        .collect()
}

/// Identify vendor/product/version from the service/version banners. Picks the
/// first banner that classifies, preferring one that also yields a version.
fn fingerprint(entries: &[PortEntry]) -> Option<SnmpIdentity> {
    let mut fallback: Option<SnmpIdentity> = None;
    for e in entries {
        let banner = format!("{} {}", e.service, e.version);
        if let Some(id) = crate::snmp::classify(&banner, None) {
            if id.version.is_some() {
                return Some(id);
            }
            fallback.get_or_insert(id);
        }
    }
    fallback
}

/// Management/VoIP exposure tokens (`label/port`) for the device facts, so the
/// vuln scan can report the same exposed services.
fn mgmt_tokens(entries: &[PortEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| {
            crate::fleet::classify(e.port, &e.proto).map(|exp| format!("{}/{}", exp.label, e.port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_open_ports_from_greppable() {
        let sample = "# Nmap 7.94 scan\n\
            Host: 203.0.113.10 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///\tIgnored State: closed (997)\n\
            # Nmap done\n";
        let f = port_findings(&port_entries(sample));
        let keys: Vec<_> = f.iter().map(|x| x.key.as_str()).collect();
        assert_eq!(keys, ["tcp/22", "tcp/80", "tcp/443"]);
        assert!(f[0].title.contains("SSH") && f[0].detail.contains("ssh"));
    }

    #[test]
    fn skips_closed_and_filtered() {
        let sample = "Host: 203.0.113.10 ()\tPorts: 22/open/tcp//ssh///, 25/filtered/tcp//smtp///, 3306/closed/tcp//mysql///\n";
        let f = port_findings(&port_entries(sample));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].key, "tcp/22");
    }

    #[test]
    fn empty_output_yields_nothing() {
        assert!(port_findings(&port_entries("")).is_empty());
        assert!(port_findings(&port_entries("# Nmap done\n")).is_empty());
    }

    #[test]
    fn fingerprints_routeros_version_from_banner() {
        let sample = "Host: 203.0.113.1 ()\tPorts: \
            8291/open/tcp//winbox///, \
            21/open/tcp//ftp//MikroTik router ftpd 6.49.3/, \
            22/open/tcp//ssh//MikroTik RouterOS sshd/\n";
        let entries = port_entries(sample);
        let id = fingerprint(&entries).expect("should fingerprint RouterOS");
        assert_eq!(id.product, "routeros");
        assert_eq!(id.vendor, "MikroTik");
        assert_eq!(id.version.as_deref(), Some("6.49.3"));
        // Winbox exposure is flagged and recorded as a mgmt token.
        let mgmt = mgmt_tokens(&entries);
        assert!(mgmt.iter().any(|t| t.ends_with("/8291")));
        let f = port_findings(&entries);
        assert!(f
            .iter()
            .any(|x| x.key == "tcp/8291" && x.severity == Severity::High));
    }
}
