//! Availability / reachability probe — the DoS/DDoS early-warning scan.
//!
//! For a URL or domain it does a live HTTP GET and reports the status and
//! latency; for a bare host it tries a TCP connect to the usual ports. A target
//! that was reachable and is now unreachable flips the finding key, so the
//! baseline diff raises an alert — the signal that a service has gone down.
//! The status→severity mapping is pure and unit-tested; the network I/O is the
//! seam.

use std::time::{Duration, Instant};

use anyhow::Result;

use super::FindingDraft;
use crate::domain::{AssetKind, Severity};

/// Latency above this (ms) is flagged as degraded even while reachable.
const SLOW_MS: u128 = 3000;

fn draft(key: &str, title: String, detail: String, severity: Severity) -> FindingDraft {
    FindingDraft {
        kind: "availability".to_string(),
        key: key.to_string(),
        title,
        detail,
        severity,
    }
}

/// Severity for an HTTP status seen on an availability probe: 2xx/3xx is fine,
/// 4xx means reachable-but-erroring, 5xx (and anything else) is a server fault.
pub fn http_severity(status: u16) -> Severity {
    match status {
        200..=399 => Severity::Info,
        400..=499 => Severity::Low,
        _ => Severity::High,
    }
}

/// Probe `value` (interpreted per `kind`) for availability.
pub async fn scan(kind: AssetKind, value: &str, timeout_secs: u64) -> Result<Vec<FindingDraft>> {
    match kind {
        AssetKind::CidrRange => Ok(vec![draft(
            "availability/n-a",
            "Non applicabile".into(),
            "Il controllo di disponibilità non si applica a un range CIDR; usalo su host, dominio o URL.".into(),
            Severity::Info,
        )]),
        AssetKind::Url => Ok(http_probe(value, value, timeout_secs).await),
        AssetKind::Domain => {
            // Prefer HTTPS; fall back to plain HTTP only if HTTPS is unreachable.
            let out = http_probe(&format!("https://{value}/"), value, timeout_secs).await;
            if out.iter().any(|f| f.key == "availability/unreachable") {
                let alt = http_probe(&format!("http://{value}/"), value, timeout_secs).await;
                if !alt.iter().any(|f| f.key == "availability/unreachable") {
                    return Ok(alt);
                }
            }
            Ok(out)
        }
        AssetKind::Host => Ok(tcp_probe(value, timeout_secs).await),
    }
}

async fn http_probe(url: &str, label: &str, timeout_secs: u64) -> Vec<FindingDraft> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return vec![draft(
                "availability/error",
                "Errore client HTTP".into(),
                e.to_string(),
                Severity::Medium,
            )]
        }
    };
    let start = Instant::now();
    match client.get(url).send().await {
        Ok(resp) => {
            let ms = start.elapsed().as_millis();
            let status = resp.status().as_u16();
            let mut out = vec![draft(
                "availability/reachable",
                format!("Raggiungibile · HTTP {status}"),
                format!("{label} ha risposto HTTP {status} in {ms} ms."),
                http_severity(status),
            )];
            if ms >= SLOW_MS {
                out.push(draft(
                    "availability/slow",
                    "Latenza elevata".into(),
                    format!("Risposta in {ms} ms (soglia {SLOW_MS} ms)."),
                    Severity::Low,
                ));
            }
            out
        }
        Err(e) => vec![draft(
            "availability/unreachable",
            "Irraggiungibile".into(),
            format!(
                "{label} non risponde: {e}. Possibile indisponibilità (DoS/DDoS, link giù o servizio fermo)."
            ),
            Severity::Critical,
        )],
    }
}

async fn tcp_probe(host: &str, timeout_secs: u64) -> Vec<FindingDraft> {
    let to = Duration::from_secs(timeout_secs.clamp(1, 10));
    for port in [443u16, 80, 22] {
        let start = Instant::now();
        match tokio::time::timeout(to, tokio::net::TcpStream::connect(format!("{host}:{port}")))
            .await
        {
            Ok(Ok(_)) => {
                let ms = start.elapsed().as_millis();
                return vec![draft(
                    "availability/reachable",
                    format!("Raggiungibile · TCP {port}"),
                    format!("{host} accetta connessioni TCP sulla porta {port} ({ms} ms)."),
                    Severity::Info,
                )];
            }
            _ => continue,
        }
    }
    vec![draft(
        "availability/unreachable",
        "Irraggiungibile".into(),
        format!(
            "{host} non accetta connessioni su 443/80/22. Possibile indisponibilità (DoS/DDoS, link giù o host spento)."
        ),
        Severity::Critical,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_severity_bands() {
        assert_eq!(http_severity(200), Severity::Info);
        assert_eq!(http_severity(301), Severity::Info);
        assert_eq!(http_severity(404), Severity::Low);
        assert_eq!(http_severity(500), Severity::High);
        assert_eq!(http_severity(502), Severity::High);
    }

    #[tokio::test]
    async fn cidr_range_is_not_applicable() {
        let out = scan(AssetKind::CidrRange, "10.0.0.0/24", 5).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key, "availability/n-a");
        assert_eq!(out[0].severity, Severity::Info);
    }
}
