//! Web hygiene scan for the client websites. A live HTTP GET that:
//!  - grades the security headers and flags plain-HTTP delivery,
//!  - fingerprints the server tech and the CMS (WordPress / Joomla / Drupal),
//!  - flags mixed content (CSS/JS/images loaded over HTTP on an HTTPS page),
//!  - detects a content change (defacement) against the stored baseline, and
//!  - crawls the home page for same-host links with query parameters and runs
//!    the SQL-injection probe against them automatically.
//!
//! Reuses the pure cores in `crate::web` and the SQLi engine in `crate::sqli`;
//! the HTTP GETs are the seam.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Result;

use super::FindingDraft;
use crate::domain::{Id, Severity};
use crate::store::Store;
use crate::web;

/// Cap on how many discovered parametric pages we probe for SQLi in one scan.
const MAX_SQLI_PAGES: usize = 5;

fn draft(key: &str, title: String, detail: String, severity: Severity) -> FindingDraft {
    FindingDraft {
        kind: "web_hygiene".to_string(),
        key: key.to_string(),
        title,
        detail,
        severity,
    }
}

fn header_val(h: &reqwest::header::HeaderMap, name: &str) -> String {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

pub async fn scan(
    store: &Store,
    asset_id: Id,
    value: &str,
    timeout_secs: u64,
) -> Result<Vec<FindingDraft>> {
    let url = if value.starts_with("http://") || value.starts_with("https://") {
        value.to_string()
    } else {
        format!("https://{value}/")
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(vec![draft(
                "webhyg/unreachable",
                "Sito non raggiungibile".into(),
                format!("{url} non risponde: {e}."),
                Severity::High,
            )])
        }
    };

    let final_url = resp.url().clone();
    let is_https = final_url.scheme() == "https";
    let status = resp.status().as_u16();
    let header_names: Vec<String> = resp
        .headers()
        .keys()
        .map(|k| k.as_str().to_string())
        .collect();
    let server = header_val(resp.headers(), "server");
    let powered = header_val(resp.headers(), "x-powered-by");
    let x_generator = header_val(resp.headers(), "x-generator");
    let body = resp.text().await.unwrap_or_default();

    let mut out = Vec::new();

    if !is_https {
        out.push(draft(
            "webhyg/no-tls",
            "Servito senza TLS".into(),
            format!("Il sito risponde su HTTP non cifrato ({final_url})."),
            Severity::Medium,
        ));
    }

    // --- security headers ---
    let missing = web::missing_security_headers(&header_names);
    let grade = web::header_grade(missing.len());
    for m in &missing {
        let sev = if *m == "HSTS" || *m == "CSP" {
            Severity::Medium
        } else {
            Severity::Low
        };
        out.push(draft(
            &format!("webhyg/header/{m}"),
            format!("Header di sicurezza mancante: {m}"),
            format!("La risposta non include l'header {m}."),
            sev,
        ));
    }
    out.push(draft(
        "webhyg/grade",
        format!("Voto header di sicurezza: {grade}"),
        format!(
            "{} header di sicurezza mancanti su 5 (HTTP {status}).",
            missing.len()
        ),
        Severity::Info,
    ));

    // --- server tech / CMS fingerprint ---
    if !server.is_empty() || !powered.is_empty() {
        out.push(draft(
            "webhyg/server",
            "Tecnologia server".into(),
            format!(
                "Server: {} · X-Powered-By: {}",
                if server.is_empty() { "n/d" } else { &server },
                if powered.is_empty() { "n/d" } else { &powered }
            ),
            Severity::Info,
        ));
    }
    if let Some((cms, ver)) = web::detect_cms(&server, &x_generator, &body) {
        let vshow = ver.clone().unwrap_or_else(|| "versione n/d".into());
        let extra = if cms == "WordPress" {
            " Per plugin/temi vulnerabili usa wpscan con un API token WPScan (env WPSCAN_API_TOKEN); il core è correlato alle CVE automaticamente."
        } else {
            ""
        };
        out.push(draft(
            &format!("webhyg/cms/{}", cms.to_ascii_lowercase()),
            format!("CMS rilevato: {cms} {vshow}"),
            format!(
                "Rilevato {cms} (versione {vshow}). Tenere il core e le estensioni aggiornati.{extra}"
            ),
            Severity::Low,
        ));
        // Tie the CMS core/version into the inventory + CVE correlation, like
        // the surface scan does for network appliances.
        let facts = crate::fleet::DeviceFacts {
            asset_id,
            vendor: cms.clone(),
            product: cms.to_ascii_lowercase(),
            version: ver,
            mgmt: vec![],
        };
        store.upsert_device_facts(&facts)?;
        let _ = crate::fleet::run_correlation(store)?;
    }

    // --- mixed content (HTTP resources on an HTTPS page) ---
    if is_https {
        let mc = web::mixed_content(&body);
        if !mc.is_empty() {
            let sample: Vec<&str> = mc.iter().take(3).map(String::as_str).collect();
            out.push(draft(
                "webhyg/mixed-content",
                "Contenuto misto (risorse via HTTP)".into(),
                format!(
                    "{} risorse (CSS/JS/immagini) caricate su http:// in una pagina https:// — possono essere bloccate dal browser o manomesse. Es.: {}",
                    mc.len(),
                    sample.join(", ")
                ),
                Severity::Medium,
            ));
        }
    }

    // --- content change / defacement vs the stored baseline ---
    let hash = web::content_hash(&web::normalize_body(&body));
    let prev = store.get_web_content_hash(asset_id)?;
    if web::change_verdict(prev.as_deref(), &hash) == web::ChangeVerdict::Changed {
        out.push(draft(
            "webhyg/content-changed",
            "Contenuto cambiato (possibile defacement)".into(),
            "L'hash del contenuto normalizzato è cambiato rispetto alla baseline precedente."
                .into(),
            Severity::Medium,
        ));
    }
    store.upsert_web_baseline(asset_id, &hash, grade, None)?;

    // --- crawl same-host parametric pages and probe them for SQLi ---
    let mut targets: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if final_url.query().is_some() {
        let s = final_url.as_str().to_string();
        seen.insert(s.clone());
        targets.push(s);
    }
    for href in web::extract_hrefs(&body) {
        if targets.len() >= MAX_SQLI_PAGES {
            break;
        }
        if let Ok(u) = final_url.join(&href) {
            let same_host = u.host_str().is_some() && u.host_str() == final_url.host_str();
            let web_scheme = u.scheme() == "http" || u.scheme() == "https";
            if same_host && web_scheme && u.query().is_some() {
                let s = u.as_str().to_string();
                if seen.insert(s.clone()) {
                    targets.push(s);
                }
            }
        }
    }

    if targets.is_empty() {
        out.push(draft(
            "webhyg/sqli/no-params",
            "Nessuna pagina con parametri trovata".into(),
            "Il crawl della home non ha trovato URL con query string da testare per SQL injection."
                .into(),
            Severity::Info,
        ));
    } else {
        let mut vulns = 0;
        for t in &targets {
            let sub = crate::sqli::scan(t, timeout_secs).await.unwrap_or_default();
            for f in sub {
                // Keep only the positive SQLi findings (error/boolean/time); the
                // per-page "clean"/"no-params" infos would just be noise here.
                if f.key.contains("/error") || f.key.contains("/boolean") || f.key.contains("/time")
                {
                    vulns += 1;
                    out.push(FindingDraft {
                        kind: "web_hygiene".to_string(),
                        key: format!("webhyg/{}@{t}", f.key),
                        title: f.title,
                        detail: format!("{} [pagina: {t}]", f.detail),
                        severity: f.severity,
                    });
                }
            }
        }
        out.push(draft(
            "webhyg/sqli/tested",
            format!("SQLi: {} pagine con parametri testate", targets.len()),
            format!(
                "Pagine testate automaticamente: {}. Vulnerabilità rilevate: {vulns}.",
                targets.len()
            ),
            if vulns > 0 {
                Severity::High
            } else {
                Severity::Info
            },
        ));
    }

    Ok(out)
}
