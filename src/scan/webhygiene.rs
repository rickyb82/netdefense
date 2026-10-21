//! Web hygiene scan for the client websites: a live HTTP GET that grades the
//! security headers, flags plain-HTTP delivery, and detects a content change
//! (defacement) against the stored baseline. Reuses the pure cores in
//! `crate::web`; the HTTP GET is the seam.

use std::time::Duration;

use anyhow::Result;

use super::FindingDraft;
use crate::domain::{Id, Severity};
use crate::store::Store;
use crate::web;

fn draft(key: &str, title: String, detail: String, severity: Severity) -> FindingDraft {
    FindingDraft {
        kind: "web_hygiene".to_string(),
        key: key.to_string(),
        title,
        detail,
        severity,
    }
}

/// Fetch `value` (adding `https://` if no scheme), grade its headers, and diff
/// its content against the asset's stored baseline. `asset_id` cleared the gate.
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

    // Content change / defacement vs the stored baseline.
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

    Ok(out)
}
