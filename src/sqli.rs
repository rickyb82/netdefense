//! SQL injection detection for a web URL's query parameters.
//!
//! Active, intrusive test — it sends crafted payloads — so it only runs through
//! the authorisation gate (authorised asset + signed RoE), like every scan.
//! Three techniques: error-based (SQL error signatures in the response),
//! boolean-based (TRUE response ~ baseline, FALSE response differs) and
//! time-based (a SLEEP payload delays the response). The payloads, URL
//! manipulation and response analysis are pure and unit-tested; the HTTP
//! sending is the seam (reqwest).

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::domain::Severity;
use crate::scan::FindingDraft;

/// Error strings that reveal the backend DBMS when a quote breaks a query.
pub const ERROR_SIGNATURES: &[(&str, &str)] = &[
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysqli", "MySQL"),
    ("warning: mysql_", "MySQL"),
    ("mysql_fetch", "MySQL"),
    (
        "unclosed quotation mark after the character string",
        "Microsoft SQL Server",
    ),
    (
        "microsoft ole db provider for sql server",
        "Microsoft SQL Server",
    ),
    ("incorrect syntax near", "Microsoft SQL Server"),
    ("pg_query():", "PostgreSQL"),
    ("unterminated quoted string at or near", "PostgreSQL"),
    ("postgresql query failed", "PostgreSQL"),
    ("sqlite3::", "SQLite"),
    ("sqlite_error", "SQLite"),
    ("sqlite3.operationalerror", "SQLite"),
    ("ora-00933", "Oracle"),
    ("ora-01756", "Oracle"),
    ("quoted string not properly terminated", "Oracle"),
    ("sqlstate[", "SQL (generic)"),
];

/// If the body carries a known SQL error, return the DBMS it points to.
pub fn detect_sql_error(body: &str) -> Option<&'static str> {
    let l = body.to_ascii_lowercase();
    ERROR_SIGNATURES
        .iter()
        .find(|(sig, _)| l.contains(sig))
        .map(|(_, db)| *db)
}

/// Query-parameter names in a URL (empty if there is no query string).
pub fn params_of(url: &str) -> Vec<String> {
    match url.split_once('?') {
        None => Vec::new(),
        Some((_, q)) => q
            .split('&')
            .filter_map(|kv| kv.split('=').next())
            .filter(|k| !k.is_empty())
            .map(|k| k.to_string())
            .collect(),
    }
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Append `payload` to the value of `param` in `url` (URL-encoded), leaving the
/// other parameters untouched.
pub fn inject(url: &str, param: &str, payload: &str) -> String {
    let Some((base, q)) = url.split_once('?') else {
        return url.to_string();
    };
    let enc = percent_encode(payload);
    let newq: Vec<String> = q
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            if k == param {
                format!("{k}={v}{enc}")
            } else {
                kv.to_string()
            }
        })
        .collect();
    format!("{base}?{}", newq.join("&"))
}

/// Crude response-similarity in [0,1] based on length (cheap, enough to tell a
/// boolean TRUE page from a FALSE one). 1.0 = identical length.
pub fn similarity(a: &str, b: &str) -> f64 {
    let (la, lb) = (a.len() as f64, b.len() as f64);
    let m = la.max(lb);
    if m == 0.0 {
        1.0
    } else {
        1.0 - (la - lb).abs() / m
    }
}

const MAX_PARAMS: usize = 15;
const TIME_PAYLOAD_SECS: u64 = 5;

fn finding(key: String, title: String, detail: String, severity: Severity) -> FindingDraft {
    FindingDraft {
        kind: "sqli".to_string(),
        key,
        title,
        detail,
        severity,
    }
}

/// Probe every query parameter of `url` for SQL injection. `target` has cleared
/// the authorisation gate.
pub async fn scan(url: &str, timeout_secs: u64) -> Result<Vec<FindingDraft>> {
    let params = params_of(url);
    if params.is_empty() {
        return Ok(vec![finding(
            "sqli/no-params".into(),
            "Nessun parametro da testare".into(),
            format!(
                "L'URL `{url}` non ha query string. Fornire un URL con parametri, es. `?id=1`."
            ),
            Severity::Info,
        )]);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;

    let (baseline_body, baseline_ms) = fetch(&client, url).await.unwrap_or_default();
    let mut findings = Vec::new();

    for p in params.iter().take(MAX_PARAMS) {
        // --- error-based ---
        let mut flagged = false;
        for payload in ["'", "\"", "')", "';--", "\"))"] {
            if let Ok((body, _)) = fetch(&client, &inject(url, p, payload)).await {
                if let Some(db) = detect_sql_error(&body) {
                    findings.push(finding(
                        format!("sqli/{p}/error"),
                        format!("SQL injection (error-based) sul parametro `{p}`"),
                        format!("Il payload `{payload}` provoca un errore SQL ({db}): il parametro è iniettabile. Usare query parametrizzate / prepared statement."),
                        Severity::Critical,
                    ));
                    flagged = true;
                    break;
                }
            }
        }
        if flagged {
            continue;
        }

        // --- boolean-based ---
        let t = fetch(&client, &inject(url, p, "' AND '1'='1")).await;
        let f = fetch(&client, &inject(url, p, "' AND '1'='2")).await;
        if let (Ok((tb, _)), Ok((fb, _))) = (&t, &f) {
            let st = similarity(tb, &baseline_body);
            let sf = similarity(fb, &baseline_body);
            if st >= 0.97 && sf < 0.90 {
                findings.push(finding(
                    format!("sqli/{p}/boolean"),
                    format!("Probabile SQL injection (boolean-based) sul parametro `{p}`"),
                    format!("La risposta alla condizione VERA somiglia al baseline ({st:.2}), quella FALSA diverge ({sf:.2})."),
                    Severity::High,
                ));
                continue;
            }
        }

        // --- time-based (only if the site is normally fast) ---
        if baseline_ms < 2000 {
            let payload = format!("' AND SLEEP({TIME_PAYLOAD_SECS})-- -");
            if let Ok((_, ms)) = fetch(&client, &inject(url, p, &payload)).await {
                if ms >= u128::from((TIME_PAYLOAD_SECS - 1) * 1000) {
                    findings.push(finding(
                        format!("sqli/{p}/time"),
                        format!("Probabile SQL injection (time-based) sul parametro `{p}`"),
                        format!("Il payload SLEEP({TIME_PAYLOAD_SECS}) ha ritardato la risposta a {ms} ms (baseline {baseline_ms} ms)."),
                        Severity::High,
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(finding(
            "sqli/clean".into(),
            "Nessuna SQL injection rilevata".into(),
            format!(
                "Testati {} parametri (error/boolean/time-based).",
                params.len().min(MAX_PARAMS)
            ),
            Severity::Info,
        ));
    }
    Ok(findings)
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<(String, u128)> {
    let start = Instant::now();
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;
    Ok((body, start.elapsed().as_millis()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dbms_from_error_text() {
        assert_eq!(
            detect_sql_error(
                "Warning: mysqli_fetch_array(): You have an error in your SQL syntax near"
            ),
            Some("MySQL")
        );
        assert_eq!(
            detect_sql_error("Unclosed quotation mark after the character string ''."),
            Some("Microsoft SQL Server")
        );
        assert_eq!(
            detect_sql_error("ORA-01756: quoted string not properly terminated"),
            Some("Oracle")
        );
        assert_eq!(detect_sql_error("<html>tutto ok</html>"), None);
    }

    #[test]
    fn extracts_params() {
        assert_eq!(params_of("http://x/p.php?id=1&cat=5"), vec!["id", "cat"]);
        assert!(params_of("http://x/p.php").is_empty());
    }

    #[test]
    fn inject_only_targets_the_named_param() {
        assert_eq!(
            inject("http://x/p?id=1&cat=5", "id", "'"),
            "http://x/p?id=1%27&cat=5"
        );
        assert_eq!(
            inject("http://x/p?id=1&cat=5", "cat", " AND 1=1"),
            "http://x/p?id=1&cat=5%20AND%201%3D1"
        );
        // no query string -> unchanged
        assert_eq!(inject("http://x/p", "id", "'"), "http://x/p");
    }

    #[test]
    fn similarity_bounds() {
        assert_eq!(similarity("abcd", "abcd"), 1.0);
        assert!(similarity("abcd", "ab") < 1.0);
        assert_eq!(similarity("", ""), 1.0);
    }
}
