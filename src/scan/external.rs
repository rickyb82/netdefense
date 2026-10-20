//! External attack-surface scan: an nmap sweep of the authorised target,
//! parsed from greppable output into one finding per open port.

use anyhow::{anyhow, Result};

use super::{runner, FindingDraft};
use crate::domain::Severity;

/// Run an nmap top-ports scan against `target` and return a finding per open
/// port. `target` has already cleared the authorisation gate.
pub async fn scan(target: &str, timeout_secs: u64) -> Result<Vec<FindingDraft>> {
    let args: Vec<String> = [
        "-Pn",
        "-T4",
        "--top-ports",
        "200",
        "--open",
        "-oG",
        "-",
        target,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let out = runner::run("nmap", &args, timeout_secs).await;
    if out.not_found {
        return Err(anyhow!("nmap is not installed on the scanner host"));
    }
    if out.timed_out {
        return Err(anyhow!("nmap timed out after {timeout_secs}s"));
    }
    if out.stdout.trim().is_empty() && !out.stderr.trim().is_empty() {
        return Err(anyhow!("nmap failed: {}", out.stderr.trim()));
    }
    Ok(parse_greppable(&out.stdout))
}

/// Parse nmap `-oG -` output. Port lines look like:
/// `Host: 1.2.3.4 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\t...`
fn parse_greppable(stdout: &str) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    for line in stdout.lines() {
        let Some(ports_seg) = line
            .split('\t')
            .find_map(|s| s.trim().strip_prefix("Ports:"))
        else {
            continue;
        };
        for entry in ports_seg.split(',') {
            let fields: Vec<&str> = entry.trim().split('/').collect();
            // port / state / proto / owner / service / ...
            if fields.len() < 3 || fields[1] != "open" {
                continue;
            }
            let port = fields[0];
            let proto = fields[2];
            let service = fields.get(4).copied().unwrap_or("").trim();
            let key = format!("{proto}/{port}");
            let title = if service.is_empty() {
                format!("Open port {port}/{proto}")
            } else {
                format!("Open port {port}/{proto} ({service})")
            };
            findings.push(FindingDraft {
                kind: "open_port".to_string(),
                key,
                title,
                detail: format!("nmap reports {port}/{proto} open, service `{service}`"),
                severity: Severity::Info,
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_open_ports_from_greppable() {
        let sample = "# Nmap 7.94 scan\n\
            Host: 203.0.113.10 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///\tIgnored State: closed (997)\n\
            # Nmap done\n";
        let f = parse_greppable(sample);
        let keys: Vec<_> = f.iter().map(|x| x.key.as_str()).collect();
        assert_eq!(keys, ["tcp/22", "tcp/80", "tcp/443"]);
        assert!(f[0].title.contains("ssh"));
    }

    #[test]
    fn skips_closed_and_filtered() {
        let sample = "Host: 203.0.113.10 ()\tPorts: 22/open/tcp//ssh///, 25/filtered/tcp//smtp///, 3306/closed/tcp//mysql///\n";
        let f = parse_greppable(sample);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].key, "tcp/22");
    }

    #[test]
    fn empty_output_yields_nothing() {
        assert!(parse_greppable("").is_empty());
        assert!(parse_greppable("# Nmap done\n").is_empty());
    }
}
