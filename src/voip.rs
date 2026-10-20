//! VoIP posture — SIP OPTIONS probe builder + response parser + PBX fingerprint
//! (pure core). The actual UDP/TCP send to 5060/5061 is the network seam; the
//! message construction and response analysis are here and unit-tested so the
//! fingerprint logic needs no live PBX.

use serde::Serialize;

/// Build a SIP OPTIONS request (RFC 3261 §11) for `host:port`. `branch` makes
/// it deterministic/testable; the live prober passes a unique value.
pub fn build_options_request(host: &str, port: u16, branch: &str) -> String {
    let tgt = format!("sip:{host}:{port}");
    [
        format!("OPTIONS {tgt} SIP/2.0"),
        format!("Via: SIP/2.0/UDP netdefense.local;branch=z9hG4bK{branch}"),
        "Max-Forwards: 70".to_string(),
        "From: \"netdefense\" <sip:netdefense@netdefense.local>;tag=nd".to_string(),
        format!("To: <{tgt}>"),
        format!("Call-ID: {branch}@netdefense.local"),
        "CSeq: 1 OPTIONS".to_string(),
        "User-Agent: netdefense-probe".to_string(),
        "Accept: application/sdp".to_string(),
        "Content-Length: 0".to_string(),
        String::new(),
        String::new(),
    ]
    .join("\r\n")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SipResponse {
    pub status_code: u16,
    pub reason: String,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    pub allow: Option<String>,
}

/// Parse a SIP response status line + headers (tolerant of \r\n or \n).
pub fn parse_sip_response(raw: &str) -> Option<SipResponse> {
    let mut lines = raw.split('\n').map(|l| l.trim_end_matches('\r'));
    let first = lines.next()?;
    let mut it = first.split_whitespace();
    if !it.next()?.starts_with("SIP/") {
        return None;
    }
    let status_code: u16 = it.next()?.parse().ok()?;
    let reason = it.collect::<Vec<_>>().join(" ");

    let (mut server, mut user_agent, mut allow) = (None, None, None);
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let val = v.trim().to_string();
            match k.trim().to_ascii_lowercase().as_str() {
                "server" => server = Some(val),
                "user-agent" => user_agent = Some(val),
                "allow" => allow = Some(val),
                _ => {}
            }
        }
    }
    Some(SipResponse {
        status_code,
        reason,
        server,
        user_agent,
        allow,
    })
}

/// Identify the PBX/softswitch from Server/User-Agent banners.
pub fn fingerprint(
    server: Option<&str>,
    user_agent: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    let hay = format!("{} {}", server.unwrap_or(""), user_agent.unwrap_or("")).to_ascii_lowercase();
    if hay.contains("3cx") {
        Some((
            "3CX",
            "PBX 3CX esposto su SIP — limitare per IP / dietro VPN",
        ))
    } else if hay.contains("asterisk") {
        Some((
            "Asterisk",
            "PBX Asterisk esposto — rischio brute-force/toll-fraud",
        ))
    } else if hay.contains("freeswitch") {
        Some(("FreeSWITCH", "PBX FreeSWITCH esposto"))
    } else if hay.contains("kamailio") || hay.contains("opensips") {
        Some(("SIP proxy", "proxy SIP (Kamailio/OpenSIPS) esposto"))
    } else if hay.contains("cirpack") {
        Some((
            "Cirpack",
            "softswitch Cirpack raggiungibile — superficie critica",
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_request_has_required_lines() {
        let m = build_options_request("198.51.100.9", 5060, "abc123");
        assert!(m.starts_with("OPTIONS sip:198.51.100.9:5060 SIP/2.0\r\n"));
        assert!(m.contains("\r\nCSeq: 1 OPTIONS\r\n"));
        assert!(m.contains("branch=z9hG4bKabc123"));
        assert!(m.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_200_and_401() {
        let r = parse_sip_response(
            "SIP/2.0 200 OK\r\nServer: 3CX Phone System 18\r\nAllow: INVITE, OPTIONS\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.status_code, 200);
        assert_eq!(r.server.as_deref(), Some("3CX Phone System 18"));
        assert_eq!(r.allow.as_deref(), Some("INVITE, OPTIONS"));

        let u = parse_sip_response("SIP/2.0 401 Unauthorized\nUser-Agent: Asterisk PBX 16.2\n\n")
            .unwrap();
        assert_eq!(u.status_code, 401);
        assert_eq!(u.user_agent.as_deref(), Some("Asterisk PBX 16.2"));
    }

    #[test]
    fn non_sip_is_none() {
        assert!(parse_sip_response("HTTP/1.1 200 OK\r\n\r\n").is_none());
    }

    #[test]
    fn fingerprints_pbx() {
        assert_eq!(
            fingerprint(Some("3CX Phone System 18"), None).unwrap().0,
            "3CX"
        );
        assert_eq!(
            fingerprint(None, Some("Asterisk PBX 16.2")).unwrap().0,
            "Asterisk"
        );
        assert_eq!(fingerprint(Some("Cirpack/4.3"), None).unwrap().0, "Cirpack");
        assert!(fingerprint(Some("nginx"), None).is_none());
    }
}
