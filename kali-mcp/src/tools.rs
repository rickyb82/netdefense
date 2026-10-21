//! Registry of exposed tools. Each `ToolDef` maps an MCP tool name to a Kali
//! binary plus a pure function that turns the JSON `arguments` object into a
//! CLI argument vector. Arguments are passed to the process directly (no
//! shell), so there is no shell-injection surface.

use serde_json::{json, Value};

pub type ArgBuilder = fn(&Value) -> Result<Vec<String>, String>;

pub struct ToolDef {
    pub name: &'static str,
    pub bin: &'static str,
    pub description: &'static str,
    pub schema: Value,
    pub build: ArgBuilder,
}

// ---- argument helpers -------------------------------------------------------

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .filter(|x| !x.is_empty())
}

fn req(v: &Value, k: &str) -> Result<String, String> {
    s(v, k).ok_or_else(|| format!("missing required field `{k}`"))
}

fn n(v: &Value, k: &str) -> Option<i64> {
    v.get(k).and_then(|x| x.as_i64())
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn b_default(v: &Value, k: &str, def: bool) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(def)
}

fn extra(v: &Value) -> Vec<String> {
    v.get("extra_args")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn push_kv(a: &mut Vec<String>, flag: &str, val: &str) {
    a.push(flag.to_string());
    a.push(val.to_string());
}

/// Merge the tool-specific property set with the two fields every tool shares.
fn tool_schema(specific: Value, required: &[&str]) -> Value {
    let mut props = match specific {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    props.insert(
        "extra_args".to_string(),
        json!({
            "type": "array",
            "items": { "type": "string" },
            "description": "Extra raw CLI arguments appended verbatim — escape hatch for any flag not modelled below."
        }),
    );
    props.insert(
        "timeout_secs".to_string(),
        json!({
            "type": "integer",
            "minimum": 1,
            "description": "Kill the process after this many seconds (default 300)."
        }),
    );
    json!({
        "type": "object",
        "properties": Value::Object(props),
        "required": required,
    })
}

// ---- registry ---------------------------------------------------------------

pub fn registry() -> Vec<ToolDef> {
    vec![
        // ---------------- recon / scanning ----------------
        ToolDef {
            name: "nmap_scan",
            bin: "nmap",
            description: "Nmap network/port scanner. Discover open ports and services on hosts you are authorised to test.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host, IP, CIDR or range to scan." },
                    "ports": { "type": "string", "description": "Port spec, e.g. \"22,80,443\" or \"1-1000\"." },
                    "top_ports": { "type": "integer", "description": "Scan the N most common ports." },
                    "syn_scan": { "type": "boolean", "description": "TCP SYN scan (-sS, needs root)." },
                    "service_version": { "type": "boolean", "description": "Service/version detection (-sV)." },
                    "os_detect": { "type": "boolean", "description": "OS detection (-O, needs root)." },
                    "scripts": { "type": "string", "description": "NSE scripts, e.g. \"default\" or \"http-title,ssl-cert\"." },
                    "timing": { "type": "integer", "description": "Timing template 0-5 (-T)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "syn_scan") { a.push("-sS".into()); }
                if b(v, "service_version") { a.push("-sV".into()); }
                if b(v, "os_detect") { a.push("-O".into()); }
                if let Some(p) = s(v, "ports") { push_kv(&mut a, "-p", &p); }
                if let Some(tp) = n(v, "top_ports") { push_kv(&mut a, "--top-ports", &tp.to_string()); }
                if let Some(sc) = s(v, "scripts") { a.push(format!("--script={sc}")); }
                if let Some(t) = n(v, "timing") { a.push(format!("-T{}", t.clamp(0, 5))); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "masscan_scan",
            bin: "masscan",
            description: "Masscan high-rate port scanner. Fast sweeps of large address spaces you own.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host, IP or CIDR to scan." },
                    "ports": { "type": "string", "description": "Port spec, e.g. \"0-65535\" or \"80,443\"." },
                    "rate": { "type": "integer", "description": "Packets per second (--rate)." }
                }),
                &["target", "ports"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-p", &req(v, "ports")?);
                if let Some(r) = n(v, "rate") { push_kv(&mut a, "--rate", &r.to_string()); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "whatweb",
            bin: "whatweb",
            description: "WhatWeb web technology fingerprinter.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "URL or host to fingerprint." },
                    "aggression": { "type": "integer", "description": "Aggression level 1-4." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if let Some(ag) = n(v, "aggression") { a.push(format!("--aggression={}", ag.clamp(1, 4))); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "dnsrecon",
            bin: "dnsrecon",
            description: "DNS enumeration (records, zone transfers, brute force).",
            schema: tool_schema(
                json!({
                    "domain": { "type": "string", "description": "Target domain." },
                    "type": { "type": "string", "description": "Enumeration type: std, axfr, brt, srv, ..." }
                }),
                &["domain"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-d", &req(v, "domain")?);
                if let Some(t) = s(v, "type") { push_kv(&mut a, "-t", &t); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "gobuster",
            bin: "gobuster",
            description: "Gobuster directory/DNS/vhost brute forcer.",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target URL (for dir mode)." },
                    "wordlist": { "type": "string", "description": "Path to a wordlist on disk." },
                    "mode": { "type": "string", "description": "Gobuster mode (default \"dir\"): dir, dns, vhost." },
                    "extensions": { "type": "string", "description": "Comma-separated extensions, e.g. \"php,txt\"." },
                    "threads": { "type": "integer", "description": "Concurrent threads." },
                    "status_codes": { "type": "string", "description": "Status codes to treat as found, e.g. \"200,204,301\"." }
                }),
                &["url", "wordlist"],
            ),
            build: |v| {
                let mut a = Vec::new();
                a.push(s(v, "mode").unwrap_or_else(|| "dir".into()));
                push_kv(&mut a, "-u", &req(v, "url")?);
                push_kv(&mut a, "-w", &req(v, "wordlist")?);
                if let Some(e) = s(v, "extensions") { push_kv(&mut a, "-x", &e); }
                if let Some(t) = n(v, "threads") { push_kv(&mut a, "-t", &t.to_string()); }
                if let Some(sc) = s(v, "status_codes") { push_kv(&mut a, "-s", &sc); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- web ----------------
        ToolDef {
            name: "nikto",
            bin: "nikto",
            description: "Nikto web server vulnerability scanner.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host or URL to scan." },
                    "port": { "type": "integer", "description": "Target port." },
                    "ssl": { "type": "boolean", "description": "Force SSL/TLS." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-h", &req(v, "target")?);
                if let Some(p) = n(v, "port") { push_kv(&mut a, "-p", &p.to_string()); }
                if b(v, "ssl") { a.push("-ssl".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "sqlmap",
            bin: "sqlmap",
            description: "sqlmap SQL-injection detection and exploitation. Runs with --batch by default.",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target URL (include parameters)." },
                    "data": { "type": "string", "description": "POST body to test." },
                    "level": { "type": "integer", "description": "Test level 1-5." },
                    "risk": { "type": "integer", "description": "Risk 1-3." },
                    "technique": { "type": "string", "description": "Techniques, e.g. \"BEUSTQ\"." },
                    "dbs": { "type": "boolean", "description": "Enumerate databases (--dbs)." },
                    "batch": { "type": "boolean", "description": "Non-interactive, accept defaults (default true)." }
                }),
                &["url"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-u", &req(v, "url")?);
                if let Some(d) = s(v, "data") { a.push(format!("--data={d}")); }
                if let Some(l) = n(v, "level") { a.push(format!("--level={}", l.clamp(1, 5))); }
                if let Some(r) = n(v, "risk") { a.push(format!("--risk={}", r.clamp(1, 3))); }
                if let Some(t) = s(v, "technique") { a.push(format!("--technique={t}")); }
                if b_default(v, "batch", true) { a.push("--batch".into()); }
                if b(v, "dbs") { a.push("--dbs".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "ffuf",
            bin: "ffuf",
            description: "ffuf web fuzzer. The url must contain the FUZZ keyword.",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target URL containing the FUZZ keyword." },
                    "wordlist": { "type": "string", "description": "Path to a wordlist on disk." },
                    "match_codes": { "type": "string", "description": "Match HTTP codes (-mc), e.g. \"200,301\"." },
                    "filter_codes": { "type": "string", "description": "Filter out HTTP codes (-fc)." },
                    "threads": { "type": "integer", "description": "Concurrent threads (-t)." }
                }),
                &["url", "wordlist"],
            ),
            build: |v| {
                let mut a = Vec::new();
                let url = req(v, "url")?;
                if !url.contains("FUZZ") {
                    return Err("ffuf `url` must contain the FUZZ keyword".into());
                }
                push_kv(&mut a, "-u", &url);
                push_kv(&mut a, "-w", &req(v, "wordlist")?);
                if let Some(mc) = s(v, "match_codes") { push_kv(&mut a, "-mc", &mc); }
                if let Some(fc) = s(v, "filter_codes") { push_kv(&mut a, "-fc", &fc); }
                if let Some(t) = n(v, "threads") { push_kv(&mut a, "-t", &t.to_string()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "wpscan",
            bin: "wpscan",
            description: "WPScan WordPress vulnerability scanner.",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target WordPress URL." },
                    "enumerate": { "type": "string", "description": "What to enumerate, e.g. \"vp,u\" (vuln plugins + users)." },
                    "api_token": { "type": "string", "description": "WPScan API token for vuln data." }
                }),
                &["url"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "--url", &req(v, "url")?);
                a.push("--no-banner".into());
                if let Some(e) = s(v, "enumerate") { push_kv(&mut a, "--enumerate", &e); }
                if let Some(t) = s(v, "api_token") { push_kv(&mut a, "--api-token", &t); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- credentials / cracking ----------------
        ToolDef {
            name: "hydra",
            bin: "hydra",
            description: "THC-Hydra network login brute forcer. For authorised credential testing of your own services.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Target host or IP." },
                    "service": { "type": "string", "description": "Service module, e.g. ssh, ftp, http-get." },
                    "username": { "type": "string", "description": "Single username (-l)." },
                    "userlist": { "type": "string", "description": "Path to a username list (-L)." },
                    "password": { "type": "string", "description": "Single password (-p)." },
                    "passlist": { "type": "string", "description": "Path to a password list (-P)." },
                    "port": { "type": "integer", "description": "Service port (-s)." }
                }),
                &["target", "service"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if let Some(u) = s(v, "username") {
                    push_kv(&mut a, "-l", &u);
                } else if let Some(ul) = s(v, "userlist") {
                    push_kv(&mut a, "-L", &ul);
                }
                if let Some(p) = s(v, "password") {
                    push_kv(&mut a, "-p", &p);
                } else if let Some(pl) = s(v, "passlist") {
                    push_kv(&mut a, "-P", &pl);
                }
                if let Some(port) = n(v, "port") { push_kv(&mut a, "-s", &port.to_string()); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                a.push(req(v, "service")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "john",
            bin: "john",
            description: "John the Ripper password hash cracker.",
            schema: tool_schema(
                json!({
                    "hashfile": { "type": "string", "description": "Path to a file of hashes." },
                    "wordlist": { "type": "string", "description": "Path to a wordlist (--wordlist)." },
                    "format": { "type": "string", "description": "Hash format, e.g. \"raw-md5\", \"sha512crypt\"." }
                }),
                &["hashfile"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if let Some(wl) = s(v, "wordlist") { a.push(format!("--wordlist={wl}")); }
                if let Some(f) = s(v, "format") { a.push(format!("--format={f}")); }
                a.extend(extra(v));
                a.push(req(v, "hashfile")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "hashcat",
            bin: "hashcat",
            description: "hashcat GPU/CPU password hash cracker.",
            schema: tool_schema(
                json!({
                    "hashfile": { "type": "string", "description": "Path to a file of hashes." },
                    "hash_type": { "type": "integer", "description": "Hash mode (-m), e.g. 0 = MD5, 1800 = sha512crypt." },
                    "attack_mode": { "type": "integer", "description": "Attack mode (-a), default 0 = straight/wordlist." },
                    "wordlist": { "type": "string", "description": "Path to a wordlist (for straight attacks)." }
                }),
                &["hashfile"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-a", &n(v, "attack_mode").unwrap_or(0).to_string());
                if let Some(ht) = n(v, "hash_type") { push_kv(&mut a, "-m", &ht.to_string()); }
                a.extend(extra(v));
                a.push(req(v, "hashfile")?);
                if let Some(wl) = s(v, "wordlist") { a.push(wl); }
                Ok(a)
            },
        },
        // ---------------- TLS / SSL ----------------
        ToolDef {
            name: "testssl",
            bin: "testssl.sh",
            description: "testssl.sh TLS/SSL configuration and vulnerability tester.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host, host:port or URL to test." },
                    "fast": { "type": "boolean", "description": "Faster run (--fast): skip some cipher checks." },
                    "severity": { "type": "string", "description": "Only findings at/above this level (--severity), e.g. LOW/MEDIUM/HIGH." },
                    "starttls": { "type": "string", "description": "STARTTLS protocol (--starttls), e.g. smtp, imap, ftp." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "fast") { a.push("--fast".into()); }
                if let Some(sev) = s(v, "severity") { push_kv(&mut a, "--severity", &sev); }
                if let Some(st) = s(v, "starttls") { push_kv(&mut a, "--starttls", &st); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "sslscan",
            bin: "sslscan",
            description: "sslscan: enumerate SSL/TLS protocols, ciphers and certificate of a service.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host or host:port." },
                    "show_certificate": { "type": "boolean", "description": "Print the server certificate (--show-certificate)." },
                    "starttls": { "type": "string", "description": "STARTTLS protocol, e.g. smtp/imap/ftp/pop3 (adds --starttls-<proto>)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "show_certificate") { a.push("--show-certificate".into()); }
                if let Some(st) = s(v, "starttls") { a.push(format!("--starttls-{st}")); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        // ---------------- SMB / AD enumeration ----------------
        ToolDef {
            name: "enum4linux_ng",
            bin: "enum4linux-ng",
            description: "enum4linux-ng SMB/NetBIOS/LDAP enumeration of Windows/Samba hosts.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Target host or IP." },
                    "all": { "type": "boolean", "description": "All simple enumeration (-A)." },
                    "shares": { "type": "boolean", "description": "Enumerate shares (-S)." },
                    "users": { "type": "boolean", "description": "Enumerate users (-U)." },
                    "username": { "type": "string", "description": "Username for authenticated enum (-u)." },
                    "password": { "type": "string", "description": "Password for authenticated enum (-p)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "all") { a.push("-A".into()); }
                if b(v, "shares") { a.push("-S".into()); }
                if b(v, "users") { a.push("-U".into()); }
                if let Some(u) = s(v, "username") { push_kv(&mut a, "-u", &u); }
                if let Some(p) = s(v, "password") { push_kv(&mut a, "-p", &p); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        // ---------------- subdomain / OSINT ----------------
        ToolDef {
            name: "amass",
            bin: "amass",
            description: "OWASP Amass subdomain enumeration (amass enum).",
            schema: tool_schema(
                json!({
                    "domain": { "type": "string", "description": "Root domain to enumerate." },
                    "passive": { "type": "boolean", "description": "Passive mode only (-passive)." },
                    "active": { "type": "boolean", "description": "Active techniques (-active)." },
                    "brute": { "type": "boolean", "description": "Brute-force subdomains (-brute)." }
                }),
                &["domain"],
            ),
            build: |v| {
                let mut a = vec!["enum".to_string()];
                push_kv(&mut a, "-d", &req(v, "domain")?);
                if b(v, "passive") { a.push("-passive".into()); }
                if b(v, "active") { a.push("-active".into()); }
                if b(v, "brute") { a.push("-brute".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- web content discovery ----------------
        ToolDef {
            name: "feroxbuster",
            bin: "feroxbuster",
            description: "feroxbuster fast recursive content/directory discovery.",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target base URL." },
                    "wordlist": { "type": "string", "description": "Path to a wordlist (-w)." },
                    "extensions": { "type": "string", "description": "Comma-separated extensions (-x), e.g. \"php,txt\"." },
                    "threads": { "type": "integer", "description": "Concurrent threads (-t)." },
                    "status_codes": { "type": "string", "description": "Status codes to keep (-s), e.g. \"200,301\"." }
                }),
                &["url"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-u", &req(v, "url")?);
                if let Some(wl) = s(v, "wordlist") { push_kv(&mut a, "-w", &wl); }
                if let Some(e) = s(v, "extensions") { push_kv(&mut a, "-x", &e); }
                if let Some(t) = n(v, "threads") { push_kv(&mut a, "-t", &t.to_string()); }
                if let Some(sc) = s(v, "status_codes") { push_kv(&mut a, "-s", &sc); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- template / vuln scanning ----------------
        ToolDef {
            name: "nuclei",
            bin: "nuclei",
            description: "Nuclei template-based vulnerability scanner (CVEs, exposures, misconfigs, default creds).",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Target URL/host (-u)." },
                    "severity": { "type": "string", "description": "Filter by severity (-severity), e.g. \"critical,high\"." },
                    "tags": { "type": "string", "description": "Template tags (-tags), e.g. \"cve,exposure\"." },
                    "rate_limit": { "type": "integer", "description": "Max requests/sec (-rl)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-u", &req(v, "target")?);
                if let Some(sev) = s(v, "severity") { push_kv(&mut a, "-severity", &sev); }
                if let Some(tags) = s(v, "tags") { push_kv(&mut a, "-tags", &tags); }
                if let Some(rl) = n(v, "rate_limit") { push_kv(&mut a, "-rl", &rl.to_string()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- malware / webshell / host forensics ----------------
        ToolDef {
            name: "yara",
            bin: "yara",
            description: "YARA: scan files/dirs against rules (e.g. webshell/malware signatures).",
            schema: tool_schema(
                json!({
                    "rules": { "type": "string", "description": "Path to a YARA rules file (.yar)." },
                    "target": { "type": "string", "description": "File or directory to scan." },
                    "recursive": { "type": "boolean", "description": "Recurse into directories (-r)." }
                }),
                &["rules", "target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "recursive") { a.push("-r".into()); }
                a.extend(extra(v));
                a.push(req(v, "rules")?);
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "clamscan",
            bin: "clamscan",
            description: "ClamAV scanner: find known malware/webshells in files or a web root.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "File or directory to scan." },
                    "recursive": { "type": "boolean", "description": "Scan directories recursively (-r)." },
                    "infected_only": { "type": "boolean", "description": "Only print infected files (-i)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "recursive") { a.push("-r".into()); }
                if b(v, "infected_only") { a.push("-i".into()); }
                a.extend(extra(v));
                a.push(req(v, "target")?);
                Ok(a)
            },
        },
        ToolDef {
            name: "searchsploit",
            bin: "searchsploit",
            description: "searchsploit: look up known exploits (Exploit-DB) by term or CVE.",
            schema: tool_schema(
                json!({
                    "query": { "type": "string", "description": "Search terms, or a CVE id when `cve` is true." },
                    "cve": { "type": "boolean", "description": "Treat the query as a CVE id (--cve)." },
                    "json": { "type": "boolean", "description": "JSON output (-j)." }
                }),
                &["query"],
            ),
            build: |v| {
                let mut a = Vec::new();
                if b(v, "cve") { a.push("--cve".into()); }
                if b(v, "json") { a.push("-j".into()); }
                a.extend(extra(v));
                let q = req(v, "query")?;
                for term in q.split_whitespace() {
                    a.push(term.to_string());
                }
                Ok(a)
            },
        },
        // ---------------- fast recon (ProjectDiscovery) ----------------
        ToolDef {
            name: "httpx",
            bin: "httpx",
            description: "httpx: fast HTTP probing/fingerprint (title, tech, status) of hosts.",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Target host or URL (-u)." },
                    "title": { "type": "boolean", "description": "Show page title (-title)." },
                    "tech_detect": { "type": "boolean", "description": "Detect technologies (-td)." },
                    "status_code": { "type": "boolean", "description": "Show status code (-sc)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-u", &req(v, "target")?);
                if b(v, "title") { a.push("-title".into()); }
                if b(v, "tech_detect") { a.push("-td".into()); }
                if b(v, "status_code") { a.push("-sc".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "naabu",
            bin: "naabu",
            description: "naabu: fast port scanner (pairs with httpx/nuclei).",
            schema: tool_schema(
                json!({
                    "target": { "type": "string", "description": "Host or CIDR (-host)." },
                    "ports": { "type": "string", "description": "Port spec (-p), e.g. \"80,443,8080\"." },
                    "top_ports": { "type": "integer", "description": "Scan top N ports (-top-ports)." },
                    "rate": { "type": "integer", "description": "Packets per second (-rate)." }
                }),
                &["target"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-host", &req(v, "target")?);
                if let Some(p) = s(v, "ports") { push_kv(&mut a, "-p", &p); }
                if let Some(tp) = n(v, "top_ports") { push_kv(&mut a, "-top-ports", &tp.to_string()); }
                if let Some(r) = n(v, "rate") { push_kv(&mut a, "-rate", &r.to_string()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "subfinder",
            bin: "subfinder",
            description: "subfinder: passive subdomain enumeration.",
            schema: tool_schema(
                json!({
                    "domain": { "type": "string", "description": "Root domain (-d)." },
                    "all_sources": { "type": "boolean", "description": "Use all sources (-all)." },
                    "recursive": { "type": "boolean", "description": "Recursive enumeration (-recursive)." }
                }),
                &["domain"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-d", &req(v, "domain")?);
                if b(v, "all_sources") { a.push("-all".into()); }
                if b(v, "recursive") { a.push("-recursive".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "dnsx",
            bin: "dnsx",
            description: "dnsx: fast DNS resolution/queries (A/AAAA/CNAME, with responses).",
            schema: tool_schema(
                json!({
                    "domain": { "type": "string", "description": "Domain to query (-d)." },
                    "a": { "type": "boolean", "description": "A records (-a)." },
                    "aaaa": { "type": "boolean", "description": "AAAA records (-aaaa)." },
                    "cname": { "type": "boolean", "description": "CNAME records (-cname)." },
                    "resp": { "type": "boolean", "description": "Show the response value (-resp)." }
                }),
                &["domain"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-d", &req(v, "domain")?);
                if b(v, "a") { a.push("-a".into()); }
                if b(v, "aaaa") { a.push("-aaaa".into()); }
                if b(v, "cname") { a.push("-cname".into()); }
                if b(v, "resp") { a.push("-resp".into()); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        // ---------------- web: XSS + parameter discovery ----------------
        ToolDef {
            name: "dalfox",
            bin: "dalfox",
            description: "Dalfox XSS scanner (dalfox url <target>).",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target URL (with parameters)." },
                    "blind": { "type": "string", "description": "Blind XSS callback URL (-b)." }
                }),
                &["url"],
            ),
            build: |v| {
                let mut a = vec!["url".to_string()];
                a.push(req(v, "url")?);
                if let Some(bl) = s(v, "blind") { push_kv(&mut a, "-b", &bl); }
                a.extend(extra(v));
                Ok(a)
            },
        },
        ToolDef {
            name: "arjun",
            bin: "arjun",
            description: "Arjun: discover hidden HTTP parameters (more injection points to test).",
            schema: tool_schema(
                json!({
                    "url": { "type": "string", "description": "Target URL (-u)." },
                    "method": { "type": "string", "description": "HTTP method (-m), GET/POST." },
                    "wordlist": { "type": "string", "description": "Parameter wordlist (-w)." }
                }),
                &["url"],
            ),
            build: |v| {
                let mut a = Vec::new();
                push_kv(&mut a, "-u", &req(v, "url")?);
                if let Some(m) = s(v, "method") { push_kv(&mut a, "-m", &m); }
                if let Some(w) = s(v, "wordlist") { push_kv(&mut a, "-w", &w); }
                a.extend(extra(v));
                Ok(a)
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> ToolDef {
        registry()
            .into_iter()
            .find(|t| t.name == name)
            .expect("tool present")
    }

    fn build(name: &str, args: Value) -> Result<Vec<String>, String> {
        (tool(name).build)(&args)
    }

    #[test]
    fn registry_names_are_unique_and_nonempty() {
        let reg = registry();
        assert!(!reg.is_empty());
        let mut names: Vec<_> = reg.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate tool name in registry");
    }

    #[test]
    fn new_tools_are_registered_and_build() {
        let names: Vec<_> = registry().iter().map(|t| t.name).collect();
        for n in [
            "testssl",
            "sslscan",
            "enum4linux_ng",
            "amass",
            "feroxbuster",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
        }
        // amass builds `enum -d <domain>` with the domain after -d
        let a = build(
            "amass",
            json!({ "domain": "acme.example", "passive": true }),
        )
        .unwrap();
        assert_eq!(a[0], "enum");
        assert_eq!(
            a.windows(2).find(|w| w[0] == "-d").unwrap()[1],
            "acme.example"
        );
        assert!(a.contains(&"-passive".to_string()));
        // testssl puts the target last
        let t = build(
            "testssl",
            json!({ "target": "example.com:443", "fast": true }),
        )
        .unwrap();
        assert_eq!(t.last().unwrap(), "example.com:443");
        assert!(t.contains(&"--fast".to_string()));
        // feroxbuster needs a url
        assert!(build("feroxbuster", json!({})).is_err());
        assert!(build("feroxbuster", json!({ "url": "http://x/" })).is_ok());
    }

    #[test]
    fn control_batch_registered_and_builds() {
        let names: Vec<_> = registry().iter().map(|t| t.name).collect();
        for n in [
            "nuclei",
            "yara",
            "clamscan",
            "searchsploit",
            "httpx",
            "naabu",
            "subfinder",
            "dnsx",
            "dalfox",
            "arjun",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
        }
        // nuclei targets via -u
        let nu = build(
            "nuclei",
            json!({ "target": "https://x", "severity": "high" }),
        )
        .unwrap();
        assert_eq!(
            nu.windows(2).find(|w| w[0] == "-u").unwrap()[1],
            "https://x"
        );
        assert!(nu.contains(&"-severity".to_string()));
        // yara takes rules then target positionally
        let y = build(
            "yara",
            json!({ "rules": "web.yar", "target": "/var/www", "recursive": true }),
        )
        .unwrap();
        assert_eq!(
            &y[y.len() - 2..],
            &["web.yar".to_string(), "/var/www".to_string()]
        );
        assert!(y.contains(&"-r".to_string()));
        // dalfox: `url <target>`
        let d = build("dalfox", json!({ "url": "http://x/?q=1" })).unwrap();
        assert_eq!(d[0], "url");
        assert_eq!(d[1], "http://x/?q=1");
        // searchsploit splits the query into terms
        let ss = build("searchsploit", json!({ "query": "apache 2.4" })).unwrap();
        assert!(ss.contains(&"apache".to_string()) && ss.contains(&"2.4".to_string()));
        // required fields enforced
        assert!(build("nuclei", json!({})).is_err());
        assert!(build("subfinder", json!({})).is_err());
    }

    #[test]
    fn nmap_flags_and_target_order() {
        let a = build(
            "nmap_scan",
            json!({ "target": "10.0.0.0/24", "top_ports": 100, "service_version": true, "timing": 9 }),
        )
        .unwrap();
        assert_eq!(
            a.last().unwrap(),
            "10.0.0.0/24",
            "target must be last positional"
        );
        assert!(a.contains(&"-sV".to_string()));
        assert!(a.contains(&"-T5".to_string()), "timing clamped to 0-5");
        assert_eq!(
            a.windows(2).find(|w| w[0] == "--top-ports").unwrap()[1],
            "100"
        );
    }

    #[test]
    fn missing_required_field_is_an_error() {
        assert!(build("nmap_scan", json!({})).is_err());
        assert!(build("masscan_scan", json!({ "target": "x" })).is_err()); // ports required
    }

    #[test]
    fn ffuf_requires_fuzz_keyword() {
        assert!(build("ffuf", json!({ "url": "http://x/", "wordlist": "/w" })).is_err());
        assert!(build("ffuf", json!({ "url": "http://x/FUZZ", "wordlist": "/w" })).is_ok());
    }

    #[test]
    fn hydra_puts_target_then_service_last() {
        let a = build(
            "hydra",
            json!({ "target": "10.0.0.5", "service": "ssh", "username": "root", "port": 22 }),
        )
        .unwrap();
        let len = a.len();
        assert_eq!(&a[len - 2..], &["10.0.0.5".to_string(), "ssh".to_string()]);
        assert_eq!(a.windows(2).find(|w| w[0] == "-l").unwrap()[1], "root");
    }

    #[test]
    fn sqlmap_batch_on_by_default_off_when_disabled() {
        let on = build("sqlmap", json!({ "url": "http://x/?id=1" })).unwrap();
        assert!(on.contains(&"--batch".to_string()));
        let off = build("sqlmap", json!({ "url": "http://x/?id=1", "batch": false })).unwrap();
        assert!(!off.contains(&"--batch".to_string()));
    }

    #[test]
    fn extra_args_are_appended() {
        let a = build(
            "nmap_scan",
            json!({ "target": "x", "extra_args": ["-Pn", "--open"] }),
        )
        .unwrap();
        assert!(a.contains(&"-Pn".to_string()) && a.contains(&"--open".to_string()));
    }
}
