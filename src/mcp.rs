//! Unified MCP server for the netdefense app (stdio, JSON-RPC 2.0).
//!
//! Exposes netdefense's own operations as `nd_*` tools (clients, devices,
//! authorization, scans incl. SQL injection, findings, alerts) AND connects the
//! whole kali-mcp tool catalogue (nmap, sqlmap, nikto, …) reused from the
//! `kali-mcp` library — so one MCP endpoint drives the app and the Kali tools.
//!
//! Run with: `netdefense mcp`. Native tools go through the same code paths as
//! the HTTP API (so scans still pass the authorization gate); Kali tools run as
//! subprocesses via kali-mcp's runner.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::domain::*;
use crate::store::Store;

const SERVER_NAME: &str = "netdefense";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PROTOCOL: &str = "2025-06-18";
const DEFAULT_TIMEOUT: u64 = 300;
const MAX_OUTPUT: usize = 200_000;

type SharedOut = Arc<Mutex<tokio::io::Stdout>>;

pub async fn serve(store: Store) {
    let stdout: SharedOut = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                let store = store.clone();
                let out = stdout.clone();
                tasks.spawn(async move { handle_line(&line, store, out).await });
                while tasks.try_join_next().is_some() {}
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("netdefense mcp: stdin read error: {e}");
                break;
            }
        }
    }
    while tasks.join_next().await.is_some() {}
}

async fn handle_line(line: &str, store: Store, out: SharedOut) {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            write_msg(
                &out,
                &error_msg(Value::Null, -32700, &format!("parse error: {e}")),
            )
            .await;
            return;
        }
    };
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let pv = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL)
                .to_string();
            respond(
                &out,
                id,
                json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
                }),
            )
            .await;
        }
        "ping" => respond(&out, id, json!({})).await,
        "tools/list" => respond(&out, id, json!({ "tools": tool_list() })).await,
        "tools/call" => {
            let result = call_tool(&store, &params).await;
            respond(&out, id, result).await;
        }
        _ => {
            if let Some(id) = id {
                write_msg(
                    &out,
                    &error_msg(id, -32601, &format!("method not found: {method}")),
                )
                .await;
            }
        }
    }
}

/// Native netdefense tools + the connected kali-mcp catalogue.
pub fn tool_list() -> Vec<Value> {
    let mut list = native_tools();
    for t in kali_mcp::tools::registry() {
        list.push(json!({ "name": t.name, "description": t.description, "inputSchema": t.schema }));
    }
    list
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

fn native_tools() -> Vec<Value> {
    vec![
        json!({ "name": "nd_add_client", "description": "netdefense: add a client.",
            "inputSchema": obj(json!({ "name": {"type":"string"}, "contact_email": {"type":"string"} }), &["name"]) }),
        json!({ "name": "nd_add_device", "description": "netdefense: add a device/asset to a client (starts Pending; must be authorized before scanning).",
            "inputSchema": obj(json!({ "client_id": {"type":"string"}, "kind": {"type":"string","description":"host|domain|url|cidr_range"}, "value": {"type":"string"} }), &["client_id","kind","value"]) }),
        json!({ "name": "nd_authorize", "description": "netdefense: authorize an asset for scanning (sets Active with a signed RoE reference).",
            "inputSchema": obj(json!({ "asset_id": {"type":"string"}, "roe_reference": {"type":"string"} }), &["asset_id","roe_reference"]) }),
        json!({ "name": "nd_scan", "description": "netdefense: run a scan on an authorized asset. kind = external_surface | sql_injection.",
            "inputSchema": obj(json!({ "asset_id": {"type":"string"}, "kind": {"type":"string"} }), &["asset_id","kind"]) }),
        json!({ "name": "nd_list_assets", "description": "netdefense: list a client's devices.",
            "inputSchema": obj(json!({ "client_id": {"type":"string"} }), &["client_id"]) }),
        json!({ "name": "nd_findings", "description": "netdefense: list findings for an asset.",
            "inputSchema": obj(json!({ "asset_id": {"type":"string"} }), &["asset_id"]) }),
        json!({ "name": "nd_alerts", "description": "netdefense: list all alerts.",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "nd_overview", "description": "netdefense: rollup counts (devices by auth status, alerts/findings by severity, scans by status, CVE archive size and CVE↔device matches).",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "nd_cve_import", "description": "netdefense: import CVEs from NVD for a product (keyword token such as routeros, 3cx, junos, huawei), or the whole fleet if omitted, then correlate. Can take a while.",
            "inputSchema": obj(json!({ "product": {"type":"string","description":"optional product/vendor, e.g. routeros or mikrotik"} }), &[]) }),
        json!({ "name": "nd_cve_correlate", "description": "netdefense: correlate stored CVEs against device facts; returns how many new alerts were raised.",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "nd_cve_list", "description": "netdefense: how many CVEs are stored and the most recent ids.",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "nd_set_facts", "description": "netdefense: record a device's vendor/product/version (product is a fleet key like routeros), then correlate CVEs — use when you learn a device's version.",
            "inputSchema": obj(json!({ "asset_id": {"type":"string"}, "vendor": {"type":"string"}, "product": {"type":"string"}, "version": {"type":"string"} }), &["asset_id","vendor","product"]) }),
        json!({ "name": "web_fetch", "description": "Fetch a web page over HTTP(S) and return its text (truncated). Use to look up CVE details, vendor advisories or other pages on the internet.",
            "inputSchema": obj(json!({ "url": {"type":"string"}, "max_chars": {"type":"integer"} }), &["url"]) }),
        json!({ "name": "ssh_exec", "description": "SSH into a device with the given credentials (password or private key) and run a command — e.g. apply a patch/upgrade on an appliance (RouterOS, Linux, …). Credentials stay local; the password is passed via env, not argv.",
            "inputSchema": obj(json!({
                "host": {"type":"string"},
                "username": {"type":"string"},
                "command": {"type":"string","description":"comando remoto, es. '/system package update install' su RouterOS"},
                "password": {"type":"string","description":"opzionale (richiede sshpass installato)"},
                "key_path": {"type":"string","description":"opzionale: path a una chiave privata sul server"},
                "port": {"type":"integer"},
                "timeout_secs": {"type":"integer"}
            }), &["host","username","command"]) }),
    ]
}

// ---- dispatch ----

async fn call_tool(store: &Store, params: &Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return tool_error("missing `name` in tools/call params");
    };
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let (text, is_err) = exec_tool(store, name, &args).await;
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_err })
}

/// Execute one tool — a native `nd_*` operation or a kali tool — and return its
/// output text and whether it errored. Shared by the MCP server and the in-app
/// chat agent, so both reach the tools through exactly the same code path (and
/// native scans still pass the authorisation gate).
pub async fn exec_tool(store: &Store, name: &str, args: &Value) -> (String, bool) {
    if let Some(res) = call_native(store, name, args).await {
        return match res {
            Ok(text) => (text, false),
            Err(e) => (e, true),
        };
    }
    // Not a native tool → delegate to the connected kali-mcp catalogue.
    let reg = kali_mcp::tools::registry();
    let Some(def) = reg.iter().find(|t| t.name == name) else {
        return (format!("unknown tool `{name}`"), true);
    };
    let cli = match (def.build)(args) {
        Ok(a) => a,
        Err(e) => return (format!("invalid arguments for `{name}`: {e}"), true),
    };
    let timeout = args
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_TIMEOUT);
    let o = kali_mcp::runner::run(def.bin, &cli, timeout).await;
    let v = format_kali(def.bin, &cli, &o);
    let text = v
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let is_err = v.get("isError").and_then(Value::as_bool).unwrap_or(false);
    (text, is_err)
}

async fn call_native(store: &Store, name: &str, args: &Value) -> Option<Result<String, String>> {
    match name {
        "nd_add_client" => Some(nd_add_client(store, args)),
        "nd_add_device" => Some(nd_add_device(store, args)),
        "nd_authorize" => Some(nd_authorize(store, args)),
        "nd_list_assets" => Some(nd_list_assets(store, args)),
        "nd_findings" => Some(nd_findings(store, args)),
        "nd_alerts" => Some(nd_alerts(store)),
        "nd_scan" => Some(nd_scan(store, args).await),
        "nd_overview" => Some(nd_overview(store)),
        "nd_cve_correlate" => Some(nd_cve_correlate(store)),
        "nd_cve_list" => Some(nd_cve_list(store)),
        "nd_set_facts" => Some(nd_set_facts(store, args)),
        "nd_cve_import" => Some(nd_cve_import(store, args).await),
        "web_fetch" => Some(web_fetch(args).await),
        "ssh_exec" => Some(ssh_exec(args).await),
        _ => None,
    }
}

// ---- native handlers ----

fn gs(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}
fn greq(v: &Value, k: &str) -> Result<String, String> {
    gs(v, k).ok_or_else(|| format!("missing required field `{k}`"))
}
fn guuid(v: &Value, k: &str) -> Result<Uuid, String> {
    Uuid::parse_str(&greq(v, k)?).map_err(|_| format!("`{k}` is not a valid id"))
}
fn as_json<T: serde::Serialize>(t: &T) -> Result<String, String> {
    serde_json::to_string_pretty(t).map_err(|e| e.to_string())
}

fn nd_add_client(store: &Store, a: &Value) -> Result<String, String> {
    let c = Client {
        id: Uuid::new_v4(),
        name: greq(a, "name")?,
        contact_email: gs(a, "contact_email").unwrap_or_default(),
        created_at: Utc::now(),
    };
    store.insert_client(&c).map_err(|e| e.to_string())?;
    as_json(&c)
}

fn nd_add_device(store: &Store, a: &Value) -> Result<String, String> {
    let client_id = guuid(a, "client_id")?;
    if store
        .get_client(client_id)
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err("client not found".into());
    }
    let kind =
        AssetKind::from_db(&greq(a, "kind")?).ok_or("kind must be host|domain|url|cidr_range")?;
    let asset = Asset {
        id: Uuid::new_v4(),
        client_id,
        kind,
        value: greq(a, "value")?,
        auth_status: AuthStatus::Pending,
        authorized_until: None,
        window_start: None,
        window_end: None,
        roe_reference: None,
        created_at: Utc::now(),
    };
    store.insert_asset(&asset).map_err(|e| e.to_string())?;
    as_json(&asset)
}

fn nd_authorize(store: &Store, a: &Value) -> Result<String, String> {
    let id = guuid(a, "asset_id")?;
    if store.get_asset(id).map_err(|e| e.to_string())?.is_none() {
        return Err("asset not found".into());
    }
    store
        .update_asset_authorization(
            id,
            AuthStatus::Active,
            None,
            None,
            None,
            Some(greq(a, "roe_reference")?),
        )
        .map_err(|e| e.to_string())?;
    as_json(&store.get_asset(id).map_err(|e| e.to_string())?)
}

fn nd_list_assets(store: &Store, a: &Value) -> Result<String, String> {
    let client_id = guuid(a, "client_id")?;
    as_json(&store.list_assets(client_id).map_err(|e| e.to_string())?)
}

fn nd_findings(store: &Store, a: &Value) -> Result<String, String> {
    let asset_id = guuid(a, "asset_id")?;
    as_json(
        &store
            .list_findings_for_asset(asset_id)
            .map_err(|e| e.to_string())?,
    )
}

fn nd_alerts(store: &Store) -> Result<String, String> {
    as_json(&store.list_alerts().map_err(|e| e.to_string())?)
}

fn nd_overview(store: &Store) -> Result<String, String> {
    as_json(&store.overview_counts().map_err(|e| e.to_string())?)
}

fn nd_cve_correlate(store: &Store) -> Result<String, String> {
    let n = crate::fleet::run_correlation(store).map_err(|e| e.to_string())?;
    Ok(json!({ "alerts_raised": n }).to_string())
}

fn nd_cve_list(store: &Store) -> Result<String, String> {
    let cves = store.list_cves().map_err(|e| e.to_string())?;
    let recent: Vec<&str> = cves.iter().take(30).map(|c| c.id.as_str()).collect();
    Ok(json!({ "count": cves.len(), "recent": recent }).to_string())
}

fn nd_set_facts(store: &Store, a: &Value) -> Result<String, String> {
    let asset_id = guuid(a, "asset_id")?;
    if store
        .get_asset(asset_id)
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err("asset not found".into());
    }
    let facts = crate::fleet::DeviceFacts {
        asset_id,
        vendor: greq(a, "vendor")?,
        product: map_product(&greq(a, "product")?),
        version: gs(a, "version"),
        mgmt: vec![],
    };
    store
        .upsert_device_facts(&facts)
        .map_err(|e| e.to_string())?;
    let raised = crate::fleet::run_correlation(store).map_err(|e| e.to_string())?;
    as_json(&json!({ "facts": facts, "alerts_raised": raised }))
}

/// Map a user-supplied product/vendor to a fleet CPE token (so correlation
/// keys line up), falling back to the lowercased input.
fn map_product(input: &str) -> String {
    for p in crate::fleet::catalog() {
        if p.key.eq_ignore_ascii_case(input)
            || p.cpe_token.eq_ignore_ascii_case(input)
            || p.vendor.eq_ignore_ascii_case(input)
        {
            return p.cpe_token.to_string();
        }
    }
    input.to_ascii_lowercase()
}

async fn nd_cve_import(store: &Store, a: &Value) -> Result<String, String> {
    let product = gs(a, "product").map(|p| map_product(&p));
    let cfg = crate::nvd::NvdConfig::from_env();
    let fetcher = crate::nvd::ReqwestFetcher::new().map_err(|e| e.to_string())?;
    let s = crate::nvd::import(store, &cfg, &fetcher, product.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let total = store.list_cves().map(|c| c.len()).unwrap_or(0);
    Ok(json!({
        "imported": s.imported,
        "alerts_raised": s.alerts_raised,
        "cves_total": total,
        "product": product,
    })
    .to_string())
}

async fn web_fetch(a: &Value) -> Result<String, String> {
    let url = greq(a, "url")?;
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("url must start with http:// or https://".into());
    }
    let max = a
        .get("max_chars")
        .and_then(Value::as_u64)
        .unwrap_or(4000)
        .clamp(200, 20000) as usize;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().await.unwrap_or_default();
    let text = if ctype.contains("html") {
        strip_html(&body)
    } else {
        body
    };
    Ok(format!(
        "HTTP {status} ({url})\n{}",
        truncate_chars(&text, max)
    ))
}

/// Remove tags (and the text inside <script>/<style>) and collapse whitespace —
/// panic-safe, char-based, good enough to feed a page's text to the model.
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(64 * 1024));
    let mut in_tag = false;
    let mut skip_to: Option<&'static str> = None;
    let lower = s.to_ascii_lowercase();
    let mut idx = 0; // byte index tracked in parallel for the lowercase scan
    for ch in s.chars() {
        let here = &lower[idx..];
        idx += ch.len_utf8();
        if let Some(close) = skip_to {
            if here.starts_with(close) {
                skip_to = None;
                in_tag = true; // we're at the '<' of the closing tag
            }
            continue;
        }
        if ch == '<' {
            if here.starts_with("<script") {
                skip_to = Some("</script");
                continue;
            }
            if here.starts_with("<style") {
                skip_to = Some("</style");
                continue;
            }
            in_tag = true;
            continue;
        }
        if ch == '>' {
            in_tag = false;
            continue;
        }
        if !in_tag {
            out.push(ch);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let t: String = s.chars().take(max).collect();
    format!("{t}\n…[troncato]")
}

struct CmdOut {
    stdout: String,
    stderr: String,
    code: Option<i32>,
    timed_out: bool,
    not_found: bool,
}

/// Run a subprocess with an optional environment and a hard timeout. Used for
/// SSH so the password can be passed via the environment instead of argv.
async fn run_cmd(
    bin: &str,
    args: &[String],
    env: &[(String, String)],
    timeout_secs: u64,
) -> CmdOut {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CmdOut {
                stdout: String::new(),
                stderr: format!("spawn `{bin}`: {e}"),
                code: None,
                timed_out: false,
                not_found: e.kind() == std::io::ErrorKind::NotFound,
            }
        }
    };
    match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
        Ok(Ok(o)) => CmdOut {
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            code: o.status.code(),
            timed_out: false,
            not_found: false,
        },
        Ok(Err(e)) => CmdOut {
            stdout: String::new(),
            stderr: format!("io `{bin}`: {e}"),
            code: None,
            timed_out: false,
            not_found: false,
        },
        Err(_) => CmdOut {
            stdout: String::new(),
            stderr: format!("`{bin}` timeout dopo {timeout_secs}s"),
            code: None,
            timed_out: true,
            not_found: false,
        },
    }
}

async fn ssh_exec(a: &Value) -> Result<String, String> {
    let host = greq(a, "host")?;
    let user = greq(a, "username")?;
    let command = greq(a, "command")?;
    let port = a
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| *p > 0 && *p <= 65535)
        .unwrap_or(22);
    let timeout = a
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(30);
    let target = format!("{user}@{host}");
    let common = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-p".to_string(),
        port.to_string(),
    ];

    let (bin, mut args, env): (&str, Vec<String>, Vec<(String, String)>) =
        if let Some(key) = gs(a, "key_path") {
            let mut v = vec![
                "-i".to_string(),
                key,
                "-o".to_string(),
                "BatchMode=yes".to_string(),
            ];
            v.extend(common);
            ("ssh", v, vec![])
        } else if let Some(pw) = gs(a, "password") {
            // sshpass -e reads the password from $SSHPASS, keeping it off argv.
            let mut v = vec!["-e".to_string(), "ssh".to_string()];
            v.extend(common);
            ("sshpass", v, vec![("SSHPASS".to_string(), pw)])
        } else {
            let mut v = vec!["-o".to_string(), "BatchMode=yes".to_string()];
            v.extend(common);
            ("ssh", v, vec![])
        };
    args.push(target.clone());
    args.push(command);

    let o = run_cmd(bin, &args, &env, timeout).await;
    if o.not_found {
        return Err(if bin == "sshpass" {
            "`sshpass` non installato (serve per l'autenticazione con password). Installalo oppure usa key_path.".into()
        } else {
            "`ssh` non trovato sull'host.".into()
        });
    }
    let mut body = format!("$ ssh {target} (porta {port})\n");
    if !o.stdout.is_empty() {
        body.push_str(&o.stdout);
    }
    if !o.stderr.is_empty() {
        body.push_str("\n--- stderr ---\n");
        body.push_str(&o.stderr);
    }
    body.push_str(&if o.timed_out {
        "\n[connessione/comando: timeout]".to_string()
    } else {
        format!(
            "\n[exit code: {}]",
            o.code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
        )
    });
    if body.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body.push_str("\n…[output troncato]");
    }
    Ok(body)
}

async fn nd_scan(store: &Store, a: &Value) -> Result<String, String> {
    let asset_id = guuid(a, "asset_id")?;
    let kind = ScanKind::from_db(&greq(a, "kind")?)
        .ok_or("kind must be external_surface|sql_injection|vuln|availability|web_hygiene")?;
    let outcome = crate::scan::run_scan(store, asset_id, kind, false)
        .await
        .map_err(|e| e.to_string())?;
    as_json(&outcome)
}

// ---- result helpers ----

fn tool_error(msg: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": msg }], "isError": true })
}

fn format_kali(bin: &str, args: &[String], o: &kali_mcp::runner::Output) -> Value {
    let mut body = format!("$ {} {}\n", bin, args.join(" "));
    if o.not_found {
        body.push_str(&format!(
            "\n`{bin}` is not installed or not on PATH.\n{}",
            o.stderr
        ));
        return json!({ "content": [{ "type": "text", "text": body }], "isError": true });
    }
    if !o.stdout.is_empty() {
        body.push_str("\n--- stdout ---\n");
        body.push_str(&o.stdout);
    }
    if !o.stderr.is_empty() {
        body.push_str("\n--- stderr ---\n");
        body.push_str(&o.stderr);
    }
    body.push_str(&if o.timed_out {
        "\n[process killed: timeout]".to_string()
    } else {
        format!(
            "\n[exit code: {}]",
            o.code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into())
        )
    });
    if body.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body.push_str("\n…[output truncated]");
    }
    let is_err = o.timed_out || o.code.map(|c| c != 0).unwrap_or(true);
    json!({ "content": [{ "type": "text", "text": body }], "isError": is_err })
}

async fn respond(out: &SharedOut, id: Option<Value>, result: Value) {
    let Some(id) = id else { return };
    write_msg(
        out,
        &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
    .await;
}
fn error_msg(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
async fn write_msg(out: &SharedOut, msg: &Value) {
    let mut line = msg.to_string();
    line.push('\n');
    let mut guard = out.lock().await;
    let _ = guard.write_all(line.as_bytes()).await;
    let _ = guard.flush().await;
}
