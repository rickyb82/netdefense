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

use std::sync::Arc;

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
fn tool_list() -> Vec<Value> {
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

    if let Some(res) = call_native(store, name, &args).await {
        return match res {
            Ok(text) => ok_text(text),
            Err(e) => tool_error(&e),
        };
    }

    // Not a native tool → delegate to the connected kali-mcp catalogue.
    let reg = kali_mcp::tools::registry();
    let Some(def) = reg.iter().find(|t| t.name == name) else {
        return tool_error(&format!("unknown tool `{name}`"));
    };
    let cli = match (def.build)(&args) {
        Ok(a) => a,
        Err(e) => return tool_error(&format!("invalid arguments for `{name}`: {e}")),
    };
    let timeout = args
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_TIMEOUT);
    let o = kali_mcp::runner::run(def.bin, &cli, timeout).await;
    format_kali(def.bin, &cli, &o)
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

fn ok_text(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}
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
