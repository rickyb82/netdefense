//! Minimal MCP server over stdio: newline-delimited JSON-RPC 2.0.
//! Implements `initialize`, `tools/list`, `tools/call`, `ping`; ignores
//! notifications. Each request is handled in its own task so a long-running
//! scan never blocks other calls; stdout writes are serialised by a mutex.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::runner;
use crate::tools::{self, ToolDef};

const SERVER_NAME: &str = "kali-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PROTOCOL: &str = "2025-06-18";
const DEFAULT_TIMEOUT: u64 = 300;
const MAX_OUTPUT: usize = 200_000;

type SharedOut = Arc<Mutex<tokio::io::Stdout>>;

pub async fn serve() {
    let registry = Arc::new(tools::registry());
    let stdout: SharedOut = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                let reg = registry.clone();
                let out = stdout.clone();
                tasks.spawn(async move {
                    handle_line(&line, reg, out).await;
                });
                // Reap finished handlers so the set does not grow unbounded.
                while tasks.try_join_next().is_some() {}
            }
            Ok(None) => break, // EOF: client closed the pipe
            Err(e) => {
                eprintln!("kali-mcp: stdin read error: {e}");
                break;
            }
        }
    }

    // Let in-flight requests finish writing their responses before exiting.
    while tasks.join_next().await.is_some() {}
}

async fn handle_line(line: &str, reg: Arc<Vec<ToolDef>>, out: SharedOut) {
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
        "tools/list" => {
            let list: Vec<Value> = reg
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.schema,
                    })
                })
                .collect();
            respond(&out, id, json!({ "tools": list })).await;
        }
        "tools/call" => {
            let result = call_tool(&reg, &params).await;
            respond(&out, id, result).await;
        }
        _ => {
            // Unknown method: reply with an error only if it was a request
            // (notifications have no id and must not be answered).
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

async fn call_tool(reg: &[ToolDef], params: &Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return tool_error("missing `name` in tools/call params");
    };
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let Some(def) = reg.iter().find(|t| t.name == name) else {
        return tool_error(&format!("unknown tool `{name}`"));
    };

    let cli_args = match (def.build)(&args) {
        Ok(a) => a,
        Err(e) => return tool_error(&format!("invalid arguments for `{name}`: {e}")),
    };

    let timeout_secs = args
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_TIMEOUT);

    let o = runner::run(def.bin, &cli_args, timeout_secs).await;
    format_result(def, &cli_args, &o)
}

fn format_result(def: &ToolDef, args: &[String], o: &runner::Output) -> Value {
    let mut body = format!("$ {} {}\n", def.bin, args.join(" "));

    if o.not_found {
        body.push_str(&format!(
            "\n`{}` is not installed or not on PATH. On Kali: `sudo apt install {}`.\n{}",
            def.bin, def.bin, o.stderr
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

    truncate_chars(&mut body, MAX_OUTPUT);

    let is_err = o.timed_out || o.code.map(|c| c != 0).unwrap_or(true);
    json!({ "content": [{ "type": "text", "text": body }], "isError": is_err })
}

/// A tool-execution failure: reported as a successful JSON-RPC result with
/// `isError: true`, per the MCP convention (protocol errors are reserved for
/// malformed requests).
fn tool_error(msg: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": msg }], "isError": true })
}

fn truncate_chars(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push_str("\n…[output truncated]");
}

async fn respond(out: &SharedOut, id: Option<Value>, result: Value) {
    // No id means this was a notification; notifications get no response.
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
