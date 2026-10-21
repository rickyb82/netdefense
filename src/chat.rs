//! In-app chat assistant backed by a local LLM through LM Studio's
//! OpenAI-compatible API. The assistant can call netdefense's MCP tools
//! (`nd_*` operations and the kali catalogue) via function calling, so the
//! whole MCP surface can be exercised locally from the web console — no
//! external service, no cloud model.
//!
//! Defaults to `http://localhost:1234/v1` (LM Studio's default). In Docker set
//! `NETDEFENSE_LLM_URL=http://host.docker.internal:1234/v1` to reach the host.
//! The tool execution goes through `crate::mcp::exec_tool`, so a scan the model
//! asks for still passes the authorisation gate.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::store::Store;

/// Cap the tool output fed back to the model so one noisy scan can't blow the
/// context window.
const MAX_TOOL_CHARS: usize = 6000;

pub struct ChatConfig {
    pub base_url: String,
    pub model: Option<String>,
    pub max_rounds: usize,
}

impl ChatConfig {
    pub fn from_env() -> Self {
        ChatConfig {
            base_url: std::env::var("NETDEFENSE_LLM_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "http://localhost:1234/v1".to_string()),
            model: std::env::var("NETDEFENSE_LLM_MODEL")
                .ok()
                .filter(|s| !s.is_empty()),
            max_rounds: std::env::var("NETDEFENSE_LLM_MAX_ROUNDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(6),
        }
    }
}

#[derive(Deserialize)]
pub struct ChatRequest {
    /// The visible conversation so far ({role:"user"|"assistant", content}).
    pub messages: Vec<Value>,
    /// Optional model id override (otherwise the configured / first loaded one).
    pub model: Option<String>,
}

fn client() -> Result<reqwest::Client> {
    // Talk to LM Studio directly on localhost — never via an outbound proxy.
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(180))
        .build()?)
}

fn system_prompt() -> Value {
    json!({
        "role": "system",
        "content": "Sei l'assistente di NetDefense, una piattaforma di monitoraggio della sicurezza. \
    Hai a disposizione dei tool (operazioni nd_* della piattaforma e tool Kali) che puoi chiamare per \
    gestire clienti/device, autorizzare asset, lanciare scansioni e leggere findings/alert. \
    Regole: ogni scansione passa dal gate di autorizzazione (un asset va prima reso 'active' con un \
    riferimento RoE firmato); non inventare dati, usa i tool per ottenerli; opera solo su asset che \
    l'utente amministra o ha autorizzato. Rispondi in italiano, conciso e operativo."
    })
}

/// OpenAI-style function tools derived from the MCP tool catalogue.
fn openai_tools() -> Vec<Value> {
    crate::mcp::tool_list()
        .into_iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            let description = t
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let parameters = t
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            Some(json!({
                "type": "function",
                "function": { "name": name, "description": description, "parameters": parameters }
            }))
        })
        .collect()
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_TOOL_CHARS {
        let mut end = MAX_TOOL_CHARS;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("\n…[output troncato]");
    }
    s
}

/// Ask LM Studio for the first loaded model id, when none is configured.
async fn resolve_model(client: &reqwest::Client, base_url: &str) -> Option<String> {
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    let v: Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    v.get("data")?
        .as_array()?
        .first()?
        .get("id")?
        .as_str()
        .map(str::to_string)
}

#[derive(serde::Serialize)]
pub struct ChatReply {
    pub reply: String,
    pub tool_log: Vec<Value>,
    pub model: String,
}

/// Run one assistant turn: an agentic loop that calls the local model, executes
/// any tool calls through the MCP layer, and returns the final text.
pub async fn run(store: &Store, cfg: &ChatConfig, req: ChatRequest) -> Result<ChatReply> {
    let client = client()?;
    let model = match req.model.or_else(|| cfg.model.clone()) {
        Some(m) => m,
        None => resolve_model(&client, &cfg.base_url)
            .await
            .unwrap_or_else(|| "local-model".to_string()),
    };
    let tools = openai_tools();
    let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));

    let mut messages = vec![system_prompt()];
    messages.extend(req.messages);
    let mut tool_log = Vec::new();

    for _ in 0..cfg.max_rounds {
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.2,
            "stream": false
        });
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("LM Studio non raggiungibile su {url}: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow!("LM Studio ha risposto con errore: {e}"))?;
        let v: Value = resp.json().await?;
        let msg = v
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .cloned()
            .ok_or_else(|| anyhow!("risposta LLM senza message"))?;

        let tool_calls = msg
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        if tool_calls.is_empty() {
            let reply = msg
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Ok(ChatReply {
                reply,
                tool_log,
                model,
            });
        }

        // Record the assistant's tool-call message, then run each tool.
        messages.push(msg.clone());
        for tc in &tool_calls {
            let id = tc
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args: Value = tc
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| json!({}));

            let (text, is_err) = crate::mcp::exec_tool(store, &name, &args).await;
            tool_log.push(json!({ "tool": name, "args": args, "ok": !is_err }));
            messages.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": truncate(text)
            }));
        }
    }

    Ok(ChatReply {
        reply: "Ho raggiunto il limite di passaggi tool senza una risposta finale. Riprova o riformula.".to_string(),
        tool_log,
        model,
    })
}

/// Connectivity/status for the UI: is LM Studio reachable, and what models does
/// it expose.
pub async fn status(cfg: &ChatConfig) -> Value {
    let base = cfg.base_url.trim_end_matches('/').to_string();
    let client = match client() {
        Ok(c) => c,
        Err(e) => return json!({ "url": base, "ok": false, "error": e.to_string() }),
    };
    let url = format!("{base}/models");
    match client.get(&url).send().await {
        Ok(r) => match r.error_for_status() {
            Ok(r) => {
                let v: Value = r.json().await.unwrap_or_else(|_| json!({}));
                let models: Vec<String> = v
                    .get("data")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                json!({ "url": base, "ok": true, "models": models, "model": cfg.model })
            }
            Err(e) => json!({ "url": base, "ok": false, "error": e.to_string() }),
        },
        Err(e) => json!({ "url": base, "ok": false, "error": e.to_string() }),
    }
}
