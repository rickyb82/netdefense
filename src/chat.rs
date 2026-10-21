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
use tokio::sync::mpsc::Sender;

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
                .unwrap_or_else(default_base_url),
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

/// Default OpenAI-compatible base URL, by provider. LM Studio serves on :1234,
/// Ollama on :11434 — both speak the same `/v1` API (incl. tools).
fn default_base_url() -> String {
    match std::env::var("NETDEFENSE_LLM_PROVIDER")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "ollama" => "http://localhost:11434/v1".to_string(),
        _ => "http://localhost:1234/v1".to_string(),
    }
}

#[derive(Deserialize)]
pub struct ChatRequest {
    /// The visible conversation so far ({role:"user"|"assistant", content}).
    pub messages: Vec<Value>,
    /// Optional model id override (otherwise the configured / first loaded one).
    pub model: Option<String>,
    /// Optional OpenAI-compatible base URL override — lets the UI point at an
    /// external LM Studio or Ollama server instead of the configured default.
    pub base_url: Option<String>,
    /// Optional sampling temperature (clamped to [0, 2]); defaults to 0.2.
    pub temperature: Option<f64>,
}

fn pick_temp(t: Option<f64>) -> f64 {
    t.unwrap_or(0.2).clamp(0.0, 2.0)
}

/// Effective base URL: the request override (if non-empty) else the config.
fn pick_base(cfg: &ChatConfig, over: Option<&str>) -> String {
    over.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| cfg.base_url.clone())
}

fn client() -> Result<reqwest::Client> {
    // Talk to the LLM server directly — never via an outbound proxy, so a
    // localhost endpoint is reached straight.
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(180))
        .build()?)
}

fn system_prompt() -> Value {
    json!({
        "role": "system",
        "content": "Sei l'assistente operativo di NetDefense, una piattaforma di monitoraggio della sicurezza. \
    Hai accesso all'INTERO catalogo di tool MCP e DEVI usarli invece di rispondere a memoria: le operazioni \
    della piattaforma (nd_add_client, nd_add_device, nd_authorize, nd_scan, nd_list_assets, nd_findings, \
    nd_alerts, nd_overview), la gestione CVE (nd_cve_import per importare da NVD, nd_cve_correlate, \
    nd_cve_list, nd_set_facts per registrare vendor/prodotto/versione di un device), la navigazione internet \
    (web_fetch per leggere advisory, dettagli CVE o pagine vendor), l'accesso SSH ai dispositivi \
    (ssh_exec per entrare con le credenziali fornite ed eseguire comandi/patch, es. aggiornare RouterOS) \
    e TUTTI i tool Kali (nmap_scan, \
    masscan_scan, sqlmap, nuclei, nikto, whatweb, dnsrecon, testssl, hydra, snmpwalk, …). Quando servono \
    dati chiamali con i tool e concatena più tool se serve (es. nd_cve_import poi nd_cve_correlate poi \
    nd_alerts). Regole: ogni scansione passa dal gate di autorizzazione (un asset va prima reso 'active' con \
    un riferimento RoE firmato); opera solo su asset che l'utente amministra o ha autorizzato; non inventare \
    risultati. Rispondi in italiano, conciso e operativo."
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
    let base = pick_base(cfg, req.base_url.as_deref());
    let temp = pick_temp(req.temperature);
    let model = match req
        .model
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.model.clone())
    {
        Some(m) => m,
        None => resolve_model(&client, &base)
            .await
            .unwrap_or_else(|| "local-model".to_string()),
    };
    let tools = openai_tools();
    let url = format!("{}/chat/completions", base.trim_end_matches('/'));

    let mut messages = vec![system_prompt()];
    messages.extend(req.messages);
    let mut tool_log = Vec::new();

    for _ in 0..cfg.max_rounds {
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": temp,
            "stream": false
        });
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("server LLM non raggiungibile su {url}: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow!("il server LLM ha risposto con errore: {e}"))?;
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

#[derive(Default)]
struct ToolAcc {
    id: String,
    name: String,
    args: String,
}

/// Streaming variant of [`run`]: emits JSON events over `tx` — `status`,
/// `token`, `reset`, `tool`, `tool_result`, `done`, `error` — so the UI shows
/// the answer as it is generated while still running the agentic tool loop.
pub async fn run_stream(store: &Store, cfg: &ChatConfig, req: ChatRequest, tx: Sender<Value>) {
    use tokio_stream::StreamExt;
    let client = match client() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx
                .send(json!({"type":"error","message":e.to_string()}))
                .await;
            return;
        }
    };
    let base = pick_base(cfg, req.base_url.as_deref());
    let temp = pick_temp(req.temperature);
    let model = match req
        .model
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.model.clone())
    {
        Some(m) => m,
        None => resolve_model(&client, &base)
            .await
            .unwrap_or_else(|| "local-model".to_string()),
    };
    let _ = tx
        .send(json!({"type":"status","model":model,"base":base}))
        .await;
    let tools = openai_tools();
    let url = format!("{}/chat/completions", base.trim_end_matches('/'));

    let mut messages = vec![system_prompt()];
    messages.extend(req.messages);
    let mut used_tools = false;
    let mut final_reply = String::new();

    for _ in 0..cfg.max_rounds {
        let body = json!({
            "model": model, "messages": messages, "tools": tools,
            "tool_choice": "auto", "temperature": temp, "stream": true
        });
        let resp = match client.post(&url).json(&body).send().await {
            Ok(r) => match r.error_for_status() {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx
                        .send(json!({"type":"error","message":format!("server LLM errore: {e}")}))
                        .await;
                    return;
                }
            },
            Err(e) => {
                let _ = tx
                    .send(json!({"type":"error","message":format!("server LLM non raggiungibile su {url}: {e}")}))
                    .await;
                return;
            }
        };

        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        let mut content = String::new();
        let mut calls: Vec<ToolAcc> = Vec::new();
        'read: while let Some(chunk) = stream.next().await {
            let Ok(bytes) = chunk else { break };
            buf.push_str(&String::from_utf8_lossy(bytes.as_ref()));
            while let Some(nl) = buf.find('\n') {
                let line: String = buf.drain(..=nl).collect();
                let line = line.trim();
                let Some(data) = line.strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data == "[DONE]" {
                    break 'read;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                let delta = &v["choices"][0]["delta"];
                if let Some(c) = delta.get("content").and_then(Value::as_str) {
                    if !c.is_empty() {
                        content.push_str(c);
                        let _ = tx.send(json!({"type":"token","text":c})).await;
                    }
                }
                if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                    for tc in tcs {
                        let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                        while calls.len() <= idx {
                            calls.push(ToolAcc::default());
                        }
                        let slot = &mut calls[idx];
                        if let Some(id) = tc.get("id").and_then(Value::as_str) {
                            if !id.is_empty() {
                                slot.id = id.to_string();
                            }
                        }
                        if let Some(f) = tc.get("function") {
                            if let Some(n) = f.get("name").and_then(Value::as_str) {
                                if !n.is_empty() {
                                    slot.name = n.to_string();
                                }
                            }
                            if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                                slot.args.push_str(a);
                            }
                        }
                    }
                }
            }
        }

        if calls.is_empty() {
            final_reply = content;
            break;
        }

        // This round routed to tools: tell the UI to drop any partial tokens.
        used_tools = true;
        let _ = tx.send(json!({"type":"reset"})).await;
        let assistant_calls: Vec<Value> = calls
            .iter()
            .map(|c| {
                json!({"id":c.id,"type":"function","function":{"name":c.name,"arguments":c.args}})
            })
            .collect();
        messages.push(json!({"role":"assistant","content":content,"tool_calls":assistant_calls}));
        for c in &calls {
            let args: Value = serde_json::from_str(&c.args).unwrap_or_else(|_| json!({}));
            let _ = tx
                .send(json!({"type":"tool","name":c.name,"args":args}))
                .await;
            let (text, is_err) = crate::mcp::exec_tool(store, &c.name, &args).await;
            let _ = tx
                .send(json!({"type":"tool_result","name":c.name,"ok":!is_err}))
                .await;
            messages.push(json!({"role":"tool","tool_call_id":c.id,"content":truncate(text)}));
        }
    }

    if final_reply.trim().is_empty() && used_tools {
        final_reply =
            "Operazioni completate con i tool. (Il modello non ha prodotto un testo finale.)"
                .to_string();
    }
    let _ = tx
        .send(json!({"type":"done","reply":final_reply,"used_tools":used_tools}))
        .await;
}

/// Connectivity/status for the UI: is the LLM server reachable, and what models
/// does it expose. `over` lets the UI probe an external/override endpoint.
pub async fn status(cfg: &ChatConfig, over: Option<&str>) -> Value {
    let base = pick_base(cfg, over).trim_end_matches('/').to_string();
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
