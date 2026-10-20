//! Alert delivery. Alerts are created synchronously (scan diffs, CVE
//! correlation) and marked undelivered; this module delivers the pending ones
//! to a notification channel out of band, so creation never blocks on the
//! network. The default channel is a webhook — in this deployment, an Emily
//! backend endpoint that calls Emily's own `events.notify` for the admins.
//!
//! Delivery is decoupled from creation via the `alerts.delivered` flag: a
//! failed POST leaves the alert pending for the next cycle (at-least-once).

use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};

use crate::domain::Alert;
use crate::store::Store;

pub struct NotifyConfig {
    pub webhook_url: Option<String>,
    /// Header name/value sent with the webhook (e.g. Authorization / Bearer …).
    pub header_name: String,
    pub header_value: Option<String>,
    pub poll_secs: u64,
}

impl NotifyConfig {
    pub fn from_env() -> Self {
        NotifyConfig {
            webhook_url: std::env::var("NETDEFENSE_NOTIFY_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            header_name: std::env::var("NETDEFENSE_NOTIFY_HEADER")
                .unwrap_or_else(|_| "Authorization".to_string()),
            header_value: std::env::var("NETDEFENSE_NOTIFY_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            poll_secs: std::env::var("NETDEFENSE_NOTIFY_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(20),
        }
    }
}

/// The JSON an alert is delivered as. Pure and unit-tested.
pub fn build_payload(a: &Alert) -> Value {
    json!({
        "source": "netdefense",
        "severity": a.severity.as_str(),
        "title": a.summary,
        "detail": a.detail,
        "asset_id": a.asset_id.to_string(),
        "scan_id": a.scan_id.map(|s| s.to_string()),
        "created_at": a.created_at.to_rfc3339(),
    })
}

/// Deliver every undelivered alert once. Returns how many were delivered. A POST
/// failure leaves that alert pending (logged, retried next cycle). With no
/// webhook configured, alerts are logged and marked delivered so they do not
/// pile up.
pub async fn deliver_pending(store: &Store, cfg: &NotifyConfig) -> Result<usize> {
    let pending = store.list_undelivered_alerts()?;
    if pending.is_empty() {
        return Ok(0);
    }

    let client = match &cfg.webhook_url {
        Some(_) => Some(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
        ),
        None => None,
    };

    let mut delivered = 0usize;
    for a in pending {
        match (&client, &cfg.webhook_url) {
            (Some(client), Some(url)) => {
                if let Err(e) = post(client, url, cfg, &build_payload(&a)).await {
                    eprintln!("netdefense notify: delivery failed for alert {}: {e}", a.id);
                    continue; // stays pending for the next cycle
                }
            }
            _ => crate::alert::log(&a), // no channel configured: log sink
        }
        store.mark_alert_delivered(a.id)?;
        delivered += 1;
    }
    Ok(delivered)
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    cfg: &NotifyConfig,
    payload: &Value,
) -> Result<()> {
    let mut req = client.post(url).json(payload);
    if let Some(v) = &cfg.header_value {
        req = req.header(cfg.header_name.as_str(), v);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

/// Background task: deliver pending alerts on a fixed interval.
pub fn spawn(store: Store, cfg: NotifyConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(cfg.poll_secs));
        loop {
            ticker.tick().await;
            if let Err(e) = deliver_pending(&store, &cfg).await {
                eprintln!("netdefense notify: cycle error: {e}");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn payload_has_expected_shape() {
        let a = Alert {
            id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            scan_id: None,
            severity: Severity::High,
            summary: "CVE-2023-41570 · routeros (6.49.7)".into(),
            detail: "RouterOS Winbox issue".into(),
            created_at: Utc::now(),
        };
        let p = build_payload(&a);
        assert_eq!(p["source"], "netdefense");
        assert_eq!(p["severity"], "high");
        assert_eq!(p["title"], a.summary);
        assert!(p["scan_id"].is_null());
        assert_eq!(p["asset_id"], a.asset_id.to_string());
    }
}
