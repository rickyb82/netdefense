//! netdefense: proactive managed security monitoring (EASM) platform.
//!
//! Scans are permitted only against assets that are explicitly authorised in
//! the database (status `active`, unexpired, within the allowed window, backed
//! by a signed rules-of-engagement reference). See `crate::authz`.

mod alert;
mod api;
mod authz;
mod cve;
mod disclosure;
mod domain;
mod fleet;
mod nms;
mod notify;
mod nvd;
mod prtg;
mod scan;
mod scheduler;
mod snmp;
mod store;
mod voip;

use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("NETDEFENSE_DB").unwrap_or_else(|_| "netdefense.db".to_string());
    let addr = std::env::var("NETDEFENSE_ADDR").unwrap_or_else(|_| "127.0.0.1:8088".to_string());
    let tick_secs: u64 = std::env::var("NETDEFENSE_TICK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);

    let store = store::Store::open(&db_path)?;
    store.migrate()?;

    scheduler::spawn(store.clone(), Duration::from_secs(tick_secs));
    notify::spawn(store.clone(), notify::NotifyConfig::from_env());

    let nvd_cfg = nvd::NvdConfig::from_env();
    if nvd_cfg.enabled {
        eprintln!(
            "netdefense nvd: poller enabled (every {}s)",
            nvd_cfg.poll_secs
        );
        nvd::spawn(store.clone(), nvd_cfg);
    }

    let app = api::router(store);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!(
        "netdefense listening on http://{addr}  (db: {db_path}, scheduler tick: {tick_secs}s)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
