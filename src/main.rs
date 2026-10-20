//! netdefense: proactive managed security monitoring (EASM) platform.
//!
//! Scans are permitted only against assets that are explicitly authorised in
//! the database (status `active`, unexpired, within the allowed window, backed
//! by a signed rules-of-engagement reference). See `crate::authz`.

mod api;
mod authz;
mod domain;
mod scan;
mod store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("NETDEFENSE_DB").unwrap_or_else(|_| "netdefense.db".to_string());
    let addr = std::env::var("NETDEFENSE_ADDR").unwrap_or_else(|_| "127.0.0.1:8088".to_string());

    let store = store::Store::open(&db_path)?;
    store.migrate()?;

    let app = api::router(store);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("netdefense listening on http://{addr}  (db: {db_path})");
    axum::serve(listener, app).await?;
    Ok(())
}
