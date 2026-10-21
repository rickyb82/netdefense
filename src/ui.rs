//! Built-in management web UI (the "gestionale"), compiled into the binary and
//! served same-origin by netdefense itself at `GET /`. It talks to the same API
//! (clients, assets, bulk add, authorize) — no external hosting, no separate
//! origin, no CORS.

/// The single-page management console, embedded at build time.
pub const INDEX: &str = include_str!("ui/index.html");
