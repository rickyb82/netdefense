//! kali-mcp: an MCP server that exposes common Kali Linux security tools.
//!
//! Intended for authorised use only — testing and defending networks and
//! systems you own or have explicit permission to assess.

mod protocol;
mod runner;
mod tools;

#[tokio::main]
async fn main() {
    protocol::serve().await;
}
