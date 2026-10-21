//! kali-mcp as a library: the Kali tool registry, the subprocess runner, and
//! the MCP stdio protocol. The `kali-mcp` binary serves the Kali tools on their
//! own; `netdefense` reuses `tools` + `runner` to expose the same tools from its
//! own unified MCP server.
//!
//! Authorised use only — testing and defending systems you own or are permitted
//! to assess.

pub mod protocol;
pub mod runner;
pub mod tools;
