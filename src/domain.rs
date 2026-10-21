//! Core domain types for the monitoring platform.
//!
//! An [`Asset`] is the authorised unit of scanning: it belongs to a client,
//! carries an authorisation state, an optional expiry, an optional daily time
//! window, and a reference to the signed rules-of-engagement. The
//! authorisation gate in `crate::authz` is the single place that decides
//! whether a scan of an asset may run.

use chrono::{DateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type Id = Uuid;

/// Macro to give a simple C-like enum stable string forms for DB storage.
macro_rules! str_enum {
    ($name:ident { $($variant:ident => $lit:literal),+ $(,)? }) => {
        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self { $( $name::$variant => $lit ),+ }
            }
            pub fn from_db(s: &str) -> Option<Self> {
                match s { $( $lit => Some($name::$variant), )+ _ => None }
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: Id,
    pub name: String,
    pub contact_email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Domain,
    Url,
    CidrRange,
}
str_enum!(AssetKind { Host => "host", Domain => "domain", Url => "url", CidrRange => "cidr_range" });

/// Lifecycle of an asset's authorisation. Only `Active` permits scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    /// Registered but not yet authorised — scanning refused.
    Pending,
    /// Authorised and in effect.
    Active,
    /// Temporarily paused by the operator or the client.
    Suspended,
    /// Authorisation withdrawn — scanning refused permanently.
    Revoked,
}
str_enum!(AuthStatus { Pending => "pending", Active => "active", Suspended => "suspended", Revoked => "revoked" });

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Id,
    pub client_id: Id,
    pub kind: AssetKind,
    /// The authorised target (host, domain, URL or CIDR). This exact value is
    /// what gets scanned — nothing is inferred or expanded beyond it.
    pub value: String,
    pub auth_status: AuthStatus,
    /// Authorisation expiry; `None` means no expiry set.
    pub authorized_until: Option<DateTime<Utc>>,
    /// Allowed daily window (UTC). Both set = scans only within [start, end]
    /// (a window may cross midnight). Both `None` = any time.
    pub window_start: Option<NaiveTime>,
    pub window_end: Option<NaiveTime>,
    /// Reference to the signed rules-of-engagement / contract authorising this
    /// asset. Required before an asset can be made `Active`.
    pub roe_reference: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    ExternalSurface,
    Vuln,
    Availability,
    WebHygiene,
    SqlInjection,
}
str_enum!(ScanKind {
    ExternalSurface => "external_surface",
    Vuln => "vuln",
    Availability => "availability",
    WebHygiene => "web_hygiene",
    SqlInjection => "sql_injection",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    /// Blocked by the authorisation gate; the reason is stored on the scan.
    Refused,
}
str_enum!(ScanStatus {
    Queued => "queued",
    Running => "running",
    Completed => "completed",
    Failed => "failed",
    Refused => "refused",
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Id,
    pub asset_id: Id,
    pub kind: ScanKind,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
str_enum!(Severity {
    Info => "info",
    Low => "low",
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Id,
    pub scan_id: Id,
    pub asset_id: Id,
    /// Category, e.g. `open_port`, `tls_cert`, `http_header`.
    pub kind: String,
    /// Stable identity used for diffing against the baseline, e.g. `tcp/443`.
    pub key: String,
    pub title: String,
    pub detail: String,
    pub severity: Severity,
    pub observed_at: DateTime<Utc>,
}

/// A recurring scan of an asset. The scheduler runs due schedules (and the
/// scan still passes the authorisation gate every time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: Id,
    pub asset_id: Id,
    pub kind: ScanKind,
    pub interval_secs: i64,
    pub next_run_at: DateTime<Utc>,
    pub enabled: bool,
}

/// A noteworthy change surfaced by the baseline diff — what proactive
/// monitoring exists to deliver to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Id,
    pub asset_id: Id,
    /// The scan that raised it, or `None` for alerts from CVE correlation.
    pub scan_id: Option<Id>,
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}
