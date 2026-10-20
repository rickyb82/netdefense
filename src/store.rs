//! SQLite persistence. A single connection behind a mutex — adequate for the
//! current load and free of an external database dependency. Rows are read as
//! primitive tuples and then *hydrated* into domain types, so all fallible
//! parsing (UUIDs, timestamps, enums) happens outside rusqlite's row closure.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveTime, Utc};
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::domain::*;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

// ---- small parse helpers ----------------------------------------------------

fn pid(s: &str) -> Result<Id> {
    Uuid::parse_str(s).with_context(|| format!("invalid uuid: {s}"))
}
fn pts(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("invalid timestamp: {s}"))?
        .with_timezone(&Utc))
}
fn pts_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|v| pts(&v)).transpose()
}
fn ptime_opt(s: Option<String>) -> Result<Option<NaiveTime>> {
    match s {
        Some(v) => Ok(Some(
            NaiveTime::parse_from_str(&v, "%H:%M:%S")
                .with_context(|| format!("invalid time: {v}"))?,
        )),
        None => Ok(None),
    }
}
fn ts(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}
fn time_str(t: &NaiveTime) -> String {
    t.format("%H:%M:%S").to_string()
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening db {path}"))?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| anyhow!("db mutex poisoned"))
    }

    pub fn migrate(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS clients (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets (
                id               TEXT PRIMARY KEY,
                client_id        TEXT NOT NULL REFERENCES clients(id),
                kind             TEXT NOT NULL,
                value            TEXT NOT NULL,
                auth_status      TEXT NOT NULL,
                authorized_until TEXT,
                window_start     TEXT,
                window_end       TEXT,
                roe_reference    TEXT,
                created_at       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                asset_id    TEXT NOT NULL REFERENCES assets(id),
                kind        TEXT NOT NULL,
                status      TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                note        TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL REFERENCES scans(id),
                asset_id    TEXT NOT NULL REFERENCES assets(id),
                kind        TEXT NOT NULL,
                key         TEXT NOT NULL,
                title       TEXT NOT NULL,
                detail      TEXT NOT NULL,
                severity    TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assets_client ON assets(client_id);
            CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            "#,
        )?;
        Ok(())
    }

    // ---- clients ----

    pub fn insert_client(&self, c: &Client) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO clients (id, name, contact_email, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![c.id.to_string(), c.name, c.contact_email, ts(&c.created_at)],
        )?;
        Ok(())
    }

    pub fn list_clients(&self) -> Result<Vec<Client>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, contact_email, created_at FROM clients ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, name, contact_email, created_at)| {
                Ok(Client {
                    id: pid(&id)?,
                    name,
                    contact_email,
                    created_at: pts(&created_at)?,
                })
            })
            .collect()
    }

    pub fn get_client(&self, id: Id) -> Result<Option<Client>> {
        Ok(self.list_clients()?.into_iter().find(|c| c.id == id))
    }

    // ---- assets ----

    pub fn insert_asset(&self, a: &Asset) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO assets
             (id, client_id, kind, value, auth_status, authorized_until, window_start, window_end, roe_reference, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                a.id.to_string(),
                a.client_id.to_string(),
                a.kind.as_str(),
                a.value,
                a.auth_status.as_str(),
                a.authorized_until.map(|t| ts(&t)),
                a.window_start.as_ref().map(time_str),
                a.window_end.as_ref().map(time_str),
                a.roe_reference,
                ts(&a.created_at),
            ],
        )?;
        Ok(())
    }

    fn hydrate_asset(raw: AssetRow) -> Result<Asset> {
        Ok(Asset {
            id: pid(&raw.id)?,
            client_id: pid(&raw.client_id)?,
            kind: AssetKind::from_db(&raw.kind)
                .ok_or_else(|| anyhow!("bad asset kind {}", raw.kind))?,
            value: raw.value,
            auth_status: AuthStatus::from_db(&raw.auth_status)
                .ok_or_else(|| anyhow!("bad auth status {}", raw.auth_status))?,
            authorized_until: pts_opt(raw.authorized_until)?,
            window_start: ptime_opt(raw.window_start)?,
            window_end: ptime_opt(raw.window_end)?,
            roe_reference: raw.roe_reference,
            created_at: pts(&raw.created_at)?,
        })
    }

    fn query_assets(&self, where_clause: &str, arg: &str) -> Result<Vec<Asset>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, client_id, kind, value, auth_status, authorized_until, window_start, window_end, roe_reference, created_at
             FROM assets {where_clause} ORDER BY created_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mapper = |r: &rusqlite::Row<'_>| {
            Ok(AssetRow {
                id: r.get(0)?,
                client_id: r.get(1)?,
                kind: r.get(2)?,
                value: r.get(3)?,
                auth_status: r.get(4)?,
                authorized_until: r.get(5)?,
                window_start: r.get(6)?,
                window_end: r.get(7)?,
                roe_reference: r.get(8)?,
                created_at: r.get(9)?,
            })
        };
        let raws = if arg.is_empty() {
            stmt.query_map([], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map([arg], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        raws.into_iter().map(Self::hydrate_asset).collect()
    }

    pub fn list_assets(&self, client_id: Id) -> Result<Vec<Asset>> {
        self.query_assets("WHERE client_id = ?1", &client_id.to_string())
    }

    pub fn get_asset(&self, id: Id) -> Result<Option<Asset>> {
        Ok(self
            .query_assets("WHERE id = ?1", &id.to_string())?
            .into_iter()
            .next())
    }

    pub fn update_asset_authorization(
        &self,
        id: Id,
        status: AuthStatus,
        authorized_until: Option<DateTime<Utc>>,
        window_start: Option<NaiveTime>,
        window_end: Option<NaiveTime>,
        roe_reference: Option<String>,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE assets SET auth_status=?2, authorized_until=?3, window_start=?4, window_end=?5, roe_reference=?6 WHERE id=?1",
            params![
                id.to_string(),
                status.as_str(),
                authorized_until.map(|t| ts(&t)),
                window_start.as_ref().map(time_str),
                window_end.as_ref().map(time_str),
                roe_reference,
            ],
        )?;
        Ok(())
    }

    // ---- scans ----

    pub fn insert_scan(&self, s: &Scan) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO scans (id, asset_id, kind, status, started_at, finished_at, note)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                s.id.to_string(),
                s.asset_id.to_string(),
                s.kind.as_str(),
                s.status.as_str(),
                ts(&s.started_at),
                s.finished_at.map(|t| ts(&t)),
                s.note,
            ],
        )?;
        Ok(())
    }

    pub fn finish_scan(&self, id: Id, status: ScanStatus, note: Option<&str>) -> Result<()> {
        self.lock()?.execute(
            "UPDATE scans SET status=?2, finished_at=?3, note=?4 WHERE id=?1",
            params![id.to_string(), status.as_str(), ts(&Utc::now()), note],
        )?;
        Ok(())
    }

    pub fn get_scan(&self, id: Id) -> Result<Option<Scan>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, asset_id, kind, status, started_at, finished_at, note FROM scans WHERE id=?1",
        )?;
        let raws = stmt
            .query_map([id.to_string()], scan_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(hydrate_scan).next().transpose()
    }

    /// Keys of findings from the most recent *completed* scan of this kind on
    /// this asset, excluding `exclude` (the scan in progress). Used as the
    /// diff baseline.
    pub fn baseline_keys(&self, asset_id: Id, kind: ScanKind, exclude: Id) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let prev: Option<String> = conn
            .query_row(
                "SELECT id FROM scans WHERE asset_id=?1 AND kind=?2 AND status='completed' AND id<>?3
                 ORDER BY started_at DESC LIMIT 1",
                params![asset_id.to_string(), kind.as_str(), exclude.to_string()],
                |r| r.get(0),
            )
            .ok();
        let Some(prev_scan) = prev else {
            return Ok(vec![]);
        };
        let mut stmt = conn.prepare("SELECT key FROM findings WHERE scan_id=?1")?;
        let keys = stmt
            .query_map([prev_scan], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(keys)
    }

    // ---- findings ----

    pub fn insert_finding(&self, f: &Finding) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO findings (id, scan_id, asset_id, kind, key, title, detail, severity, observed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                f.id.to_string(),
                f.scan_id.to_string(),
                f.asset_id.to_string(),
                f.kind,
                f.key,
                f.title,
                f.detail,
                f.severity.as_str(),
                ts(&f.observed_at),
            ],
        )?;
        Ok(())
    }

    pub fn list_findings_for_scan(&self, scan_id: Id) -> Result<Vec<Finding>> {
        self.query_findings("WHERE scan_id = ?1", &scan_id.to_string())
    }

    pub fn list_findings_for_asset(&self, asset_id: Id) -> Result<Vec<Finding>> {
        self.query_findings("WHERE asset_id = ?1", &asset_id.to_string())
    }

    fn query_findings(&self, where_clause: &str, arg: &str) -> Result<Vec<Finding>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, scan_id, asset_id, kind, key, title, detail, severity, observed_at
             FROM findings {where_clause} ORDER BY observed_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let raws = stmt
            .query_map([arg], |r| {
                Ok(FindingRow {
                    id: r.get(0)?,
                    scan_id: r.get(1)?,
                    asset_id: r.get(2)?,
                    kind: r.get(3)?,
                    key: r.get(4)?,
                    title: r.get(5)?,
                    detail: r.get(6)?,
                    severity: r.get(7)?,
                    observed_at: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(hydrate_finding).collect()
    }
}

// ---- raw row structs --------------------------------------------------------

struct AssetRow {
    id: String,
    client_id: String,
    kind: String,
    value: String,
    auth_status: String,
    authorized_until: Option<String>,
    window_start: Option<String>,
    window_end: Option<String>,
    roe_reference: Option<String>,
    created_at: String,
}

struct ScanRow {
    id: String,
    asset_id: String,
    kind: String,
    status: String,
    started_at: String,
    finished_at: Option<String>,
    note: Option<String>,
}

fn scan_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRow> {
    Ok(ScanRow {
        id: r.get(0)?,
        asset_id: r.get(1)?,
        kind: r.get(2)?,
        status: r.get(3)?,
        started_at: r.get(4)?,
        finished_at: r.get(5)?,
        note: r.get(6)?,
    })
}

fn hydrate_scan(raw: ScanRow) -> Result<Scan> {
    Ok(Scan {
        id: pid(&raw.id)?,
        asset_id: pid(&raw.asset_id)?,
        kind: ScanKind::from_db(&raw.kind).ok_or_else(|| anyhow!("bad scan kind {}", raw.kind))?,
        status: ScanStatus::from_db(&raw.status)
            .ok_or_else(|| anyhow!("bad scan status {}", raw.status))?,
        started_at: pts(&raw.started_at)?,
        finished_at: pts_opt(raw.finished_at)?,
        note: raw.note,
    })
}

struct FindingRow {
    id: String,
    scan_id: String,
    asset_id: String,
    kind: String,
    key: String,
    title: String,
    detail: String,
    severity: String,
    observed_at: String,
}

fn hydrate_finding(raw: FindingRow) -> Result<Finding> {
    Ok(Finding {
        id: pid(&raw.id)?,
        scan_id: pid(&raw.scan_id)?,
        asset_id: pid(&raw.asset_id)?,
        kind: raw.kind,
        key: raw.key,
        title: raw.title,
        detail: raw.detail,
        severity: Severity::from_db(&raw.severity)
            .ok_or_else(|| anyhow!("bad severity {}", raw.severity))?,
        observed_at: pts(&raw.observed_at)?,
    })
}
