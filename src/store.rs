//! SQLite persistence. A single connection behind a mutex — adequate for the
//! current load and free of an external database dependency. Rows are read as
//! primitive tuples and then *hydrated* into domain types, so all fallible
//! parsing (UUIDs, timestamps, enums) happens outside rusqlite's row closure.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveTime, Utc};
use rusqlite::{params, Connection};
use serde::Serialize;
use uuid::Uuid;

use crate::domain::*;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

/// SQL predicate (on an aliased `findings f`) true only for findings belonging
/// to the latest *completed* scan of their (asset, kind) — i.e. the current
/// state. Rescanning a target does not accumulate in the views: older scans'
/// findings stay in the database for the baseline diff and the audit trail, but
/// the current-state queries show only the most recent scan per kind.
const CURRENT_PRED: &str = "EXISTS (SELECT 1 FROM scans s WHERE s.id = f.scan_id \
AND s.status = 'completed' AND NOT EXISTS (SELECT 1 FROM scans s2 \
WHERE s2.asset_id = s.asset_id AND s2.kind = s.kind AND s2.status = 'completed' \
AND (s2.started_at > s.started_at OR (s2.started_at = s.started_at AND s2.id > s.id))))";

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
            CREATE TABLE IF NOT EXISTS schedules (
                id            TEXT PRIMARY KEY,
                asset_id      TEXT NOT NULL REFERENCES assets(id),
                kind          TEXT NOT NULL,
                interval_secs INTEGER NOT NULL,
                next_run_at   TEXT NOT NULL,
                enabled       INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id         TEXT PRIMARY KEY,
                asset_id   TEXT NOT NULL REFERENCES assets(id),
                scan_id    TEXT REFERENCES scans(id),
                severity   TEXT NOT NULL,
                summary    TEXT NOT NULL,
                detail     TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cves (
                id                 TEXT PRIMARY KEY,
                published          TEXT NOT NULL,
                severity           TEXT NOT NULL,
                summary            TEXT NOT NULL,
                product            TEXT NOT NULL,
                version_start_incl TEXT,
                version_end_excl   TEXT
            );
            CREATE TABLE IF NOT EXISTS device_facts (
                asset_id   TEXT PRIMARY KEY REFERENCES assets(id),
                vendor     TEXT NOT NULL,
                product    TEXT NOT NULL,
                version    TEXT,
                mgmt       TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cve_matches (
                cve_id     TEXT NOT NULL,
                asset_id   TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (cve_id, asset_id)
            );
            CREATE TABLE IF NOT EXISTS cve_sync_state (
                source        TEXT NOT NULL,
                product       TEXT NOT NULL,
                last_modified TEXT,
                last_run_at   TEXT NOT NULL,
                last_status   TEXT,
                PRIMARY KEY (source, product)
            );
            CREATE TABLE IF NOT EXISTS mitigation_proposals (
                id         TEXT PRIMARY KEY,
                title      TEXT NOT NULL,
                dst_cidr   TEXT NOT NULL,
                action     TEXT NOT NULL,
                state      TEXT NOT NULL,
                approver   TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_baselines (
                asset_id         TEXT PRIMARY KEY REFERENCES assets(id),
                content_hash     TEXT NOT NULL,
                header_grade     TEXT NOT NULL,
                cert_expiry_days INTEGER,
                updated_at       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vuln_candidates (
                id         TEXT PRIMARY KEY,
                asset_id   TEXT NOT NULL REFERENCES assets(id),
                title      TEXT NOT NULL,
                detail     TEXT NOT NULL,
                severity   TEXT NOT NULL,
                state      TEXT NOT NULL,
                cve_id     TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assets_client ON assets(client_id);
            CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
            CREATE TABLE IF NOT EXISTS chat_messages (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                role       TEXT NOT NULL,
                content    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_asset_kind ON scans(asset_id, kind, status, started_at);
            CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(next_run_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_asset ON alerts(asset_id);
            CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);
            CREATE INDEX IF NOT EXISTS idx_facts_product ON device_facts(product);
            "#,
        )?;
        // Idempotent column add for databases created before alert delivery existed.
        let _ = conn.execute(
            "ALTER TABLE alerts ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0",
            [],
        );
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

    /// Every asset across all clients (used by the SNMP collector).
    pub fn list_all_assets(&self) -> Result<Vec<Asset>> {
        self.query_assets("", "")
    }

    pub fn get_asset(&self, id: Id) -> Result<Option<Asset>> {
        Ok(self
            .query_assets("WHERE id = ?1", &id.to_string())?
            .into_iter()
            .next())
    }

    /// Change an asset's kind/value (its scan target). Authorization is handled
    /// separately by the caller (changing the target should re-require it).
    pub fn set_asset_target(&self, id: Id, kind: AssetKind, value: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE assets SET kind=?2, value=?3 WHERE id=?1",
            params![id.to_string(), kind.as_str(), value],
        )?;
        Ok(())
    }

    /// Delete an asset and everything that references it (findings, alerts,
    /// scans, schedules, facts, baselines, CVE matches), atomically.
    pub fn delete_asset(&self, id: Id) -> Result<()> {
        let aid = id.to_string();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for sql in [
            "DELETE FROM findings WHERE asset_id=?1",
            "DELETE FROM alerts WHERE asset_id=?1",
            "DELETE FROM scans WHERE asset_id=?1",
            "DELETE FROM schedules WHERE asset_id=?1",
            "DELETE FROM device_facts WHERE asset_id=?1",
            "DELETE FROM web_baselines WHERE asset_id=?1",
            "DELETE FROM cve_matches WHERE asset_id=?1",
            "DELETE FROM vuln_candidates WHERE asset_id=?1",
            "DELETE FROM assets WHERE id=?1",
        ] {
            tx.execute(sql, params![aid])?;
        }
        tx.commit()?;
        Ok(())
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
        // Current state only: the latest completed scan per kind, so rescanning
        // does not accumulate duplicate findings in the device view.
        let wc = format!("WHERE f.asset_id = ?1 AND {CURRENT_PRED}");
        self.query_findings(&wc, &asset_id.to_string())
    }

    fn query_findings(&self, where_clause: &str, arg: &str) -> Result<Vec<Finding>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, scan_id, asset_id, kind, key, title, detail, severity, observed_at
             FROM findings f {where_clause} ORDER BY observed_at DESC"
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

    // ---- schedules ----

    pub fn insert_schedule(&self, s: &Schedule) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO schedules (id, asset_id, kind, interval_secs, next_run_at, enabled)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                s.id.to_string(),
                s.asset_id.to_string(),
                s.kind.as_str(),
                s.interval_secs,
                ts(&s.next_run_at),
                s.enabled as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_schedules_for_asset(&self, asset_id: Id) -> Result<Vec<Schedule>> {
        self.query_schedules("WHERE asset_id = ?1", Some(&asset_id.to_string()))
    }

    /// Enabled schedules whose `next_run_at` is at or before `now`.
    pub fn list_due_schedules(&self, now: DateTime<Utc>) -> Result<Vec<Schedule>> {
        self.query_schedules("WHERE enabled = 1 AND next_run_at <= ?1", Some(&ts(&now)))
    }

    pub fn update_schedule_next_run(&self, id: Id, next: DateTime<Utc>) -> Result<()> {
        self.lock()?.execute(
            "UPDATE schedules SET next_run_at=?2 WHERE id=?1",
            params![id.to_string(), ts(&next)],
        )?;
        Ok(())
    }

    pub fn set_schedule_enabled(&self, id: Id, enabled: bool) -> Result<()> {
        self.lock()?.execute(
            "UPDATE schedules SET enabled=?2 WHERE id=?1",
            params![id.to_string(), enabled as i64],
        )?;
        Ok(())
    }

    fn query_schedules(&self, where_clause: &str, arg: Option<&str>) -> Result<Vec<Schedule>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, asset_id, kind, interval_secs, next_run_at, enabled
             FROM schedules {where_clause} ORDER BY next_run_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mapper = |r: &rusqlite::Row<'_>| {
            Ok(ScheduleRow {
                id: r.get(0)?,
                asset_id: r.get(1)?,
                kind: r.get(2)?,
                interval_secs: r.get(3)?,
                next_run_at: r.get(4)?,
                enabled: r.get(5)?,
            })
        };
        let raws = match arg {
            Some(a) => stmt
                .query_map([a], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => stmt
                .query_map([], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        raws.into_iter().map(hydrate_schedule).collect()
    }

    // ---- alerts ----

    pub fn insert_alert(&self, a: &Alert) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO alerts (id, asset_id, scan_id, severity, summary, detail, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                a.id.to_string(),
                a.asset_id.to_string(),
                a.scan_id.map(|x| x.to_string()),
                a.severity.as_str(),
                a.summary,
                a.detail,
                ts(&a.created_at),
            ],
        )?;
        Ok(())
    }

    pub fn list_alerts(&self) -> Result<Vec<Alert>> {
        self.query_alerts("", None)
    }

    pub fn list_alerts_for_asset(&self, asset_id: Id) -> Result<Vec<Alert>> {
        self.query_alerts("WHERE asset_id = ?1", Some(&asset_id.to_string()))
    }

    fn query_alerts(&self, where_clause: &str, arg: Option<&str>) -> Result<Vec<Alert>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, asset_id, scan_id, severity, summary, detail, created_at
             FROM alerts {where_clause} ORDER BY created_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mapper = |r: &rusqlite::Row<'_>| {
            Ok(AlertRow {
                id: r.get(0)?,
                asset_id: r.get(1)?,
                scan_id: r.get(2)?,
                severity: r.get(3)?,
                summary: r.get(4)?,
                detail: r.get(5)?,
                created_at: r.get(6)?,
            })
        };
        let raws = match arg {
            Some(a) => stmt
                .query_map([a], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => stmt
                .query_map([], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        raws.into_iter().map(hydrate_alert).collect()
    }

    /// Alerts not yet delivered to a notification channel.
    pub fn list_undelivered_alerts(&self) -> Result<Vec<Alert>> {
        self.query_alerts("WHERE delivered = 0", None)
    }

    pub fn mark_alert_delivered(&self, id: Id) -> Result<()> {
        self.lock()?.execute(
            "UPDATE alerts SET delivered = 1 WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    // ---- cves ----

    pub fn insert_cve(&self, c: &crate::cve::Cve) -> Result<()> {
        self.lock()?.execute(
            "INSERT OR REPLACE INTO cves (id, published, severity, summary, product, version_start_incl, version_end_excl)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                c.id,
                c.published,
                c.severity.as_str(),
                c.summary,
                c.product,
                c.version_start_incl,
                c.version_end_excl,
            ],
        )?;
        Ok(())
    }

    pub fn list_cves(&self) -> Result<Vec<crate::cve::Cve>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, published, severity, summary, product, version_start_incl, version_end_excl
             FROM cves ORDER BY published DESC",
        )?;
        let raws = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(id, published, sev, summary, product, start, end)| {
                Ok(crate::cve::Cve {
                    id,
                    published,
                    severity: Severity::from_db(&sev)
                        .ok_or_else(|| anyhow!("bad severity {sev}"))?,
                    summary,
                    product,
                    version_start_incl: start,
                    version_end_excl: end,
                })
            })
            .collect()
    }

    // ---- device facts ----

    pub fn upsert_device_facts(&self, f: &crate::fleet::DeviceFacts) -> Result<()> {
        let mgmt = serde_json::to_string(&f.mgmt)?;
        self.lock()?.execute(
            "INSERT OR REPLACE INTO device_facts (asset_id, vendor, product, version, mgmt, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![f.asset_id.to_string(), f.vendor, f.product, f.version, mgmt, ts(&Utc::now())],
        )?;
        Ok(())
    }

    pub fn list_device_facts(&self) -> Result<Vec<crate::fleet::DeviceFacts>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT asset_id, vendor, product, version, mgmt FROM device_facts")?;
        let raws = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(asset_id, vendor, product, version, mgmt)| {
                Ok(crate::fleet::DeviceFacts {
                    asset_id: pid(&asset_id)?,
                    vendor,
                    product,
                    version,
                    mgmt: serde_json::from_str(&mgmt).unwrap_or_default(),
                })
            })
            .collect()
    }

    /// High-water `last_modified` cursor for an incremental feed sync.
    pub fn get_sync_cursor(&self, source: &str, product: &str) -> Result<Option<DateTime<Utc>>> {
        let conn = self.lock()?;
        let v: Option<Option<String>> = conn
            .query_row(
                "SELECT last_modified FROM cve_sync_state WHERE source=?1 AND product=?2",
                params![source, product],
                |r| r.get(0),
            )
            .ok();
        match v.flatten() {
            Some(s) => Ok(Some(pts(&s)?)),
            None => Ok(None),
        }
    }

    pub fn set_sync_cursor(
        &self,
        source: &str,
        product: &str,
        last_modified: Option<DateTime<Utc>>,
        last_run_at: DateTime<Utc>,
        status: &str,
    ) -> Result<()> {
        self.lock()?.execute(
            "INSERT OR REPLACE INTO cve_sync_state (source, product, last_modified, last_run_at, last_status)
             VALUES (?1,?2,?3,?4,?5)",
            params![source, product, last_modified.map(|t| ts(&t)), ts(&last_run_at), status],
        )?;
        Ok(())
    }

    /// Record a (cve, asset) match; returns true if it is newly recorded (so
    /// the caller raises exactly one alert per pair).
    pub fn record_cve_match(&self, cve_id: &str, asset_id: Id) -> Result<bool> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "INSERT OR IGNORE INTO cve_matches (cve_id, asset_id, created_at) VALUES (?1,?2,?3)",
            params![cve_id, asset_id.to_string(), ts(&Utc::now())],
        )?;
        Ok(changed > 0)
    }

    // ---- mitigation proposals (NetFlow x BGP, approval-gated) ----

    pub fn insert_mitigation(&self, p: &crate::flowbgp::MitigationProposal) -> Result<()> {
        let action = serde_json::to_string(&p.action)?;
        self.lock()?.execute(
            "INSERT INTO mitigation_proposals (id, title, dst_cidr, action, state, approver, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                p.id.to_string(),
                p.title,
                p.dst_cidr,
                action,
                p.state.as_str(),
                p.approver,
                ts(&p.created_at),
                ts(&p.updated_at),
            ],
        )?;
        Ok(())
    }

    pub fn update_mitigation_state(
        &self,
        id: Id,
        state: crate::flowbgp::MitigationState,
        approver: Option<&str>,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE mitigation_proposals SET state=?2, approver=COALESCE(?3, approver), updated_at=?4 WHERE id=?1",
            params![id.to_string(), state.as_str(), approver, ts(&Utc::now())],
        )?;
        Ok(())
    }

    pub fn get_mitigation(&self, id: Id) -> Result<Option<crate::flowbgp::MitigationProposal>> {
        Ok(self
            .query_mitigations("WHERE id = ?1", Some(&id.to_string()))?
            .into_iter()
            .next())
    }

    pub fn list_mitigations(&self) -> Result<Vec<crate::flowbgp::MitigationProposal>> {
        self.query_mitigations("", None)
    }

    fn query_mitigations(
        &self,
        where_clause: &str,
        arg: Option<&str>,
    ) -> Result<Vec<crate::flowbgp::MitigationProposal>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, title, dst_cidr, action, state, approver, created_at, updated_at
             FROM mitigation_proposals {where_clause} ORDER BY created_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mapper = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        };
        let raws = match arg {
            Some(a) => stmt
                .query_map([a], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => stmt
                .query_map([], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        raws.into_iter()
            .map(
                |(id, title, dst_cidr, action, state, approver, created, updated)| {
                    Ok(crate::flowbgp::MitigationProposal {
                        id: pid(&id)?,
                        title,
                        dst_cidr,
                        action: serde_json::from_str(&action)?,
                        state: crate::flowbgp::MitigationState::from_db(&state)
                            .ok_or_else(|| anyhow!("bad mitigation state {state}"))?,
                        approver,
                        created_at: pts(&created)?,
                        updated_at: pts(&updated)?,
                    })
                },
            )
            .collect()
    }

    // ---- web baselines ----

    pub fn get_web_content_hash(&self, asset_id: Id) -> Result<Option<String>> {
        let conn = self.lock()?;
        let v: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM web_baselines WHERE asset_id=?1",
                params![asset_id.to_string()],
                |r| r.get(0),
            )
            .ok();
        Ok(v)
    }

    pub fn upsert_web_baseline(
        &self,
        asset_id: Id,
        content_hash: &str,
        header_grade: char,
        cert_expiry_days: Option<i64>,
    ) -> Result<()> {
        self.lock()?.execute(
            "INSERT OR REPLACE INTO web_baselines (asset_id, content_hash, header_grade, cert_expiry_days, updated_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![asset_id.to_string(), content_hash, header_grade.to_string(), cert_expiry_days, ts(&Utc::now())],
        )?;
        Ok(())
    }

    // ---- vuln candidates (research lab / disclosure) ----

    pub fn insert_candidate(&self, c: &crate::disclosure::VulnCandidate) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO vuln_candidates (id, asset_id, title, detail, severity, state, cve_id, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                c.id.to_string(),
                c.asset_id.to_string(),
                c.title,
                c.detail,
                c.severity.as_str(),
                c.state.as_str(),
                c.cve_id,
                ts(&c.created_at),
                ts(&c.updated_at),
            ],
        )?;
        Ok(())
    }

    pub fn update_candidate_state(
        &self,
        id: Id,
        state: crate::disclosure::DisclosureState,
        cve_id: Option<&str>,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE vuln_candidates SET state=?2, cve_id=COALESCE(?3, cve_id), updated_at=?4 WHERE id=?1",
            params![id.to_string(), state.as_str(), cve_id, ts(&Utc::now())],
        )?;
        Ok(())
    }

    pub fn get_candidate(&self, id: Id) -> Result<Option<crate::disclosure::VulnCandidate>> {
        Ok(self
            .query_candidates("WHERE id = ?1", Some(&id.to_string()))?
            .into_iter()
            .next())
    }

    pub fn list_candidates(&self) -> Result<Vec<crate::disclosure::VulnCandidate>> {
        self.query_candidates("", None)
    }

    fn query_candidates(
        &self,
        where_clause: &str,
        arg: Option<&str>,
    ) -> Result<Vec<crate::disclosure::VulnCandidate>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT id, asset_id, title, detail, severity, state, cve_id, created_at, updated_at
             FROM vuln_candidates {where_clause} ORDER BY created_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mapper = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        };
        let raws = match arg {
            Some(a) => stmt
                .query_map([a], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => stmt
                .query_map([], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        raws.into_iter()
            .map(
                |(id, asset_id, title, detail, sev, state, cve_id, created, updated)| {
                    Ok(crate::disclosure::VulnCandidate {
                        id: pid(&id)?,
                        asset_id: pid(&asset_id)?,
                        title,
                        detail,
                        severity: Severity::from_db(&sev)
                            .ok_or_else(|| anyhow!("bad severity {sev}"))?,
                        state: crate::disclosure::DisclosureState::from_db(&state)
                            .ok_or_else(|| anyhow!("bad disclosure state {state}"))?,
                        cve_id,
                        created_at: pts(&created)?,
                        updated_at: pts(&updated)?,
                    })
                },
            )
            .collect()
    }

    // ---- dashboard aggregates ---------------------------------------------
    // Cheap COUNT/GROUP BY rollups for the SOC dashboard. These stay fast at
    // estate scale (tens of thousands of assets) because they never hydrate
    // rows — the database does the counting.

    fn scalar_i64(&self, sql: &str) -> Result<i64> {
        let conn = self.lock()?;
        Ok(conn.query_row(sql, [], |r| r.get(0))?)
    }

    fn group_map(&self, sql: &str) -> Result<BTreeMap<String, i64>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().collect())
    }

    /// Rollup counts for the dashboard header and severity breakdowns.
    pub fn overview_counts(&self) -> Result<OverviewCounts> {
        Ok(OverviewCounts {
            clients: self.scalar_i64("SELECT COUNT(*) FROM clients")?,
            assets: self.scalar_i64("SELECT COUNT(*) FROM assets")?,
            assets_by_status: self
                .group_map("SELECT auth_status, COUNT(*) FROM assets GROUP BY auth_status")?,
            alerts: self.scalar_i64("SELECT COUNT(*) FROM alerts")?,
            alerts_by_severity: self
                .group_map("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")?,
            findings: self.scalar_i64(&format!("SELECT COUNT(*) FROM findings f WHERE {CURRENT_PRED}"))?,
            findings_by_severity: self.group_map(&format!(
                "SELECT f.severity, COUNT(*) FROM findings f WHERE {CURRENT_PRED} GROUP BY f.severity"
            ))?,
            scans: self.scalar_i64("SELECT COUNT(*) FROM scans")?,
            scans_by_status: self
                .group_map("SELECT status, COUNT(*) FROM scans GROUP BY status")?,
            cves: self.scalar_i64("SELECT COUNT(*) FROM cves")?,
            cve_matches: self.scalar_i64("SELECT COUNT(*) FROM cve_matches")?,
            cve_last_sync: self.cve_last_sync()?.map(|t| ts(&t)),
        })
    }

    /// Most recent scans across all assets, with the asset value and finding
    /// count, for the activity feed.
    pub fn recent_scans(&self, limit: i64) -> Result<Vec<RecentScan>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT s.id, s.asset_id, a.value, s.kind, s.status, s.started_at, s.finished_at, s.note,
                    (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id)
             FROM scans s JOIN assets a ON a.id = s.asset_id
             ORDER BY s.started_at DESC LIMIT ?1",
        )?;
        let raws = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(
                |(id, aid, val, kind, status, started, finished, note, fc)| {
                    Ok(RecentScan {
                        id: pid(&id)?,
                        asset_id: pid(&aid)?,
                        asset_value: val,
                        kind: ScanKind::from_db(&kind)
                            .ok_or_else(|| anyhow!("bad scan kind {kind}"))?,
                        status: ScanStatus::from_db(&status)
                            .ok_or_else(|| anyhow!("bad scan status {status}"))?,
                        started_at: pts(&started)?,
                        finished_at: pts_opt(finished)?,
                        note,
                        findings: fc,
                    })
                },
            )
            .collect()
    }

    /// Most recent alerts across all assets, with the asset value, for the feed.
    pub fn recent_alerts(&self, limit: i64) -> Result<Vec<RecentAlert>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT al.id, al.asset_id, a.value, al.severity, al.summary, al.detail, al.created_at
             FROM alerts al JOIN assets a ON a.id = al.asset_id
             ORDER BY al.created_at DESC LIMIT ?1",
        )?;
        let raws = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(id, aid, val, sev, summary, detail, created)| {
                Ok(RecentAlert {
                    id: pid(&id)?,
                    asset_id: pid(&aid)?,
                    asset_value: val,
                    severity: Severity::from_db(&sev)
                        .ok_or_else(|| anyhow!("bad severity {sev}"))?,
                    summary,
                    detail,
                    created_at: pts(&created)?,
                })
            })
            .collect()
    }

    /// Most recent findings across all assets, with the asset value, for the feed.
    pub fn recent_findings(&self, limit: i64) -> Result<Vec<RecentFinding>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT f.asset_id, a.value, f.kind, f.key, f.title, f.severity, f.observed_at
             FROM findings f JOIN assets a ON a.id = f.asset_id
             WHERE {CURRENT_PRED}
             ORDER BY f.observed_at DESC LIMIT ?1"
        ))?;
        let raws = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(aid, val, kind, key, title, sev, observed)| {
                Ok(RecentFinding {
                    asset_id: pid(&aid)?,
                    asset_value: val,
                    kind,
                    key,
                    title,
                    severity: Severity::from_db(&sev)
                        .ok_or_else(|| anyhow!("bad severity {sev}"))?,
                    observed_at: pts(&observed)?,
                })
            })
            .collect()
    }

    /// Device count per product key, for the fleet breakdown.
    pub fn fleet_by_product(&self) -> Result<BTreeMap<String, i64>> {
        self.group_map("SELECT product, COUNT(*) FROM device_facts GROUP BY product")
    }

    /// Most recent CVE feed sync time across all products (None if never synced).
    pub fn cve_last_sync(&self) -> Result<Option<DateTime<Utc>>> {
        let conn = self.lock()?;
        let v: Option<String> =
            conn.query_row("SELECT MAX(last_run_at) FROM cve_sync_state", [], |r| {
                r.get::<_, Option<String>>(0)
            })?;
        match v {
            Some(s) => Ok(Some(pts(&s)?)),
            None => Ok(None),
        }
    }

    /// Most recent CVE↔device matches, joined with the CVE and asset, for the feed.
    pub fn recent_cve_matches(&self, limit: i64) -> Result<Vec<RecentCveMatch>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT m.cve_id, c.severity, c.summary, c.product, m.asset_id, a.value, m.created_at
             FROM cve_matches m
             JOIN cves c ON c.id = m.cve_id
             JOIN assets a ON a.id = m.asset_id
             ORDER BY m.created_at DESC LIMIT ?1",
        )?;
        let raws = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(cve_id, sev, summary, product, aid, val, created)| {
                Ok(RecentCveMatch {
                    cve_id,
                    severity: Severity::from_db(&sev)
                        .ok_or_else(|| anyhow!("bad severity {sev}"))?,
                    summary,
                    product,
                    asset_id: pid(&aid)?,
                    asset_value: val,
                    created_at: pts(&created)?,
                })
            })
            .collect()
    }

    // ---- chat transcript (persisted so the assistant reopens with history) --

    pub fn insert_chat_message(&self, role: &str, content: &str) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO chat_messages (role, content, created_at) VALUES (?1,?2,?3)",
            params![role, content, ts(&Utc::now())],
        )?;
        Ok(())
    }

    /// The last `limit` chat messages, in chronological order.
    pub fn list_chat_messages(&self, limit: i64) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT role, content FROM
                (SELECT seq, role, content FROM chat_messages ORDER BY seq DESC LIMIT ?1)
             ORDER BY seq ASC",
        )?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn clear_chat_messages(&self) -> Result<()> {
        self.lock()?.execute("DELETE FROM chat_messages", [])?;
        Ok(())
    }
}

// ---- dashboard aggregate structs --------------------------------------------

#[derive(Debug, Serialize)]
pub struct OverviewCounts {
    pub clients: i64,
    pub assets: i64,
    pub assets_by_status: BTreeMap<String, i64>,
    pub alerts: i64,
    pub alerts_by_severity: BTreeMap<String, i64>,
    pub findings: i64,
    pub findings_by_severity: BTreeMap<String, i64>,
    pub scans: i64,
    pub scans_by_status: BTreeMap<String, i64>,
    pub cves: i64,
    pub cve_matches: i64,
    /// RFC3339 time of the most recent CVE feed sync, or null if never synced.
    pub cve_last_sync: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RecentScan {
    pub id: Id,
    pub asset_id: Id,
    pub asset_value: String,
    pub kind: ScanKind,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
    pub findings: i64,
}

#[derive(Debug, Serialize)]
pub struct RecentAlert {
    pub id: Id,
    pub asset_id: Id,
    pub asset_value: String,
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RecentFinding {
    pub asset_id: Id,
    pub asset_value: String,
    pub kind: String,
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RecentCveMatch {
    pub cve_id: String,
    pub severity: Severity,
    pub summary: String,
    pub product: String,
    pub asset_id: Id,
    pub asset_value: String,
    pub created_at: DateTime<Utc>,
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

struct ScheduleRow {
    id: String,
    asset_id: String,
    kind: String,
    interval_secs: i64,
    next_run_at: String,
    enabled: i64,
}

fn hydrate_schedule(raw: ScheduleRow) -> Result<Schedule> {
    Ok(Schedule {
        id: pid(&raw.id)?,
        asset_id: pid(&raw.asset_id)?,
        kind: ScanKind::from_db(&raw.kind).ok_or_else(|| anyhow!("bad scan kind {}", raw.kind))?,
        interval_secs: raw.interval_secs,
        next_run_at: pts(&raw.next_run_at)?,
        enabled: raw.enabled != 0,
    })
}

struct AlertRow {
    id: String,
    asset_id: String,
    scan_id: Option<String>,
    severity: String,
    summary: String,
    detail: String,
    created_at: String,
}

fn hydrate_alert(raw: AlertRow) -> Result<Alert> {
    Ok(Alert {
        id: pid(&raw.id)?,
        asset_id: pid(&raw.asset_id)?,
        scan_id: raw.scan_id.map(|s| pid(&s)).transpose()?,
        severity: Severity::from_db(&raw.severity)
            .ok_or_else(|| anyhow!("bad severity {}", raw.severity))?,
        summary: raw.summary,
        detail: raw.detail,
        created_at: pts(&raw.created_at)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn mem() -> Store {
        let s = Store::open(":memory:").unwrap();
        s.migrate().unwrap();
        s
    }

    fn seed_asset(s: &Store) -> Id {
        let cid = Uuid::new_v4();
        s.insert_client(&Client {
            id: cid,
            name: "C".into(),
            contact_email: "c@e".into(),
            created_at: Utc::now(),
        })
        .unwrap();
        let aid = Uuid::new_v4();
        s.insert_asset(&Asset {
            id: aid,
            client_id: cid,
            kind: AssetKind::Host,
            value: "203.0.113.1".into(),
            auth_status: AuthStatus::Active,
            authorized_until: None,
            window_start: None,
            window_end: None,
            roe_reference: Some("RoE-1".into()),
            created_at: Utc::now(),
        })
        .unwrap();
        aid
    }

    #[test]
    fn asset_roundtrips_through_sqlite() {
        let s = mem();
        let aid = seed_asset(&s);
        let got = s.get_asset(aid).unwrap().unwrap();
        assert_eq!(got.value, "203.0.113.1");
        assert_eq!(got.auth_status, AuthStatus::Active);
        assert_eq!(got.roe_reference.as_deref(), Some("RoE-1"));
    }

    #[test]
    fn set_target_and_delete_cascade() {
        let s = mem();
        let aid = seed_asset(&s);
        // rename target
        s.set_asset_target(aid, AssetKind::Domain, "new.example")
            .unwrap();
        let got = s.get_asset(aid).unwrap().unwrap();
        assert_eq!(got.value, "new.example");
        assert_eq!(got.kind, AssetKind::Domain);

        // give it a dependent row, then delete — must not FK-fail and must vanish
        let scan_id = Uuid::new_v4();
        s.insert_scan(&Scan {
            id: scan_id,
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            status: ScanStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            note: None,
        })
        .unwrap();
        s.insert_finding(&Finding {
            id: Uuid::new_v4(),
            scan_id,
            asset_id: aid,
            kind: "open_port".into(),
            key: "tcp/22".into(),
            title: "x".into(),
            detail: "x".into(),
            severity: Severity::Info,
            observed_at: Utc::now(),
        })
        .unwrap();

        s.delete_asset(aid).unwrap();
        assert!(s.get_asset(aid).unwrap().is_none());
        assert!(s.list_findings_for_asset(aid).unwrap().is_empty());
    }

    #[test]
    fn due_schedules_respect_time_and_enabled_flag() {
        let s = mem();
        let aid = seed_asset(&s);
        let now = Utc::now();

        let due = Schedule {
            id: Uuid::new_v4(),
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            interval_secs: 3600,
            next_run_at: now - Duration::minutes(1),
            enabled: true,
        };
        let future = Schedule {
            id: Uuid::new_v4(),
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            interval_secs: 3600,
            next_run_at: now + Duration::hours(1),
            enabled: true,
        };
        let disabled = Schedule {
            id: Uuid::new_v4(),
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            interval_secs: 3600,
            next_run_at: now - Duration::minutes(1),
            enabled: false,
        };
        s.insert_schedule(&due).unwrap();
        s.insert_schedule(&future).unwrap();
        s.insert_schedule(&disabled).unwrap();

        let got = s.list_due_schedules(now).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, due.id);

        // After rescheduling, it is no longer due.
        s.update_schedule_next_run(due.id, now + Duration::hours(1))
            .unwrap();
        assert!(s.list_due_schedules(now).unwrap().is_empty());
    }

    #[test]
    fn alerts_persist_and_list_newest_first() {
        let s = mem();
        let aid = seed_asset(&s);
        let scan_id = Uuid::new_v4();
        s.insert_scan(&Scan {
            id: scan_id,
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            status: ScanStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            note: None,
        })
        .unwrap();
        s.insert_alert(&Alert {
            id: Uuid::new_v4(),
            asset_id: aid,
            scan_id: Some(scan_id),
            severity: Severity::Medium,
            summary: "change".into(),
            detail: "new: tcp/3389".into(),
            created_at: Utc::now(),
        })
        .unwrap();
        assert_eq!(s.list_alerts().unwrap().len(), 1);
        assert_eq!(s.list_alerts_for_asset(aid).unwrap().len(), 1);
    }

    #[test]
    fn cve_facts_and_match_dedup() {
        use crate::cve::Cve;
        use crate::fleet::{run_correlation, DeviceFacts};
        let s = mem();
        let aid = seed_asset(&s);

        s.insert_cve(&Cve {
            id: "CVE-2023-41570".into(),
            published: "2023-10-01".into(),
            severity: Severity::High,
            summary: "RouterOS issue".into(),
            product: "routeros".into(),
            version_start_incl: None,
            version_end_excl: Some("6.49.8".into()),
        })
        .unwrap();
        s.upsert_device_facts(&DeviceFacts {
            asset_id: aid,
            vendor: "MikroTik".into(),
            product: "routeros".into(),
            version: Some("6.49.7".into()),
            mgmt: vec!["winbox/8291".into()],
        })
        .unwrap();

        assert_eq!(s.list_cves().unwrap().len(), 1);
        assert_eq!(s.list_device_facts().unwrap().len(), 1);

        // First correlation raises one alert; a second run is a no-op (dedup).
        assert_eq!(run_correlation(&s).unwrap(), 1);
        assert_eq!(run_correlation(&s).unwrap(), 0);
        assert_eq!(s.list_alerts_for_asset(aid).unwrap().len(), 1);
    }

    #[test]
    fn findings_show_only_latest_completed_scan_per_kind() {
        let s = mem();
        let aid = seed_asset(&s);
        let t1 = Utc::now();
        let scan1 = Uuid::new_v4();
        s.insert_scan(&Scan {
            id: scan1,
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            status: ScanStatus::Completed,
            started_at: t1,
            finished_at: Some(t1),
            note: None,
        })
        .unwrap();
        for k in ["tcp/22", "tcp/80"] {
            s.insert_finding(&Finding {
                id: Uuid::new_v4(),
                scan_id: scan1,
                asset_id: aid,
                kind: "open_port".into(),
                key: k.into(),
                title: k.into(),
                detail: String::new(),
                severity: Severity::Info,
                observed_at: t1,
            })
            .unwrap();
        }
        // A later scan of the same kind supersedes the earlier one.
        let t2 = t1 + Duration::seconds(5);
        let scan2 = Uuid::new_v4();
        s.insert_scan(&Scan {
            id: scan2,
            asset_id: aid,
            kind: ScanKind::ExternalSurface,
            status: ScanStatus::Completed,
            started_at: t2,
            finished_at: Some(t2),
            note: None,
        })
        .unwrap();
        s.insert_finding(&Finding {
            id: Uuid::new_v4(),
            scan_id: scan2,
            asset_id: aid,
            kind: "open_port".into(),
            key: "tcp/22".into(),
            title: "tcp/22".into(),
            detail: String::new(),
            severity: Severity::Info,
            observed_at: t2,
        })
        .unwrap();

        let cur = s.list_findings_for_asset(aid).unwrap();
        assert_eq!(cur.len(), 1, "only the latest scan's findings remain");
        assert_eq!(cur[0].key, "tcp/22");
        assert_eq!(cur[0].scan_id, scan2);
    }
}
