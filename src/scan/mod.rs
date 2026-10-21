//! Scan orchestration. Every scan goes through the authorisation gate first;
//! a refusal is recorded as a `Refused` scan (for audit) rather than silently
//! dropped. Only `ExternalSurface` is implemented so far; the other kinds are
//! gated and stubbed so the wiring is honest about what runs.

pub mod availability;
pub mod diff;
pub mod external;
pub mod runner;
pub mod vuln;
pub mod webhygiene;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::alert;
use crate::authz::{self};
use crate::domain::*;
use crate::store::Store;
use diff::DiffSummary;

/// A finding produced by a scanner before it is assigned ids/timestamps.
#[derive(Debug, Clone)]
pub struct FindingDraft {
    pub kind: String,
    pub key: String,
    pub title: String,
    pub detail: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanOutcome {
    pub scan: Scan,
    pub findings: Vec<Finding>,
    pub diff: Option<DiffSummary>,
    pub alert: Option<Alert>,
}

const DEFAULT_SCAN_TIMEOUT: u64 = 300;

/// Run a scan of `asset_id`. Loads the asset, applies the authorisation gate,
/// and either records a `Refused` scan or runs the scanner, stores findings,
/// and diffs against the previous baseline.
pub async fn run_scan(store: &Store, asset_id: Id, kind: ScanKind) -> Result<ScanOutcome> {
    let asset = store
        .get_asset(asset_id)?
        .ok_or_else(|| anyhow::anyhow!("asset {asset_id} not found"))?;

    let now = Utc::now();
    let scan_id = Uuid::new_v4();

    // --- authorisation gate ---
    let target = match authz::authorize(&asset, now) {
        Ok(t) => t,
        Err(e) => {
            let scan = Scan {
                id: scan_id,
                asset_id,
                kind,
                status: ScanStatus::Refused,
                started_at: now,
                finished_at: Some(now),
                note: Some(format!("refused by authorisation gate: {e}")),
            };
            store.insert_scan(&scan)?;
            return Ok(ScanOutcome {
                scan,
                findings: vec![],
                diff: None,
                alert: None,
            });
        }
    };

    // --- record the running scan ---
    let mut scan = Scan {
        id: scan_id,
        asset_id,
        kind,
        status: ScanStatus::Running,
        started_at: now,
        finished_at: None,
        note: None,
    };
    store.insert_scan(&scan)?;

    // --- dispatch to the scanner ---
    let drafts = match kind {
        ScanKind::ExternalSurface => {
            external::scan(store, asset_id, &target.value, DEFAULT_SCAN_TIMEOUT).await
        }
        ScanKind::SqlInjection => crate::sqli::scan(&target.value, DEFAULT_SCAN_TIMEOUT).await,
        ScanKind::Availability => {
            availability::scan(asset.kind, &target.value, DEFAULT_SCAN_TIMEOUT).await
        }
        ScanKind::WebHygiene => {
            webhygiene::scan(store, asset_id, &target.value, DEFAULT_SCAN_TIMEOUT).await
        }
        ScanKind::Vuln => vuln::scan(store, asset_id),
    };

    let drafts = match drafts {
        Ok(d) => d,
        Err(e) => {
            let note = e.to_string();
            store.finish_scan(scan_id, ScanStatus::Failed, Some(&note))?;
            scan.status = ScanStatus::Failed;
            scan.finished_at = Some(Utc::now());
            scan.note = Some(note);
            return Ok(ScanOutcome {
                scan,
                findings: vec![],
                diff: None,
                alert: None,
            });
        }
    };

    // --- persist findings ---
    let observed_at = Utc::now();
    let mut findings = Vec::with_capacity(drafts.len());
    for d in &drafts {
        let f = Finding {
            id: Uuid::new_v4(),
            scan_id,
            asset_id,
            kind: d.kind.clone(),
            key: d.key.clone(),
            title: d.title.clone(),
            detail: d.detail.clone(),
            severity: d.severity,
            observed_at,
        };
        store.insert_finding(&f)?;
        findings.push(f);
    }

    // --- diff against the previous baseline, raising an alert on change ---
    let baseline = store.baseline_keys(asset_id, kind, scan_id)?;
    let summary = diff::compare(&baseline, &drafts);
    let mut alert = None;
    if summary.is_noteworthy() {
        let a = alert::from_diff(asset_id, scan_id, kind, &summary);
        store.insert_alert(&a)?;
        alert::log(&a);
        alert = Some(a);
    }

    store.finish_scan(scan_id, ScanStatus::Completed, None)?;
    scan.status = ScanStatus::Completed;
    scan.finished_at = Some(Utc::now());

    Ok(ScanOutcome {
        scan,
        findings,
        diff: Some(summary),
        alert,
    })
}

/// The sensible battery of scans for an asset kind. A "deep" scan runs them
/// all; the choice avoids pointless runs (nmap on a bare URL, SQLi on a host).
pub fn kinds_for(kind: AssetKind) -> Vec<ScanKind> {
    match kind {
        AssetKind::Url => vec![
            ScanKind::Availability,
            ScanKind::WebHygiene,
            ScanKind::SqlInjection,
            ScanKind::Vuln,
        ],
        AssetKind::Domain => vec![
            ScanKind::ExternalSurface,
            ScanKind::Availability,
            ScanKind::WebHygiene,
            ScanKind::Vuln,
        ],
        AssetKind::Host => vec![
            ScanKind::ExternalSurface,
            ScanKind::Availability,
            ScanKind::Vuln,
        ],
        AssetKind::CidrRange => vec![ScanKind::ExternalSurface, ScanKind::Vuln],
    }
}

/// Run the full appropriate battery of scans on one asset (a deep scan). Each
/// scan independently passes the authorisation gate.
pub async fn run_deep_scan(store: &Store, asset_id: Id) -> Result<Vec<ScanOutcome>> {
    let asset = store
        .get_asset(asset_id)?
        .ok_or_else(|| anyhow::anyhow!("asset {asset_id} not found"))?;
    let mut out = Vec::new();
    for k in kinds_for(asset.kind) {
        out.push(run_scan(store, asset_id, k).await?);
    }
    Ok(out)
}
