//! Alert generation from a baseline diff. A noteworthy change (new or removed
//! exposure) becomes an [`Alert`], which the orchestrator persists and logs.
//! Delivery channels (webhook/email/Slack) plug in behind this: build the
//! alert here, then hand it to a sink.

use chrono::Utc;
use uuid::Uuid;

use crate::domain::{Alert, Id, ScanKind, Severity};
use crate::scan::diff::DiffSummary;

/// Build an alert from a noteworthy diff. New exposure (added keys) is treated
/// as more serious than reduced exposure (only removals).
pub fn from_diff(asset_id: Id, scan_id: Id, kind: ScanKind, summary: &DiffSummary) -> Alert {
    let severity = if !summary.added.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    };

    let mut parts = Vec::new();
    if !summary.added.is_empty() {
        parts.push(format!("new: {}", summary.added.join(", ")));
    }
    if !summary.removed.is_empty() {
        parts.push(format!("gone: {}", summary.removed.join(", ")));
    }
    let detail = parts.join("; ");
    let summary_line = format!(
        "{kind:?} change on asset ({} item(s))",
        summary.added.len() + summary.removed.len()
    );

    Alert {
        id: Uuid::new_v4(),
        asset_id,
        scan_id,
        severity,
        summary: summary_line,
        detail,
        created_at: Utc::now(),
    }
}

/// Log sink. Replaceable/extendable with webhook/email delivery.
pub fn log(alert: &Alert) {
    eprintln!(
        "netdefense ALERT [{}] asset={} scan={} :: {} — {}",
        alert.severity.as_str(),
        alert.asset_id,
        alert.scan_id,
        alert.summary,
        alert.detail
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::diff::DiffSummary;

    fn summary(added: &[&str], removed: &[&str]) -> DiffSummary {
        DiffSummary {
            added: added.iter().map(|s| s.to_string()).collect(),
            removed: removed.iter().map(|s| s.to_string()).collect(),
            unchanged: vec![],
            first_baseline: false,
        }
    }

    #[test]
    fn added_exposure_is_medium() {
        let a = from_diff(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ScanKind::ExternalSurface,
            &summary(&["tcp/3389"], &[]),
        );
        assert_eq!(a.severity, Severity::Medium);
        assert!(a.detail.contains("tcp/3389"));
    }

    #[test]
    fn only_removals_is_low() {
        let a = from_diff(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ScanKind::ExternalSurface,
            &summary(&[], &["tcp/22"]),
        );
        assert_eq!(a.severity, Severity::Low);
        assert!(a.detail.contains("gone"));
    }
}
