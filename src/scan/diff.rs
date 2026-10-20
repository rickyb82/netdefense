//! Baseline diff: compare the current scan's finding keys against the previous
//! completed scan. New keys (e.g. a newly open port) are what proactive
//! monitoring alerts on.

use std::collections::BTreeSet;

use serde::Serialize;

use super::FindingDraft;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiffSummary {
    /// Keys present now but not in the baseline (new exposure).
    pub added: Vec<String>,
    /// Keys in the baseline but gone now (closed / resolved).
    pub removed: Vec<String>,
    /// Keys present in both.
    pub unchanged: Vec<String>,
    /// True when there was no prior baseline (first scan of this kind).
    pub first_baseline: bool,
}

impl DiffSummary {
    /// A change worth alerting on. The first scan only establishes the
    /// baseline, so it is never noteworthy even though every key is "added".
    pub fn is_noteworthy(&self) -> bool {
        !self.first_baseline && (!self.added.is_empty() || !self.removed.is_empty())
    }
}

pub fn compare(baseline: &[String], current: &[FindingDraft]) -> DiffSummary {
    let first_baseline = baseline.is_empty();
    let base: BTreeSet<&str> = baseline.iter().map(String::as_str).collect();
    let cur: BTreeSet<&str> = current.iter().map(|f| f.key.as_str()).collect();

    let added = cur.difference(&base).map(|s| s.to_string()).collect();
    let removed = base.difference(&cur).map(|s| s.to_string()).collect();
    let unchanged = cur.intersection(&base).map(|s| s.to_string()).collect();

    DiffSummary {
        added,
        removed,
        unchanged,
        first_baseline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn draft(key: &str) -> FindingDraft {
        FindingDraft {
            kind: "open_port".into(),
            key: key.into(),
            title: key.into(),
            detail: String::new(),
            severity: Severity::Info,
        }
    }

    #[test]
    fn detects_added_and_removed() {
        let baseline = vec!["tcp/22".to_string(), "tcp/80".to_string()];
        let current = vec![draft("tcp/22"), draft("tcp/443")];
        let d = compare(&baseline, &current);
        assert_eq!(d.added, ["tcp/443"]);
        assert_eq!(d.removed, ["tcp/80"]);
        assert_eq!(d.unchanged, ["tcp/22"]);
        assert!(d.is_noteworthy());
        assert!(!d.first_baseline);
    }

    #[test]
    fn first_scan_is_baseline_not_noteworthy() {
        let d = compare(&[], &[draft("tcp/22")]);
        assert!(d.first_baseline);
        assert!(!d.is_noteworthy());
        assert_eq!(d.added, ["tcp/22"]);
    }

    #[test]
    fn no_change_is_not_noteworthy() {
        let base = vec!["tcp/22".to_string()];
        let d = compare(&base, &[draft("tcp/22")]);
        assert!(!d.is_noteworthy());
    }
}
