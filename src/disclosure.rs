//! Coordinated disclosure for vulnerabilities found in the research lab.
//!
//! A new vulnerability found on your own lab gear must not be dropped publicly
//! before a patch exists — that would expose your own ~20k-device fleet first.
//! This models the responsible path as a state machine with a strict set of
//! allowed transitions; the transition function is pure and unit-tested.

use serde::{Deserialize, Serialize};

use crate::domain::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureState {
    /// Found in the lab, not yet reported to the vendor.
    Discovered,
    /// Reported to the vendor (coordinated disclosure started).
    VendorNotified,
    /// A CVE id has been reserved (e.g. via a CNA / MITRE).
    CveReserved,
    /// Vendor has published a fix.
    PatchAvailable,
    /// Publicly disclosed (after a patch exists).
    Published,
    /// Vendor declined / not applicable — closed without publication.
    WontFix,
}

impl DisclosureState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureState::Discovered => "discovered",
            DisclosureState::VendorNotified => "vendor_notified",
            DisclosureState::CveReserved => "cve_reserved",
            DisclosureState::PatchAvailable => "patch_available",
            DisclosureState::Published => "published",
            DisclosureState::WontFix => "wont_fix",
        }
    }
    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s {
            "discovered" => DisclosureState::Discovered,
            "vendor_notified" => DisclosureState::VendorNotified,
            "cve_reserved" => DisclosureState::CveReserved,
            "patch_available" => DisclosureState::PatchAvailable,
            "published" => DisclosureState::Published,
            "wont_fix" => DisclosureState::WontFix,
            _ => return None,
        })
    }
}

/// Is `to` a permitted next state from `from`? The ordinary path moves forward
/// Discovered → VendorNotified → CveReserved → PatchAvailable → Published, and
/// from any pre-publication state the case may be closed as WontFix.
/// Crucially, Published is reachable ONLY from PatchAvailable.
pub fn allowed(from: DisclosureState, to: DisclosureState) -> bool {
    use DisclosureState::*;
    matches!(
        (from, to),
        (Discovered, VendorNotified)
            | (VendorNotified, CveReserved)
            | (CveReserved, PatchAvailable)
            | (PatchAvailable, Published)
            | (Discovered, WontFix)
            | (VendorNotified, WontFix)
            | (CveReserved, WontFix)
            | (PatchAvailable, WontFix)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub from: DisclosureState,
    pub to: DisclosureState,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "disclosure transition {} → {} not allowed",
            self.from.as_str(),
            self.to.as_str()
        )
    }
}

/// Advance the state, enforcing the policy. In particular this refuses to
/// publish before a patch exists.
pub fn advance(
    from: DisclosureState,
    to: DisclosureState,
) -> Result<DisclosureState, TransitionError> {
    if allowed(from, to) {
        Ok(to)
    } else {
        Err(TransitionError { from, to })
    }
}

/// A vulnerability candidate tracked through disclosure. Found only on lab
/// (non-production) assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnCandidate {
    pub id: crate::domain::Id,
    pub asset_id: crate::domain::Id,
    pub title: String,
    pub detail: String,
    pub severity: Severity,
    pub state: DisclosureState,
    pub cve_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::DisclosureState::*;
    use super::*;

    #[test]
    fn forward_path_is_allowed() {
        assert!(advance(Discovered, VendorNotified).is_ok());
        assert!(advance(VendorNotified, CveReserved).is_ok());
        assert!(advance(CveReserved, PatchAvailable).is_ok());
        assert!(advance(PatchAvailable, Published).is_ok());
    }

    #[test]
    fn publish_requires_a_patch_first() {
        // The whole point: never public before a fix exists.
        assert!(advance(Discovered, Published).is_err());
        assert!(advance(VendorNotified, Published).is_err());
        assert!(advance(CveReserved, Published).is_err());
    }

    #[test]
    fn cannot_skip_or_go_backwards() {
        assert!(advance(Discovered, CveReserved).is_err());
        assert!(advance(CveReserved, VendorNotified).is_err());
        assert!(advance(Published, Discovered).is_err());
    }

    #[test]
    fn can_close_as_wont_fix_before_publication() {
        assert!(advance(Discovered, WontFix).is_ok());
        assert!(advance(PatchAvailable, WontFix).is_ok());
        // but not after publishing
        assert!(advance(Published, WontFix).is_err());
    }
}
