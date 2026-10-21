//! The scan gate: the single decision point for whether an asset may be
//! scanned. The operator is authorised by default on their own assets, so this
//! no longer requires a signed rules-of-engagement, an expiry or a time window
//! — it only blocks an asset that has been explicitly **suspended** or
//! **revoked** (an opt-out kill switch), or one with an empty target.

use std::fmt;

use crate::domain::{Asset, AuthStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// The asset was explicitly disabled (suspended or revoked).
    Disabled(AuthStatus),
    /// The asset's target value is empty.
    EmptyTarget,
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzError::Disabled(s) => {
                write!(f, "asset disabled for scanning (status: {})", s.as_str())
            }
            AuthzError::EmptyTarget => write!(f, "asset has an empty target value"),
        }
    }
}

/// A target that has cleared the gate. Carrying it (rather than a bare string)
/// means a target can only reach a scanner after `authorize`.
#[derive(Debug)]
pub struct AuthorizedTarget {
    pub value: String,
}

/// Decide whether `asset` may be scanned. Authorised by default; refused only
/// when the asset is explicitly suspended/revoked or has no target. Pure and
/// deterministic — unit tested below.
pub fn authorize(asset: &Asset) -> Result<AuthorizedTarget, AuthzError> {
    if matches!(
        asset.auth_status,
        AuthStatus::Suspended | AuthStatus::Revoked
    ) {
        return Err(AuthzError::Disabled(asset.auth_status));
    }

    let value = asset.value.trim();
    if value.is_empty() {
        return Err(AuthzError::EmptyTarget);
    }

    Ok(AuthorizedTarget {
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::AssetKind;
    use chrono::Utc;
    use uuid::Uuid;

    fn asset(status: AuthStatus, value: &str) -> Asset {
        Asset {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            kind: AssetKind::Host,
            value: value.to_string(),
            auth_status: status,
            authorized_until: None,
            window_start: None,
            window_end: None,
            roe_reference: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn active_and_pending_are_authorised_by_default() {
        // No RoE, no window, no expiry needed — the operator is authorised.
        for s in [AuthStatus::Active, AuthStatus::Pending] {
            let t = authorize(&asset(s, "203.0.113.10")).expect("should authorise");
            assert_eq!(t.value, "203.0.113.10");
        }
    }

    #[test]
    fn suspended_and_revoked_are_refused() {
        for s in [AuthStatus::Suspended, AuthStatus::Revoked] {
            assert_eq!(
                authorize(&asset(s, "203.0.113.10")).unwrap_err(),
                AuthzError::Disabled(s)
            );
        }
    }

    #[test]
    fn empty_target_is_refused() {
        assert_eq!(
            authorize(&asset(AuthStatus::Active, "  ")).unwrap_err(),
            AuthzError::EmptyTarget
        );
    }
}
