//! The authorisation gate: the single decision point for whether an asset may
//! be scanned. Every scan path must pass through [`authorize`] first. This is
//! what keeps a multi-client service lawful — nothing is scanned unless it is
//! an `Active`, unexpired, in-window asset backed by a signed authorisation.

use std::fmt;

use chrono::{DateTime, Utc};

use crate::domain::{Asset, AuthStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// Authorisation is not `Active` (pending, suspended or revoked).
    NotActive(AuthStatus),
    /// The authorisation expiry has passed.
    Expired(DateTime<Utc>),
    /// The current time is outside the asset's allowed daily window.
    OutsideWindow,
    /// No signed rules-of-engagement reference is recorded.
    MissingRoe,
    /// The asset's target value is empty.
    EmptyTarget,
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzError::NotActive(s) => {
                write!(f, "authorisation not active (status: {})", s.as_str())
            }
            AuthzError::Expired(t) => write!(f, "authorisation expired at {}", t.to_rfc3339()),
            AuthzError::OutsideWindow => write!(f, "outside the asset's allowed scan window"),
            AuthzError::MissingRoe => write!(f, "no signed rules-of-engagement reference recorded"),
            AuthzError::EmptyTarget => write!(f, "asset has an empty target value"),
        }
    }
}

/// A target that has cleared the authorisation gate. Carrying it (rather than a
/// bare string) means a target can only reach a scanner after `authorize`.
#[derive(Debug)]
pub struct AuthorizedTarget {
    pub value: String,
}

/// Decide whether `asset` may be scanned at `now`. Returns the vetted target or
/// the reason it is refused. Pure and deterministic — unit tested below.
pub fn authorize(asset: &Asset, now: DateTime<Utc>) -> Result<AuthorizedTarget, AuthzError> {
    if asset.auth_status != AuthStatus::Active {
        return Err(AuthzError::NotActive(asset.auth_status));
    }

    if asset
        .roe_reference
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        return Err(AuthzError::MissingRoe);
    }

    if let Some(until) = asset.authorized_until {
        if now > until {
            return Err(AuthzError::Expired(until));
        }
    }

    if let (Some(start), Some(end)) = (asset.window_start, asset.window_end) {
        let t = now.time();
        let in_window = if start <= end {
            t >= start && t <= end
        } else {
            // Window crosses midnight, e.g. 22:00–06:00.
            t >= start || t <= end
        };
        if !in_window {
            return Err(AuthzError::OutsideWindow);
        }
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
    use chrono::{NaiveTime, TimeZone};
    use uuid::Uuid;

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 15, h, m, 0).unwrap()
    }

    fn base_asset() -> Asset {
        Asset {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            kind: AssetKind::Host,
            value: "203.0.113.10".to_string(),
            auth_status: AuthStatus::Active,
            authorized_until: None,
            window_start: None,
            window_end: None,
            roe_reference: Some("RoE-2026-ACME-001".to_string()),
            created_at: at(0, 0),
        }
    }

    #[test]
    fn active_asset_with_roe_is_authorised() {
        let a = base_asset();
        let t = authorize(&a, at(12, 0)).expect("should authorise");
        assert_eq!(t.value, "203.0.113.10");
    }

    #[test]
    fn non_active_statuses_are_refused() {
        for s in [
            AuthStatus::Pending,
            AuthStatus::Suspended,
            AuthStatus::Revoked,
        ] {
            let mut a = base_asset();
            a.auth_status = s;
            assert_eq!(
                authorize(&a, at(12, 0)).unwrap_err(),
                AuthzError::NotActive(s)
            );
        }
    }

    #[test]
    fn missing_or_blank_roe_is_refused() {
        let mut a = base_asset();
        a.roe_reference = None;
        assert_eq!(
            authorize(&a, at(12, 0)).unwrap_err(),
            AuthzError::MissingRoe
        );
        a.roe_reference = Some("   ".to_string());
        assert_eq!(
            authorize(&a, at(12, 0)).unwrap_err(),
            AuthzError::MissingRoe
        );
    }

    #[test]
    fn expired_authorisation_is_refused() {
        let mut a = base_asset();
        a.authorized_until = Some(at(10, 0));
        assert!(matches!(
            authorize(&a, at(11, 0)).unwrap_err(),
            AuthzError::Expired(_)
        ));
        // Exactly at expiry is still allowed.
        assert!(authorize(&a, at(10, 0)).is_ok());
    }

    #[test]
    fn daytime_window_is_enforced() {
        let mut a = base_asset();
        a.window_start = Some(NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        a.window_end = Some(NaiveTime::from_hms_opt(17, 0, 0).unwrap());
        assert!(authorize(&a, at(12, 0)).is_ok());
        assert_eq!(
            authorize(&a, at(8, 0)).unwrap_err(),
            AuthzError::OutsideWindow
        );
        assert_eq!(
            authorize(&a, at(18, 0)).unwrap_err(),
            AuthzError::OutsideWindow
        );
    }

    #[test]
    fn overnight_window_is_enforced() {
        let mut a = base_asset();
        a.window_start = Some(NaiveTime::from_hms_opt(22, 0, 0).unwrap());
        a.window_end = Some(NaiveTime::from_hms_opt(6, 0, 0).unwrap());
        assert!(authorize(&a, at(23, 0)).is_ok());
        assert!(authorize(&a, at(3, 0)).is_ok());
        assert_eq!(
            authorize(&a, at(12, 0)).unwrap_err(),
            AuthzError::OutsideWindow
        );
    }

    #[test]
    fn empty_target_is_refused() {
        let mut a = base_asset();
        a.value = "  ".to_string();
        assert_eq!(
            authorize(&a, at(12, 0)).unwrap_err(),
            AuthzError::EmptyTarget
        );
    }
}
