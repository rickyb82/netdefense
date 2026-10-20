//! NetFlow × BGP control plane (pure cores).
//!
//! netdefense is the BRAIN: it decides, a human approves, and a proven BGP
//! speaker (GoBGP) announces. So the pieces here are pure and safety-first:
//! RPKI route-origin validation, FlowSpec rule validation with a broad-match
//! safety cap, and a mitigation state machine where an announcement is reachable
//! ONLY after explicit approval — there is no auto-announce path in the code.
//! The ClickHouse flow queries and the GoBGP gRPC announce are external seams.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

// ---- RPKI route-origin validation (RFC 6811, IPv4) ----

#[derive(Debug, Clone, Copy)]
pub struct Vrp {
    pub prefix: u32,
    pub len: u8,
    pub max_len: u8,
    pub asn: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RpkiState {
    Valid,
    Invalid,
    NotFound,
}

/// Parse an IPv4 CIDR like "203.0.113.0/24" into (network u32, prefix len).
pub fn parse_v4_cidr(s: &str) -> Option<(u32, u8)> {
    let (ip, len) = s.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    if len > 32 {
        return None;
    }
    let addr: Ipv4Addr = ip.trim().parse().ok()?;
    Some((u32::from(addr), len))
}

fn same_prefix(a: u32, b: u32, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let mask = if len >= 32 {
        u32::MAX
    } else {
        !(u32::MAX >> len)
    };
    (a & mask) == (b & mask)
}

/// Validate a route's origin against the VRP set (RFC 6811): Valid if a covering
/// VRP matches ASN and the route length ≤ maxLength; Invalid if covered but none
/// validates; NotFound if no covering VRP.
pub fn rpki_validity(route_prefix: u32, route_len: u8, origin_asn: u32, vrps: &[Vrp]) -> RpkiState {
    let mut covered = false;
    for v in vrps {
        if route_len >= v.len && same_prefix(route_prefix, v.prefix, v.len) {
            covered = true;
            if route_len <= v.max_len && origin_asn == v.asn {
                return RpkiState::Valid;
            }
        }
    }
    if covered {
        RpkiState::Invalid
    } else {
        RpkiState::NotFound
    }
}

// ---- FlowSpec rule validation ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FsAction {
    Drop,
    RateLimit { bps: u64 },
}

/// Minimum destination prefix length a Drop action may target without an
/// explicit broad-match override — stops a typo from blackholing a huge range.
const MIN_DROP_PREFIX_LEN: u8 = 24;

/// Validate a FlowSpec mitigation rule. `allow_broad` must be set explicitly to
/// drop traffic to a prefix shorter than /24.
pub fn validate_flowspec(
    dst_cidr: &str,
    action: &FsAction,
    allow_broad: bool,
) -> Result<(), String> {
    let (_, len) = parse_v4_cidr(dst_cidr)
        .ok_or_else(|| format!("destinazione `{dst_cidr}` non è un CIDR IPv4 valido"))?;
    if let FsAction::Drop = action {
        if len < MIN_DROP_PREFIX_LEN && !allow_broad {
            return Err(format!(
                "Drop su prefisso ampio /{len}: richiede conferma esplicita (allow_broad) per evitare blackhole di massa"
            ));
        }
    }
    if let FsAction::RateLimit { bps } = action {
        if *bps == 0 {
            return Err("rate limit a 0 bps equivale a un Drop: usa Drop esplicito".to_string());
        }
    }
    Ok(())
}

// ---- mitigation proposal state machine (approval-gated) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationState {
    Proposed,
    Approved,
    Announced,
    Withdrawn,
    Rejected,
}

impl MitigationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            MitigationState::Proposed => "proposed",
            MitigationState::Approved => "approved",
            MitigationState::Announced => "announced",
            MitigationState::Withdrawn => "withdrawn",
            MitigationState::Rejected => "rejected",
        }
    }
    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s {
            "proposed" => MitigationState::Proposed,
            "approved" => MitigationState::Approved,
            "announced" => MitigationState::Announced,
            "withdrawn" => MitigationState::Withdrawn,
            "rejected" => MitigationState::Rejected,
            _ => return None,
        })
    }
}

/// Allowed transitions. Crucially, Announced is reachable ONLY from Approved —
/// a proposal can never be announced without passing through human approval.
pub fn mitigation_allowed(from: MitigationState, to: MitigationState) -> bool {
    use MitigationState::*;
    matches!(
        (from, to),
        (Proposed, Approved)
            | (Proposed, Rejected)
            | (Approved, Announced)
            | (Approved, Rejected)
            | (Announced, Withdrawn)
    )
}

pub fn mitigation_advance(
    from: MitigationState,
    to: MitigationState,
) -> Result<MitigationState, String> {
    if mitigation_allowed(from, to) {
        Ok(to)
    } else {
        Err(format!(
            "transizione mitigazione {} → {} non ammessa",
            from.as_str(),
            to.as_str()
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationProposal {
    pub id: crate::domain::Id,
    pub title: String,
    pub dst_cidr: String,
    pub action: FsAction,
    pub state: MitigationState,
    pub approver: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::MitigationState::*;
    use super::*;

    fn vrp(cidr: &str, max_len: u8, asn: u32) -> Vrp {
        let (prefix, len) = parse_v4_cidr(cidr).unwrap();
        Vrp {
            prefix,
            len,
            max_len,
            asn,
        }
    }

    #[test]
    fn rpki_valid_invalid_notfound() {
        let vrps = [vrp("203.0.113.0/24", 24, 64500)];
        let (p, l) = parse_v4_cidr("203.0.113.0/24").unwrap();
        assert_eq!(rpki_validity(p, l, 64500, &vrps), RpkiState::Valid);
        // right prefix, wrong origin ASN -> Invalid (hijack signal)
        assert_eq!(rpki_validity(p, l, 65001, &vrps), RpkiState::Invalid);
        // more-specific beyond maxLength -> Invalid
        let (p2, l2) = parse_v4_cidr("203.0.113.128/25").unwrap();
        assert_eq!(rpki_validity(p2, l2, 64500, &vrps), RpkiState::Invalid);
        // uncovered prefix -> NotFound
        let (p3, l3) = parse_v4_cidr("198.51.100.0/24").unwrap();
        assert_eq!(rpki_validity(p3, l3, 64500, &vrps), RpkiState::NotFound);
    }

    #[test]
    fn flowspec_safety_cap() {
        assert!(validate_flowspec("203.0.113.5/32", &FsAction::Drop, false).is_ok());
        assert!(validate_flowspec("10.0.0.0/8", &FsAction::Drop, false).is_err()); // broad drop blocked
        assert!(validate_flowspec("10.0.0.0/8", &FsAction::Drop, true).is_ok()); // explicit override
        assert!(validate_flowspec("bad", &FsAction::Drop, true).is_err());
        assert!(
            validate_flowspec("203.0.113.0/24", &FsAction::RateLimit { bps: 0 }, false).is_err()
        );
    }

    #[test]
    fn announce_requires_approval() {
        assert!(mitigation_advance(Proposed, Approved).is_ok());
        assert!(mitigation_advance(Approved, Announced).is_ok());
        // never announce without approval
        assert!(mitigation_advance(Proposed, Announced).is_err());
        assert!(mitigation_advance(Announced, Withdrawn).is_ok());
        assert!(mitigation_advance(Rejected, Approved).is_err());
    }
}
