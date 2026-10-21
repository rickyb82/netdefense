//! Live SNMPv2c inventory collector — the piece that actually reads from the
//! devices. Dependency-free: the SNMP/BER codec is pure and unit-tested, the
//! UDP transport uses tokio (already a dependency), and the poll orchestration
//! is tested offline with a fake transport.
//!
//! v1 scope: GET sysDescr.0 / sysObjectID.0 per Host asset → `snmp::classify`
//! → `device_facts` → `fleet::run_correlation`, so versions (and thus CVE
//! matches) are discovered automatically across the whole multi-vendor fleet.
//! The interface WALK for the NMS builds on the same codec next.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::store::Store;

const OID_SYSDESCR: &str = "1.3.6.1.2.1.1.1.0";
const OID_SYSOBJECTID: &str = "1.3.6.1.2.1.1.2.0";

// ---- SNMP value ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpValue {
    OctetString(String),
    Oid(String),
    Int(i64),
    Other,
}

// ---- pure BER encoding ----

fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.push((v & 0xff) as u8);
            v >>= 8;
        }
        b.reverse();
        let mut out = vec![0x80 | b.len() as u8];
        out.extend(b);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn enc_int(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut i = 0usize;
    // strip leading 0x00 bytes while the sign bit of the next byte stays clear
    while i < 7 && b[i] == 0 && (b[i + 1] & 0x80) == 0 {
        i += 1;
    }
    tlv(0x02, &b[i..])
}

fn base128(mut v: u64) -> Vec<u8> {
    let mut tmp = vec![(v & 0x7f) as u8];
    v >>= 7;
    while v > 0 {
        tmp.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    tmp.reverse();
    tmp
}

fn enc_oid(oid: &str) -> Result<Vec<u8>> {
    let arcs: Vec<u64> = oid
        .split('.')
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| anyhow!("bad oid arc in {oid}"))
        })
        .collect::<Result<_>>()?;
    if arcs.len() < 2 {
        return Err(anyhow!("oid too short: {oid}"));
    }
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        body.extend(base128(a));
    }
    Ok(tlv(0x06, &body))
}

/// Build an SNMPv2c GetRequest for the given OIDs.
pub fn build_get(request_id: u32, community: &str, oids: &[&str]) -> Result<Vec<u8>> {
    let mut vbs = Vec::new();
    for oid in oids {
        let mut vb = enc_oid(oid)?;
        vb.extend(tlv(0x05, &[])); // value = NULL
        vbs.extend(tlv(0x30, &vb));
    }
    let vblist = tlv(0x30, &vbs);

    let mut pdu = enc_int(request_id as i64);
    pdu.extend(enc_int(0)); // error-status
    pdu.extend(enc_int(0)); // error-index
    pdu.extend(vblist);
    let pdu = tlv(0xA0, &pdu); // GetRequest

    let mut msg = enc_int(1); // version 1 == SNMPv2c
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(pdu);
    Ok(tlv(0x30, &msg))
}

// ---- pure BER decoding ----

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.p + 2 > self.b.len() {
            return Err(anyhow!("truncated TLV"));
        }
        let tag = self.b[self.p];
        self.p += 1;
        let first = self.b[self.p];
        self.p += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let nbytes = (first & 0x7f) as usize;
            if nbytes == 0 || nbytes > 4 || self.p + nbytes > self.b.len() {
                return Err(anyhow!("bad length"));
            }
            let mut l = 0usize;
            for _ in 0..nbytes {
                l = (l << 8) | self.b[self.p] as usize;
                self.p += 1;
            }
            l
        };
        if self.p + len > self.b.len() {
            return Err(anyhow!("content past end"));
        }
        let content = &self.b[self.p..self.p + len];
        self.p += len;
        Ok((tag, content))
    }
}

fn decode_oid(b: &[u8]) -> Option<String> {
    if b.is_empty() {
        return None;
    }
    let mut out = format!("{}.{}", b[0] / 40, b[0] % 40);
    let mut v: u64 = 0;
    for &byte in &b[1..] {
        v = (v << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&v.to_string());
            v = 0;
        }
    }
    Some(out)
}

fn decode_value(tag: u8, content: &[u8]) -> SnmpValue {
    match tag {
        0x04 => SnmpValue::OctetString(String::from_utf8_lossy(content).into_owned()),
        0x06 => decode_oid(content)
            .map(SnmpValue::Oid)
            .unwrap_or(SnmpValue::Other),
        0x02 => {
            let mut v: i64 = 0;
            for &byte in content {
                v = (v << 8) | byte as i64;
            }
            SnmpValue::Int(v)
        }
        _ => SnmpValue::Other,
    }
}

/// Parse an SNMPv2c GetResponse into (oid, value) pairs.
pub fn parse_response(bytes: &[u8]) -> Result<Vec<(String, SnmpValue)>> {
    let (tag, msg) = Reader::new(bytes).read_tlv()?;
    if tag != 0x30 {
        return Err(anyhow!("not a SEQUENCE"));
    }
    let mut r = Reader::new(msg);
    r.read_tlv()?; // version
    r.read_tlv()?; // community
    let (_pdu_tag, pdu) = r.read_tlv()?; // response PDU
    let mut pr = Reader::new(pdu);
    pr.read_tlv()?; // request-id
    pr.read_tlv()?; // error-status
    pr.read_tlv()?; // error-index
    let (_, vblist) = pr.read_tlv()?; // varbind list SEQUENCE
    let mut vr = Reader::new(vblist);
    let mut out = Vec::new();
    while vr.p < vblist.len() {
        let (_, vb) = vr.read_tlv()?;
        let mut one = Reader::new(vb);
        let (_, oid_bytes) = one.read_tlv()?;
        let (vtag, vval) = one.read_tlv()?;
        if let Some(oid) = decode_oid(oid_bytes) {
            out.push((oid, decode_value(vtag, vval)));
        }
    }
    Ok(out)
}

// ---- transport seam ----

#[allow(async_fn_in_trait)]
pub trait SnmpTransport {
    async fn get(
        &self,
        host: &str,
        community: &str,
        oids: &[&str],
    ) -> Result<Vec<(String, SnmpValue)>>;
}

pub struct UdpTransport {
    pub timeout_secs: u64,
    counter: AtomicU32,
}

impl UdpTransport {
    pub fn new(timeout_secs: u64) -> Self {
        UdpTransport {
            timeout_secs,
            counter: AtomicU32::new(1),
        }
    }
}

impl SnmpTransport for UdpTransport {
    async fn get(
        &self,
        host: &str,
        community: &str,
        oids: &[&str],
    ) -> Result<Vec<(String, SnmpValue)>> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let req = build_get(id, community, oids)?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect((host, 161)).await?;
        sock.send(&req).await?;
        let mut buf = vec![0u8; 8192];
        let n = timeout(Duration::from_secs(self.timeout_secs), sock.recv(&mut buf)).await??;
        parse_response(&buf[..n])
    }
}

// ---- config + poller ----

pub struct SnmpConfig {
    pub enabled: bool,
    pub community: String,
    pub poll_secs: u64,
    pub timeout_secs: u64,
}

impl SnmpConfig {
    pub fn from_env() -> Self {
        SnmpConfig {
            enabled: std::env::var("NETDEFENSE_SNMP_ENABLE")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            community: std::env::var("NETDEFENSE_SNMP_COMMUNITY")
                .unwrap_or_else(|_| "public".to_string()),
            poll_secs: std::env::var("NETDEFENSE_SNMP_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(3600),
            timeout_secs: std::env::var("NETDEFENSE_SNMP_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(3),
        }
    }
}

#[derive(Debug, Default)]
pub struct PollSummary {
    pub polled: usize,
    pub classified: usize,
    pub alerts_raised: usize,
}

fn value_str(pairs: &[(String, SnmpValue)], oid: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(o, _)| o == oid)
        .and_then(|(_, v)| match v {
            SnmpValue::OctetString(s) => Some(s.clone()),
            SnmpValue::Oid(s) => Some(s.clone()),
            _ => None,
        })
}

/// Poll every Host asset once: read sysDescr/sysObjectID, classify into facts,
/// then correlate. Unreachable or unrecognised devices are skipped (logged).
pub async fn poll_once<T: SnmpTransport>(
    store: &Store,
    cfg: &SnmpConfig,
    transport: &T,
) -> Result<PollSummary> {
    let mut s = PollSummary::default();
    let assets = store.list_all_assets()?;
    for a in assets
        .into_iter()
        .filter(|a| a.kind == crate::domain::AssetKind::Host)
    {
        s.polled += 1;
        let pairs = match transport
            .get(&a.value, &cfg.community, &[OID_SYSDESCR, OID_SYSOBJECTID])
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("netdefense snmp: {} unreachable: {e}", a.value);
                continue;
            }
        };
        let Some(sysdescr) = value_str(&pairs, OID_SYSDESCR) else {
            continue;
        };
        let sysobjid = value_str(&pairs, OID_SYSOBJECTID);
        if let Some(id) = crate::snmp::classify(&sysdescr, sysobjid.as_deref()) {
            store.upsert_device_facts(&crate::snmp::facts(a.id, &id))?;
            s.classified += 1;
        }
    }
    s.alerts_raised = crate::fleet::run_correlation(store)?;
    Ok(s)
}

pub fn spawn(store: Store, cfg: SnmpConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let transport = UdpTransport::new(cfg.timeout_secs);
        let mut ticker = tokio::time::interval(Duration::from_secs(cfg.poll_secs));
        loop {
            ticker.tick().await;
            match poll_once(&store, &cfg, &transport).await {
                Ok(s) => eprintln!(
                    "netdefense snmp: polled {}, classified {}, alerts {}",
                    s.polled, s.classified, s.alerts_raised
                ),
                Err(e) => eprintln!("netdefense snmp: cycle error: {e}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use chrono::Utc;
    use uuid::Uuid;

    /// Build a GetResponse the way a device would, to test the decoder.
    fn build_response(request_id: u32, community: &str, varbinds: &[(&str, SnmpValue)]) -> Vec<u8> {
        let mut vbs = Vec::new();
        for (oid, val) in varbinds {
            let mut vb = enc_oid(oid).unwrap();
            vb.extend(match val {
                SnmpValue::OctetString(s) => tlv(0x04, s.as_bytes()),
                SnmpValue::Oid(s) => enc_oid(s).unwrap(),
                SnmpValue::Int(i) => enc_int(*i),
                SnmpValue::Other => tlv(0x05, &[]),
            });
            vbs.extend(tlv(0x30, &vb));
        }
        let vblist = tlv(0x30, &vbs);
        let mut pdu = enc_int(request_id as i64);
        pdu.extend(enc_int(0));
        pdu.extend(enc_int(0));
        pdu.extend(vblist);
        let pdu = tlv(0xA2, &pdu); // GetResponse
        let mut msg = enc_int(1);
        msg.extend(tlv(0x04, community.as_bytes()));
        msg.extend(pdu);
        tlv(0x30, &msg)
    }

    #[test]
    fn get_request_is_wellformed_ber() {
        let req = build_get(42, "public", &[OID_SYSDESCR]).unwrap();
        assert_eq!(req[0], 0x30); // top SEQUENCE
                                  // decodes back without error and round-trips the oid
                                  // (parse_response accepts GetRequest too since structure matches)
        let parsed = parse_response(&req).unwrap();
        assert_eq!(parsed[0].0, OID_SYSDESCR);
    }

    #[test]
    fn decodes_sysdescr_and_oid() {
        let resp = build_response(
            7,
            "public",
            &[
                (
                    OID_SYSDESCR,
                    SnmpValue::OctetString("RouterOS CCR1009, RouterOS 7.19".into()),
                ),
                (
                    OID_SYSOBJECTID,
                    SnmpValue::Oid("1.3.6.1.4.1.14988.1.1.7.3".into()),
                ),
            ],
        );
        let pairs = parse_response(&resp).unwrap();
        assert_eq!(
            value_str(&pairs, OID_SYSDESCR).as_deref(),
            Some("RouterOS CCR1009, RouterOS 7.19")
        );
        assert_eq!(
            value_str(&pairs, OID_SYSOBJECTID).as_deref(),
            Some("1.3.6.1.4.1.14988.1.1.7.3")
        );
    }

    // Fake transport returns a canned RouterOS sysDescr for any host.
    struct FakeSnmp;
    impl SnmpTransport for FakeSnmp {
        async fn get(
            &self,
            _host: &str,
            _community: &str,
            _oids: &[&str],
        ) -> Result<Vec<(String, SnmpValue)>> {
            Ok(vec![
                (
                    OID_SYSDESCR.to_string(),
                    SnmpValue::OctetString("RouterOS 6.49.7".into()),
                ),
                (
                    OID_SYSOBJECTID.to_string(),
                    SnmpValue::Oid("1.3.6.1.4.1.14988.1.1.7.3".into()),
                ),
            ])
        }
    }

    #[tokio::test]
    async fn poll_reads_classifies_and_correlates_offline() {
        let store = Store::open(":memory:").unwrap();
        store.migrate().unwrap();
        let cid = Uuid::new_v4();
        store
            .insert_client(&Client {
                id: cid,
                name: "C".into(),
                contact_email: "c@e".into(),
                created_at: Utc::now(),
            })
            .unwrap();
        let aid = Uuid::new_v4();
        store
            .insert_asset(&Asset {
                id: aid,
                client_id: cid,
                kind: AssetKind::Host,
                value: "10.0.0.1".into(),
                auth_status: AuthStatus::Active,
                authorized_until: None,
                window_start: None,
                window_end: None,
                roe_reference: Some("RoE".into()),
                created_at: Utc::now(),
            })
            .unwrap();
        // a RouterOS CVE that affects < 6.49.8
        store
            .insert_cve(&crate::cve::Cve {
                id: "CVE-2023-41570".into(),
                published: "2023-10-01".into(),
                severity: Severity::High,
                summary: "x".into(),
                product: "routeros".into(),
                version_start_incl: None,
                version_end_excl: Some("6.49.8".into()),
            })
            .unwrap();

        let cfg = SnmpConfig {
            enabled: true,
            community: "public".into(),
            poll_secs: 3600,
            timeout_secs: 3,
        };
        let s = poll_once(&store, &cfg, &FakeSnmp).await.unwrap();
        assert_eq!(s.classified, 1);
        // version 6.49.7 was discovered from the device and matched the CVE
        let facts = store.list_device_facts().unwrap();
        assert_eq!(facts[0].version.as_deref(), Some("6.49.7"));
        assert!(s.alerts_raised >= 1);
    }
}
