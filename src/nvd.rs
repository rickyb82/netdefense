//! Incremental NVD 2.0 poller. On a schedule, for each fleet product it pulls
//! CVEs modified since the last run from the NVD REST API, feeds each page to
//! the existing `cve::parse_nvd`, stores them, and runs `fleet::run_correlation`
//! so newly disclosed vulnerabilities alert automatically — no manual import.
//!
//! All windowing/paging/query policy is pure and unit-tested; only `Fetcher`
//! touches the network, so the poll loop is tested offline with canned pages.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::store::Store;

const SOURCE: &str = "nvd";
const MAX_WINDOW_DAYS: i64 = 120; // NVD caps lastMod ranges at 120 days
const MAX_PAGES: usize = 50; // safety cap per window
const OVERLAP_MINUTES: i64 = 2; // re-pull a small overlap; inserts are idempotent

pub struct NvdConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: Option<String>,
    pub poll_secs: u64,
    pub initial_lookback_days: i64,
    pub request_delay_secs: u64,
    pub results_per_page: i64,
}

impl NvdConfig {
    pub fn from_env() -> Self {
        let has_key = std::env::var("NETDEFENSE_NVD_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        NvdConfig {
            enabled: std::env::var("NETDEFENSE_NVD_ENABLE")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            base_url: std::env::var("NETDEFENSE_NVD_URL")
                .unwrap_or_else(|_| "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string()),
            api_key: has_key.clone(),
            poll_secs: env_u64("NETDEFENSE_NVD_POLL_SECS", 3600),
            initial_lookback_days: env_u64("NETDEFENSE_NVD_LOOKBACK_DAYS", 30) as i64,
            // NVD rate limits are far tighter without a key.
            request_delay_secs: env_u64(
                "NETDEFENSE_NVD_DELAY_SECS",
                if has_key.is_some() { 1 } else { 6 },
            ),
            results_per_page: env_u64("NETDEFENSE_NVD_PAGE_SIZE", 2000) as i64,
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

// ---- pure logic ----

/// NVD's required extended ISO-8601 with milliseconds and literal Z (UTC).
pub fn format_nvd_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Split the sync range into NVD-legal windows (≤120 days). From the cursor
/// minus a small overlap (or `now - initial_lookback` on first run) up to now.
pub fn plan_sync_windows(
    cursor: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    initial_lookback_days: i64,
    max_window_days: i64,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let start = match cursor {
        Some(c) => c - chrono::Duration::minutes(OVERLAP_MINUTES),
        None => now - chrono::Duration::days(initial_lookback_days.max(0)),
    };
    if start >= now {
        return vec![];
    }
    let step = chrono::Duration::days(max_window_days.max(1));
    let mut out = Vec::new();
    let mut s = start;
    let mut guard = 0;
    while s < now && guard < 64 {
        let e = (s + step).min(now);
        out.push((s, e));
        s = e;
        guard += 1;
    }
    out
}

/// NVD query params for one page.
pub fn build_cve_query(
    token: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    start_index: i64,
    results_per_page: i64,
) -> Vec<(String, String)> {
    vec![
        ("keywordSearch".into(), token.into()),
        ("lastModStartDate".into(), format_nvd_timestamp(start)),
        ("lastModEndDate".into(), format_nvd_timestamp(end)),
        ("resultsPerPage".into(), results_per_page.to_string()),
        ("startIndex".into(), start_index.to_string()),
    ]
}

#[derive(Debug, PartialEq, Eq)]
pub struct Page {
    pub total_results: i64,
    pub results_per_page: i64,
    pub start_index: i64,
}

pub fn parse_nvd_envelope(body: &str) -> Result<Page> {
    let v: Value = serde_json::from_str(body)?;
    Ok(Page {
        total_results: v["totalResults"].as_i64().unwrap_or(0),
        results_per_page: v["resultsPerPage"].as_i64().unwrap_or(0),
        start_index: v["startIndex"].as_i64().unwrap_or(0),
    })
}

/// Next `startIndex`, or `None` when the page set is exhausted or the page cap
/// is hit.
pub fn next_start_index(
    start_index: i64,
    per_page: i64,
    total: i64,
    pages_done: usize,
    max_pages: usize,
) -> Option<i64> {
    let next = start_index.saturating_add(per_page.max(1));
    if next >= total || pages_done >= max_pages {
        None
    } else {
        Some(next)
    }
}

// ---- network seam ----

#[allow(async_fn_in_trait)]
pub trait Fetcher {
    async fn get(
        &self,
        base_url: &str,
        params: &[(String, String)],
        api_key: Option<&str>,
    ) -> Result<String>;
}

pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client })
    }
}

impl Fetcher for ReqwestFetcher {
    async fn get(
        &self,
        base_url: &str,
        params: &[(String, String)],
        api_key: Option<&str>,
    ) -> Result<String> {
        let mut req = self.client.get(base_url).query(params);
        if let Some(k) = api_key {
            req = req.header("apiKey", k);
        }
        Ok(req.send().await?.error_for_status()?.text().await?)
    }
}

#[derive(Debug, Default)]
pub struct PollSummary {
    pub imported: usize,
    pub alerts_raised: usize,
}

async fn poll_product<F: Fetcher>(
    store: &Store,
    cfg: &NvdConfig,
    fetcher: &F,
    token: &str,
    now: DateTime<Utc>,
) -> Result<usize> {
    let cursor = store.get_sync_cursor(SOURCE, token)?;
    let mut imported = 0usize;
    for (ws, we) in plan_sync_windows(cursor, now, cfg.initial_lookback_days, MAX_WINDOW_DAYS) {
        let mut start_index = 0i64;
        let mut pages = 0usize;
        loop {
            let params = build_cve_query(token, ws, we, start_index, cfg.results_per_page);
            let body = fetcher
                .get(&cfg.base_url, &params, cfg.api_key.as_deref())
                .await?;
            let page = parse_nvd_envelope(&body)?;
            for c in crate::cve::parse_nvd(&body, token) {
                store.insert_cve(&c)?;
                imported += 1;
            }
            pages += 1;
            match next_start_index(
                start_index,
                cfg.results_per_page,
                page.total_results,
                pages,
                MAX_PAGES,
            ) {
                Some(n) => {
                    start_index = n;
                    tokio::time::sleep(Duration::from_secs(cfg.request_delay_secs)).await;
                }
                None => break,
            }
        }
    }
    // High-water only advances on success, so a failure re-pulls next cycle.
    store.set_sync_cursor(SOURCE, token, Some(now), now, "ok")?;
    Ok(imported)
}

/// One full poll across every fleet product, then correlate.
pub async fn poll_once<F: Fetcher>(
    store: &Store,
    cfg: &NvdConfig,
    fetcher: &F,
) -> Result<PollSummary> {
    let now = Utc::now();
    let mut imported = 0usize;
    for p in crate::fleet::catalog() {
        match poll_product(store, cfg, fetcher, p.cpe_token, now).await {
            Ok(n) => imported += n,
            Err(e) => eprintln!("netdefense nvd: product {} failed: {e}", p.key),
        }
        tokio::time::sleep(Duration::from_secs(cfg.request_delay_secs)).await;
    }
    let alerts_raised = crate::fleet::run_correlation(store)?;
    Ok(PollSummary {
        imported,
        alerts_raised,
    })
}

pub fn spawn(store: Store, cfg: NvdConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let fetcher = match ReqwestFetcher::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("netdefense nvd: cannot build HTTP client: {e}");
                return;
            }
        };
        let mut ticker = tokio::time::interval(Duration::from_secs(cfg.poll_secs));
        loop {
            ticker.tick().await;
            match poll_once(&store, &cfg, &fetcher).await {
                Ok(s) => eprintln!(
                    "netdefense nvd: imported {}, alerts {}",
                    s.imported, s.alerts_raised
                ),
                Err(e) => eprintln!("netdefense nvd: cycle error: {e}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use chrono::TimeZone;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn timestamp_is_nvd_format() {
        let s = format_nvd_timestamp(Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap());
        assert_eq!(s, "2026-01-02T03:04:05.000Z");
    }

    #[test]
    fn first_run_uses_lookback_then_splits_120d() {
        let now = at(2026, 1, 1);
        let w = plan_sync_windows(None, now, 30, 120);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].1, now);
        // A long gap splits into ≤120-day windows.
        let w2 = plan_sync_windows(Some(at(2025, 1, 1)), now, 30, 120);
        assert!(w2.len() >= 3);
        assert!(w2
            .iter()
            .all(|(s, e)| *e - *s <= chrono::Duration::days(120)));
    }

    #[test]
    fn no_window_when_cursor_is_in_the_future() {
        let now = at(2026, 1, 1);
        // A cursor ahead of now (nothing newer to pull) yields no windows.
        assert!(plan_sync_windows(Some(now + chrono::Duration::days(1)), now, 30, 120).is_empty());
        // A cursor at now still re-pulls only the small overlap window.
        let w = plan_sync_windows(Some(now), now, 30, 120);
        assert_eq!(w.len(), 1);
        assert!(w[0].1 - w[0].0 <= chrono::Duration::minutes(OVERLAP_MINUTES));
    }

    #[test]
    fn paging_stops_at_total_and_cap() {
        assert_eq!(next_start_index(0, 2000, 3000, 1, 50), Some(2000));
        assert_eq!(next_start_index(2000, 2000, 3000, 2, 50), None); // 4000 >= 3000
        assert_eq!(next_start_index(0, 2000, 999999, 50, 50), None); // page cap
    }

    #[test]
    fn envelope_parses_totals() {
        let p = parse_nvd_envelope(r#"{"totalResults":3,"resultsPerPage":2000,"startIndex":0}"#)
            .unwrap();
        assert_eq!(
            p,
            Page {
                total_results: 3,
                results_per_page: 2000,
                start_index: 0
            }
        );
    }

    // Offline end-to-end: a canned NVD page flows through parse -> store -> correlation.
    struct CannedFetcher {
        pages: Vec<String>,
        idx: Mutex<usize>,
    }
    impl Fetcher for CannedFetcher {
        async fn get(&self, _u: &str, _p: &[(String, String)], _k: Option<&str>) -> Result<String> {
            let mut i = self.idx.lock().map_err(|_| anyhow::anyhow!("poison"))?;
            let body = self.pages.get(*i).cloned().unwrap_or_else(|| "{}".into());
            *i += 1;
            Ok(body)
        }
    }

    #[tokio::test]
    async fn poll_once_imports_and_correlates_offline() {
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
                value: "203.0.113.1".into(),
                auth_status: AuthStatus::Active,
                authorized_until: None,
                window_start: None,
                window_end: None,
                roe_reference: Some("RoE".into()),
                created_at: Utc::now(),
            })
            .unwrap();
        store
            .upsert_device_facts(&crate::fleet::DeviceFacts {
                asset_id: aid,
                vendor: "MikroTik".into(),
                product: "routeros".into(),
                version: Some("6.49.7".into()),
                mgmt: vec![],
            })
            .unwrap();

        let page = r#"{"totalResults":1,"resultsPerPage":2000,"startIndex":0,"vulnerabilities":[
            {"cve":{"id":"CVE-2023-41570","published":"2023-10-01T00:00Z",
              "descriptions":[{"lang":"en","value":"RouterOS issue"}],
              "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},
              "configurations":[{"nodes":[{"cpeMatch":[
                {"criteria":"cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*","versionEndExcluding":"6.49.8"}
              ]}]}]}}]}"#;
        // Every product queries once; the routeros page matches, others return empty.
        let fetcher = CannedFetcher {
            pages: vec![page.to_string(); 32],
            idx: Mutex::new(0),
        };
        let mut cfg = NvdConfig::from_env();
        cfg.request_delay_secs = 0;
        cfg.initial_lookback_days = 10;

        let summary = poll_once(&store, &cfg, &fetcher).await.unwrap();
        assert!(summary.imported >= 1);
        assert!(summary.alerts_raised >= 1);
        assert_eq!(store.list_alerts_for_asset(aid).unwrap().len(), 1);
        // Cursor advanced for routeros.
        assert!(store.get_sync_cursor("nvd", "routeros").unwrap().is_some());
    }
}
