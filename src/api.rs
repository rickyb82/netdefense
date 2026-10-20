//! HTTP API (axum). CRUD for clients and assets, the authorisation action, and
//! scan triggering. Authorisation is enforced inside `scan::run_scan`, so a
//! refused scan comes back as HTTP 403 with the reason.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::domain::*;
use crate::scan::{self};
use crate::store::Store;

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/clients", post(create_client).get(list_clients))
        .route("/clients/:id/assets", post(add_asset).get(list_assets))
        .route("/assets/:id", get(get_asset))
        .route("/assets/:id/authorize", post(authorize_asset))
        .route("/assets/:id/scan", post(trigger_scan))
        .route("/assets/:id/findings", get(asset_findings))
        .route(
            "/assets/:id/schedules",
            post(add_schedule).get(list_schedules),
        )
        .route("/assets/:id/alerts", get(asset_alerts))
        .route("/schedules/:id/enabled", post(set_schedule_enabled))
        .route("/scans/:id", get(get_scan))
        .route("/alerts", get(list_alerts))
        .route("/cve", post(ingest_cve).get(list_cve))
        .route("/cve/import-nvd", post(import_nvd))
        .route("/cve/correlate", post(correlate_cve))
        .route("/assets/:id/facts", post(set_facts))
        .route("/assets/:id/snmp-classify", post(snmp_classify))
        .route("/fleet/catalog", get(fleet_catalog))
        .route("/voip/options-template", get(voip_template))
        .route("/assets/:id/voip-analyze", post(voip_analyze))
        .route("/assets/:id/candidates", post(create_candidate))
        .route("/candidates", get(list_candidates))
        .route("/candidates/:id/advance", post(advance_candidate))
        .route("/clients/:id/import-prtg", post(import_prtg))
        .route("/nms/interface-eval", post(nms_eval))
        .route("/assets/:id/web-baseline", post(web_baseline))
        .route("/rpki/check", post(rpki_check))
        .route(
            "/mitigations",
            post(propose_mitigation).get(list_mitigations),
        )
        .route("/mitigations/:id/approve", post(approve_mitigation))
        .route("/mitigations/:id/reject", post(reject_mitigation))
        .route("/mitigations/:id/announce", post(announce_mitigation))
        .with_state(store)
}

/// Wraps `anyhow::Error` as an HTTP 500 with a JSON body.
pub struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

type ApiResult = Result<Response, ApiError>;

// ---- clients ----

#[derive(Deserialize)]
struct NewClient {
    name: String,
    contact_email: String,
}

async fn create_client(State(store): State<Store>, Json(body): Json<NewClient>) -> ApiResult {
    let client = Client {
        id: Uuid::new_v4(),
        name: body.name,
        contact_email: body.contact_email,
        created_at: Utc::now(),
    };
    store.insert_client(&client)?;
    Ok((StatusCode::CREATED, Json(client)).into_response())
}

async fn list_clients(State(store): State<Store>) -> ApiResult {
    Ok(Json(store.list_clients()?).into_response())
}

// ---- assets ----

#[derive(Deserialize)]
struct NewAsset {
    kind: AssetKind,
    value: String,
}

async fn add_asset(
    State(store): State<Store>,
    Path(client_id): Path<Uuid>,
    Json(body): Json<NewAsset>,
) -> ApiResult {
    if store.get_client(client_id)?.is_none() {
        return Ok(not_found("client"));
    }
    // New assets start Pending: they cannot be scanned until explicitly
    // authorised via /assets/:id/authorize.
    let asset = Asset {
        id: Uuid::new_v4(),
        client_id,
        kind: body.kind,
        value: body.value,
        auth_status: AuthStatus::Pending,
        authorized_until: None,
        window_start: None,
        window_end: None,
        roe_reference: None,
        created_at: Utc::now(),
    };
    store.insert_asset(&asset)?;
    Ok((StatusCode::CREATED, Json(asset)).into_response())
}

async fn list_assets(State(store): State<Store>, Path(client_id): Path<Uuid>) -> ApiResult {
    Ok(Json(store.list_assets(client_id)?).into_response())
}

async fn get_asset(State(store): State<Store>, Path(id): Path<Uuid>) -> ApiResult {
    match store.get_asset(id)? {
        Some(a) => Ok(Json(a).into_response()),
        None => Ok(not_found("asset")),
    }
}

#[derive(Deserialize)]
struct AuthorizeBody {
    /// Target status; typically `active` to authorise, or `suspended`/`revoked`.
    status: AuthStatus,
    /// Reference to the signed rules-of-engagement / contract. Required to go
    /// `active` (the authorisation gate refuses an active asset without one).
    roe_reference: Option<String>,
    authorized_until: Option<DateTime<Utc>>,
    /// Daily allowed window in UTC, "HH:MM:SS".
    window_start: Option<String>,
    window_end: Option<String>,
}

async fn authorize_asset(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
    Json(body): Json<AuthorizeBody>,
) -> ApiResult {
    if store.get_asset(id)?.is_none() {
        return Ok(not_found("asset"));
    }
    let window_start = parse_time_opt(body.window_start.as_deref())?;
    let window_end = parse_time_opt(body.window_end.as_deref())?;

    store.update_asset_authorization(
        id,
        body.status,
        body.authorized_until,
        window_start,
        window_end,
        body.roe_reference,
    )?;
    Ok(Json(store.get_asset(id)?).into_response())
}

async fn asset_findings(State(store): State<Store>, Path(id): Path<Uuid>) -> ApiResult {
    Ok(Json(store.list_findings_for_asset(id)?).into_response())
}

// ---- scans ----

#[derive(Deserialize)]
struct ScanRequest {
    kind: ScanKind,
}

async fn trigger_scan(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
    Json(body): Json<ScanRequest>,
) -> ApiResult {
    if store.get_asset(id)?.is_none() {
        return Ok(not_found("asset"));
    }
    let outcome = scan::run_scan(&store, id, body.kind).await?;
    // A gate refusal is a legitimate, recorded outcome — surface it as 403.
    let code = match outcome.scan.status {
        ScanStatus::Refused => StatusCode::FORBIDDEN,
        ScanStatus::Failed => StatusCode::BAD_GATEWAY,
        _ => StatusCode::OK,
    };
    Ok((code, Json(outcome)).into_response())
}

async fn get_scan(State(store): State<Store>, Path(id): Path<Uuid>) -> ApiResult {
    match store.get_scan(id)? {
        Some(s) => {
            let findings = store.list_findings_for_scan(id)?;
            Ok(Json(json!({ "scan": s, "findings": findings })).into_response())
        }
        None => Ok(not_found("scan")),
    }
}

// ---- schedules ----

#[derive(Deserialize)]
struct NewSchedule {
    kind: ScanKind,
    interval_secs: i64,
    /// If false, the schedule is created paused. Defaults to true.
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn add_schedule(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(body): Json<NewSchedule>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    if body.interval_secs < 1 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "interval_secs must be >= 1" })),
        )
            .into_response());
    }
    // First run is due immediately on the next scheduler tick.
    let schedule = Schedule {
        id: Uuid::new_v4(),
        asset_id,
        kind: body.kind,
        interval_secs: body.interval_secs,
        next_run_at: Utc::now() - Duration::seconds(1),
        enabled: body.enabled,
    };
    store.insert_schedule(&schedule)?;
    Ok((StatusCode::CREATED, Json(schedule)).into_response())
}

async fn list_schedules(State(store): State<Store>, Path(asset_id): Path<Uuid>) -> ApiResult {
    Ok(Json(store.list_schedules_for_asset(asset_id)?).into_response())
}

#[derive(Deserialize)]
struct EnabledBody {
    enabled: bool,
}

async fn set_schedule_enabled(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
    Json(body): Json<EnabledBody>,
) -> ApiResult {
    store.set_schedule_enabled(id, body.enabled)?;
    Ok(Json(json!({ "id": id, "enabled": body.enabled })).into_response())
}

// ---- alerts ----

async fn list_alerts(State(store): State<Store>) -> ApiResult {
    Ok(Json(store.list_alerts()?).into_response())
}

async fn asset_alerts(State(store): State<Store>, Path(asset_id): Path<Uuid>) -> ApiResult {
    Ok(Json(store.list_alerts_for_asset(asset_id)?).into_response())
}

// ---- cve / fleet ----

async fn ingest_cve(State(store): State<Store>, Json(cve): Json<crate::cve::Cve>) -> ApiResult {
    store.insert_cve(&cve)?;
    // Correlate immediately so a freshly published CVE alerts the moment it lands.
    let raised = crate::fleet::run_correlation(&store)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "stored": cve.id, "alerts_raised": raised })),
    )
        .into_response())
}

async fn list_cve(State(store): State<Store>) -> ApiResult {
    Ok(Json(store.list_cves()?).into_response())
}

async fn correlate_cve(State(store): State<Store>) -> ApiResult {
    let raised = crate::fleet::run_correlation(&store)?;
    Ok(Json(json!({ "alerts_raised": raised })).into_response())
}

#[derive(Deserialize)]
struct NvdQuery {
    /// Product CPE token to match in the feed, e.g. `routeros`, `3cx`, `junos`.
    product: String,
}

/// Ingest a raw NVD 2.0 JSON feed (body) and store every CVE matching the
/// `product` token, then correlate. Lets you pipe NVD / vendor feeds in.
async fn import_nvd(
    State(store): State<Store>,
    Query(q): Query<NvdQuery>,
    body: String,
) -> ApiResult {
    let cves = crate::cve::parse_nvd(&body, &q.product);
    let n = cves.len();
    for c in &cves {
        store.insert_cve(c)?;
    }
    let raised = crate::fleet::run_correlation(&store)?;
    Ok(
        Json(json!({ "imported": n, "product": q.product, "alerts_raised": raised }))
            .into_response(),
    )
}

#[derive(Deserialize)]
struct SnmpClassifyBody {
    sysdescr: String,
    sys_object_id: Option<String>,
}

/// Classify a device from its SNMP sysDescr/sysObjectID, store the resulting
/// vendor/product/version as device facts, and correlate against known CVEs.
async fn snmp_classify(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(b): Json<SnmpClassifyBody>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    match crate::snmp::classify(&b.sysdescr, b.sys_object_id.as_deref()) {
        Some(id) => {
            let facts = crate::snmp::facts(asset_id, &id);
            store.upsert_device_facts(&facts)?;
            let raised = crate::fleet::run_correlation(&store)?;
            Ok(
                Json(json!({ "identity": id, "facts": facts, "alerts_raised": raised }))
                    .into_response(),
            )
        }
        None => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "sysDescr not recognised", "sysdescr": b.sysdescr })),
        )
            .into_response()),
    }
}

async fn fleet_catalog(State(_store): State<Store>) -> ApiResult {
    let items: Vec<_> = crate::fleet::catalog()
        .iter()
        .map(|p| json!({ "key": p.key, "vendor": p.vendor, "label": p.label, "cpe_token": p.cpe_token }))
        .collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
struct FactsBody {
    vendor: String,
    product: String,
    version: Option<String>,
    #[serde(default)]
    mgmt: Vec<String>,
}

async fn set_facts(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(b): Json<FactsBody>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    let facts = crate::fleet::DeviceFacts {
        asset_id,
        vendor: b.vendor,
        product: b.product,
        version: b.version,
        mgmt: b.mgmt,
    };
    store.upsert_device_facts(&facts)?;
    // New version info may match existing CVEs.
    let raised = crate::fleet::run_correlation(&store)?;
    Ok(Json(json!({ "facts": facts, "alerts_raised": raised })).into_response())
}

// ---- voip ----

#[derive(Deserialize)]
struct VoipTemplateQuery {
    host: String,
    port: Option<u16>,
}

async fn voip_template(Query(q): Query<VoipTemplateQuery>) -> ApiResult {
    let branch = Uuid::new_v4().simple().to_string();
    let msg = crate::voip::build_options_request(&q.host, q.port.unwrap_or(5060), &branch);
    Ok(Json(json!({ "sip_options": msg })).into_response())
}

#[derive(Deserialize)]
struct VoipAnalyzeBody {
    /// A raw SIP response captured from the target (e.g. to an OPTIONS probe).
    response: String,
}

async fn voip_analyze(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(b): Json<VoipAnalyzeBody>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    match crate::voip::parse_sip_response(&b.response) {
        Some(r) => {
            let fp = crate::voip::fingerprint(r.server.as_deref(), r.user_agent.as_deref());
            Ok(Json(json!({
                "parsed": r,
                "pbx": fp.map(|(p, note)| json!({ "product": p, "note": note })),
            }))
            .into_response())
        }
        None => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "not a SIP response" })),
        )
            .into_response()),
    }
}

// ---- vuln candidates / disclosure ----

#[derive(Deserialize)]
struct NewCandidate {
    title: String,
    detail: String,
    severity: Severity,
    cve_id: Option<String>,
}

async fn create_candidate(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(b): Json<NewCandidate>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    let now = Utc::now();
    let c = crate::disclosure::VulnCandidate {
        id: Uuid::new_v4(),
        asset_id,
        title: b.title,
        detail: b.detail,
        severity: b.severity,
        state: crate::disclosure::DisclosureState::Discovered,
        cve_id: b.cve_id,
        created_at: now,
        updated_at: now,
    };
    store.insert_candidate(&c)?;
    Ok((StatusCode::CREATED, Json(c)).into_response())
}

async fn list_candidates(State(store): State<Store>) -> ApiResult {
    Ok(Json(store.list_candidates()?).into_response())
}

#[derive(Deserialize)]
struct AdvanceBody {
    to: crate::disclosure::DisclosureState,
    cve_id: Option<String>,
}

async fn advance_candidate(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
    Json(b): Json<AdvanceBody>,
) -> ApiResult {
    let Some(c) = store.get_candidate(id)? else {
        return Ok(not_found("candidate"));
    };
    match crate::disclosure::advance(c.state, b.to) {
        Ok(next) => {
            store.update_candidate_state(id, next, b.cve_id.as_deref())?;
            Ok(Json(store.get_candidate(id)?).into_response())
        }
        Err(e) => Ok((
            StatusCode::CONFLICT,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response()),
    }
}

// ---- PRTG import ----

#[derive(Deserialize)]
struct PrtgImportBody {
    /// Raw PRTG /api/table.json?content=devices response body.
    table_json: String,
}

/// Import PRTG devices as assets for a client. Imported assets start Pending —
/// they still require explicit authorization before any scan.
async fn import_prtg(
    State(store): State<Store>,
    Path(client_id): Path<Uuid>,
    Json(b): Json<PrtgImportBody>,
) -> ApiResult {
    if store.get_client(client_id)?.is_none() {
        return Ok(not_found("client"));
    }
    let devices = crate::prtg::parse_table_devices(&b.table_json)?;
    let mut imported = 0usize;
    for d in &devices {
        let asset = Asset {
            id: Uuid::new_v4(),
            client_id,
            kind: if crate::prtg::looks_like_ip(&d.host) {
                AssetKind::Host
            } else {
                AssetKind::Domain
            },
            value: d.host.clone(),
            auth_status: AuthStatus::Pending,
            authorized_until: None,
            window_start: None,
            window_end: None,
            roe_reference: None,
            created_at: Utc::now(),
        };
        store.insert_asset(&asset)?;
        imported += 1;
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "imported": imported, "parsed": devices.len() })),
    )
        .into_response())
}

// ---- NMS interface evaluation ----

#[derive(Deserialize)]
struct NmsEvalBody {
    prev_octets: u64,
    cur_octets: u64,
    delta_seconds: f64,
    #[serde(default = "default_width")]
    width_bits: u32,
    speed_bps: f64,
    oper_up: bool,
    #[serde(default = "warn_default")]
    warn_pct: f64,
    #[serde(default = "crit_default")]
    crit_pct: f64,
}

fn default_width() -> u32 {
    64
}
fn warn_default() -> f64 {
    70.0
}
fn crit_default() -> f64 {
    90.0
}

/// Evaluate one interface sample pair into bandwidth / utilization / verdict.
/// The SNMP poller posts pairs here (or calls the nms functions directly).
async fn nms_eval(Json(b): Json<NmsEvalBody>) -> ApiResult {
    let bps = crate::nms::bandwidth_bps(b.prev_octets, b.cur_octets, b.delta_seconds, b.width_bits);
    let util = bps.and_then(|v| crate::nms::utilization_pct(v, b.speed_bps));
    let verdict = crate::nms::evaluate(util, b.oper_up, b.warn_pct, b.crit_pct);
    Ok(Json(json!({ "bps": bps, "utilization_pct": util, "verdict": verdict })).into_response())
}

// ---- web estate monitoring ----

#[derive(Deserialize)]
struct WebBaselineBody {
    /// Fetched page body (HTML/text).
    body: String,
    /// Present response header names.
    #[serde(default)]
    headers: Vec<String>,
    /// Days until the TLS cert expires (from the TLS peek), if available.
    cert_expiry_days: Option<i64>,
}

/// Record/compare a web baseline for an asset: content change (defacement),
/// header grade, and TLS expiry. Raises alerts on a real content change and on
/// an expiring/expired certificate. The live fetch/TLS peek feed this.
async fn web_baseline(
    State(store): State<Store>,
    Path(asset_id): Path<Uuid>,
    Json(b): Json<WebBaselineBody>,
) -> ApiResult {
    if store.get_asset(asset_id)?.is_none() {
        return Ok(not_found("asset"));
    }
    let hash = crate::web::content_hash(&crate::web::normalize_body(&b.body));
    let missing = crate::web::missing_security_headers(&b.headers);
    let grade = crate::web::header_grade(missing.len());

    let prev = store.get_web_content_hash(asset_id)?;
    let verdict = crate::web::change_verdict(prev.as_deref(), &hash);
    store.upsert_web_baseline(asset_id, &hash, grade, b.cert_expiry_days)?;

    let now = Utc::now();
    let mut alerts = 0;
    if verdict == crate::web::ChangeVerdict::Changed {
        store.insert_alert(&Alert {
            id: Uuid::new_v4(),
            asset_id,
            scan_id: None,
            severity: Severity::Medium,
            summary: "Contenuto sito cambiato (possibile defacement)".into(),
            detail: "L'hash del contenuto normalizzato è cambiato rispetto alla baseline.".into(),
            created_at: now,
        })?;
        alerts += 1;
    }
    if let Some(days) = b.cert_expiry_days {
        let sev = crate::web::cert_expiry_severity(days);
        if sev >= Severity::Low {
            store.insert_alert(&Alert {
                id: Uuid::new_v4(),
                asset_id,
                scan_id: None,
                severity: sev,
                summary: format!("Certificato TLS: {days} giorni alla scadenza"),
                detail: "Rinnovare il certificato per evitare interruzioni.".into(),
                created_at: now,
            })?;
            alerts += 1;
        }
    }

    Ok(Json(json!({
        "verdict": verdict,
        "header_grade": grade,
        "missing_headers": missing,
        "cert_severity": b.cert_expiry_days.map(|d| crate::web::cert_expiry_severity(d).as_str()),
        "alerts_raised": alerts,
    }))
    .into_response())
}

// ---- RPKI check ----

#[derive(Deserialize)]
struct VrpIn {
    prefix: String,
    max_len: u8,
    asn: u32,
}

#[derive(Deserialize)]
struct RpkiCheckBody {
    route: String,
    origin_asn: u32,
    #[serde(default)]
    vrps: Vec<VrpIn>,
}

async fn rpki_check(Json(b): Json<RpkiCheckBody>) -> ApiResult {
    let Some((rp, rl)) = crate::flowbgp::parse_v4_cidr(&b.route) else {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "route non è un CIDR IPv4 valido" })),
        )
            .into_response());
    };
    let mut vrps = Vec::new();
    for v in &b.vrps {
        if let Some((prefix, len)) = crate::flowbgp::parse_v4_cidr(&v.prefix) {
            vrps.push(crate::flowbgp::Vrp {
                prefix,
                len,
                max_len: v.max_len,
                asn: v.asn,
            });
        }
    }
    let state = crate::flowbgp::rpki_validity(rp, rl, b.origin_asn, &vrps);
    Ok(
        Json(json!({ "route": b.route, "origin_asn": b.origin_asn, "rpki": state }))
            .into_response(),
    )
}

// ---- mitigation proposals (approval-gated) ----

#[derive(Deserialize)]
struct NewMitigation {
    title: String,
    dst_cidr: String,
    action: crate::flowbgp::FsAction,
    #[serde(default)]
    allow_broad: bool,
}

async fn propose_mitigation(State(store): State<Store>, Json(b): Json<NewMitigation>) -> ApiResult {
    if let Err(e) = crate::flowbgp::validate_flowspec(&b.dst_cidr, &b.action, b.allow_broad) {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": e })),
        )
            .into_response());
    }
    let now = Utc::now();
    let p = crate::flowbgp::MitigationProposal {
        id: Uuid::new_v4(),
        title: b.title,
        dst_cidr: b.dst_cidr,
        action: b.action,
        state: crate::flowbgp::MitigationState::Proposed,
        approver: None,
        created_at: now,
        updated_at: now,
    };
    store.insert_mitigation(&p)?;
    Ok((StatusCode::CREATED, Json(p)).into_response())
}

async fn list_mitigations(State(store): State<Store>) -> ApiResult {
    Ok(Json(store.list_mitigations()?).into_response())
}

#[derive(Deserialize)]
struct ApproveBody {
    approver: String,
}

async fn transition_mitigation(
    store: &Store,
    id: Uuid,
    to: crate::flowbgp::MitigationState,
    approver: Option<&str>,
) -> ApiResult {
    let Some(m) = store.get_mitigation(id)? else {
        return Ok(not_found("mitigation"));
    };
    match crate::flowbgp::mitigation_advance(m.state, to) {
        Ok(next) => {
            store.update_mitigation_state(id, next, approver)?;
            Ok(Json(store.get_mitigation(id)?).into_response())
        }
        Err(e) => Ok((StatusCode::CONFLICT, Json(json!({ "error": e }))).into_response()),
    }
}

async fn approve_mitigation(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
    Json(b): Json<ApproveBody>,
) -> ApiResult {
    transition_mitigation(
        &store,
        id,
        crate::flowbgp::MitigationState::Approved,
        Some(&b.approver),
    )
    .await
}

async fn reject_mitigation(State(store): State<Store>, Path(id): Path<Uuid>) -> ApiResult {
    transition_mitigation(&store, id, crate::flowbgp::MitigationState::Rejected, None).await
}

/// Advance an approved proposal to Announced. The actual GoBGP FlowSpec/RTBH
/// announcement is the external seam; this records intent only.
async fn announce_mitigation(State(store): State<Store>, Path(id): Path<Uuid>) -> ApiResult {
    eprintln!("netdefense flowbgp: announce requested for mitigation {id} (GoBGP seam)");
    transition_mitigation(&store, id, crate::flowbgp::MitigationState::Announced, None).await
}

// ---- helpers ----

fn not_found(what: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": format!("{what} not found") })),
    )
        .into_response()
}

fn parse_time_opt(s: Option<&str>) -> Result<Option<NaiveTime>, ApiError> {
    match s {
        Some(v) => NaiveTime::parse_from_str(v, "%H:%M:%S")
            .map(Some)
            .map_err(|e| ApiError(anyhow::anyhow!("invalid time `{v}` (want HH:MM:SS): {e}"))),
        None => Ok(None),
    }
}
