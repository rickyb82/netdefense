//! HTTP API (axum). CRUD for clients and assets, the authorisation action, and
//! scan triggering. Authorisation is enforced inside `scan::run_scan`, so a
//! refused scan comes back as HTTP 403 with the reason.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, NaiveTime, Utc};
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
        .route("/scans/:id", get(get_scan))
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
