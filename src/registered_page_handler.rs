//! Central dispatcher for all registered page requests.
//!
//! Hit counting is done here (not in middleware) because it only applies
//! to formally-defined pages.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use tracing::{debug, error};

use crate::app_state::AppState;
use crate::context::PageContext;
use crate::handler::PostBody;
use crate::libs::{phpcount::HitCounts, util::client_ip};
use crate::middleware::url_canonicalization::is_dev_host;
use crate::pages::not_found::NotFoundPage;
use crate::registry::{resolve_path, PathLookupResult, NOT_FOUND_PAGE_INFO};

/// Main registered page handler. Set as a fallback in main.rs.
pub async fn handle(State(state): State<AppState>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query_string = request.uri().query().map(|s| s.to_string());

    // Extract all data from request BEFORE any async operations.
    let connection_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .expect("BUG: ConnectInfo not available - is into_make_service_with_connect_info set up?")
        .0
        .ip();
    let client_ip = client_ip(connection_ip, request.headers());

    let dnt_enabled = request
        .headers()
        .get(header::DNT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let host = match request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => {
            return (StatusCode::BAD_REQUEST, "Missing Host header").into_response();
        }
    };

    let scheme = if is_dev_host(&host) { "http" } else { "https" };
    let url_prefix = format!("{}://{}", scheme, host);

    let captcha_bypass_header = request
        .headers()
        .get("X-Captcha-Bypass")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Look up the registered page.
    let page_info = match resolve_path(&path) {
        PathLookupResult::Canonical(page) => page,
        PathLookupResult::NotFound => {
            return render_not_found(client_ip, dnt_enabled);
        }
        PathLookupResult::Redirect { canonical_path } => {
            // Middleware should have already redirected. This is a bug.
            panic!(
                "BUG: Redirect reached dispatcher - middleware failed to redirect {} -> {}",
                path, canonical_path
            );
        }
    };

    // All non-redirect registry entries MUST have a handler
    let handler = page_info.handler.expect("BUG: canonical page must have a handler");

    // Extract body for POST requests.
    let post_body = if method == Method::POST {
        let (_parts, body) = request.into_parts();
        // 100MB limit (matches PHP's post_max_size)
        match axum::body::to_bytes(body, 100 * 1024 * 1024).await {
            Ok(bytes) => Some(PostBody(bytes)),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
            }
        }
    } else {
        None
    };

    // Count the hit
    let page_id = page_info.hit_counter_id();
    let hit_counts = record_and_get_hits(&state, page_id, &client_ip, &user_agent).await;

    debug!("{} {} (ip: {})", method, path, client_ip);

    let ctx = PageContext {
        page_info,
        client_ip,
        dnt_enabled,
        hit_counts,
        captcha_bypass_header,
        query_string,
        url_prefix,
    };

    // Dispatch based on HTTP method
    match method {
        Method::GET | Method::HEAD => handler.get(ctx, &state).await,
        Method::POST => match handler.post(ctx, &state, post_body.expect("BUG: POST without body")) {
            Some(future) => future.await,
            None => {
                (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed").into_response()
            }
        },
        _ => {
            (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed").into_response()
        }
    }
}

/// Record a hit and get hit counts from the database.
async fn record_and_get_hits(
    state: &AppState,
    page_id: &str,
    client_ip: &str,
    user_agent: &str,
) -> HitCounts {
    if let Err(e) = state.phpcount.add_hit(page_id, client_ip, user_agent).await {
        error!("Failed to record hit for {}: {}", page_id, e);
    }

    state.phpcount.get_hit_counts(page_id).await
        .unwrap_or_else(|e| {
            error!("Failed to get hit counts for {}: {}", page_id, e);
            HitCounts::default()
        })
}

/// Render the 404 not found page.
fn render_not_found(client_ip: String, dnt_enabled: bool) -> Response {
    let ctx = PageContext {
        page_info: &NOT_FOUND_PAGE_INFO,
        client_ip,
        dnt_enabled,
        hit_counts: HitCounts::default(),
        captcha_bypass_header: None,
        query_string: None,
        url_prefix: "https://crackstation.net".to_string(),
    };

    (StatusCode::NOT_FOUND, NotFoundPage { ctx }).into_response()
}
