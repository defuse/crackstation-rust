//! Central dispatcher for all registered page requests.
//!
//! Hit counting is done here (not in middleware) because it only applies
//! to formally-defined pages.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, Method, Request, StatusCode, Uri},
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

    // Reject an unsupported method here, before the body is read and before the hit
    // is recorded: it is the cheapest rejection in the request and should not sit
    // behind the two most expensive steps.
    if method == Method::POST && !handler.accepts_post() {
        return method_not_allowed(handler.allowed_methods());
    }

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
        recaptcha_site_key: state.recaptcha_site_key,
    };

    // Dispatch based on HTTP method
    match method {
        Method::GET | Method::HEAD => handler.get(ctx, &state).await,
        Method::POST => {
            handler
                .post(ctx, &state, post_body.expect("BUG: POST without body"))
                .await
        }
        // The router sends nothing else here. ServeDir answers every other method
        // itself without consulting its fallback, and main.rs routes the remaining
        // methods to handle_unsupported_method.
        _ => unreachable!("BUG: dispatcher reached with method {}", method),
    }
}

/// Answer the methods the router does not route: PUT, DELETE, PATCH, OPTIONS,
/// TRACE and CONNECT. Registered as the `MethodRouter` fallback in main.rs.
///
/// axum's own default fallback emits one router-wide `Allow` — `GET,HEAD,POST` —
/// which is wrong on the nine pages that do not accept POST, and which contradicts
/// the 405 those pages return for POST. axum fills in its value only when the
/// response does not already carry `Allow`, so the per-resource value set here is
/// the one that ships.
///
/// Deliberately reads no body and records no hit.
pub async fn handle_unsupported_method(uri: Uri) -> Response {
    let allowed_methods = match resolve_path(uri.path()) {
        PathLookupResult::Canonical(page) => page
            .handler
            .expect("BUG: canonical page must have a handler")
            .allowed_methods(),
        // Aliases are redirected by UrlCanonicalizationLayer before the router sees
        // them, static assets are served by ServeDir, and unregistered paths render
        // the 404 page. All of those are read-only.
        PathLookupResult::Redirect { .. } | PathLookupResult::NotFound => "GET, HEAD",
    };
    method_not_allowed(allowed_methods)
}

/// Build a 405 carrying the `Allow` header RFC 9110 §15.5.6 requires.
fn method_not_allowed(allowed_methods: &'static str) -> Response {
    let mut response = (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed").into_response();
    response.headers_mut().insert(
        header::ALLOW,
        allowed_methods.parse().expect("valid header value"),
    );
    response
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
        recaptcha_site_key: crate::app_state::PRODUCTION_RECAPTCHA_SITE_KEY,
    };

    (StatusCode::NOT_FOUND, NotFoundPage { ctx }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Allow` value on a response, or a failure if the header is absent —
    /// RFC 9110 §15.5.6 makes it mandatory on a 405.
    fn allow_header(response: &Response) -> &str {
        response
            .headers()
            .get(header::ALLOW)
            .expect("a 405 must carry an Allow header")
            .to_str()
            .expect("Allow header must be ASCII")
    }

    #[tokio::test]
    async fn unsupported_method_on_a_page_without_post_advertises_get_and_head() {
        let response =
            handle_unsupported_method("/about-us.htm".parse().expect("valid uri")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(allow_header(&response), "GET, HEAD");
    }

    #[tokio::test]
    async fn unsupported_method_on_the_home_page_advertises_post_too() {
        let response = handle_unsupported_method("/".parse().expect("valid uri")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(allow_header(&response), "GET, HEAD, POST");
    }

    #[tokio::test]
    async fn unsupported_method_on_a_static_asset_advertises_get_and_head() {
        let response =
            handle_unsupported_method("/css/main.css".parse().expect("valid uri")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(allow_header(&response), "GET, HEAD");
    }

    #[tokio::test]
    async fn unsupported_method_on_an_unregistered_path_advertises_get_and_head() {
        let response =
            handle_unsupported_method("/no-such-page.htm".parse().expect("valid uri")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(allow_header(&response), "GET, HEAD");
    }
}
