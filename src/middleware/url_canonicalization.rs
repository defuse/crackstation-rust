//! URL Canonicalization Middleware for CrackStation
//!
//! Handles all URL normalization and redirects:
//! - Host canonicalization (redirect to crackstation.net)
//! - HTTPS enforcement (with localhost bypass)
//! - URL canonicalization (/page -> /page.htm, .html -> .htm)
//! - Case normalization (redirect to canonical case from registry)

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, Response, StatusCode},
};
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::libs::util::is_https;
use crate::registry::{resolve_path, PathLookupResult};

/// The canonical hostname - all other hosts redirect here
pub const MASTER_HOST: &str = "crackstation.net";

/// Hosts that bypass redirects (for local development)
/// These hosts skip host canonicalization AND HTTPS enforcement
/// Note: Must include port for non-standard ports (e.g., "localhost:3000")
///
/// DO NOT add the real domain name (e.g. "crackstation.net") since that would cause
/// security_headers.rs to not add HSTS headers when it should.
///
/// # DEPLOYMENT CONTRACT: this list is only safe behind Caddy
///
/// Matching a host here turns off four protections and widens one boundary:
///
/// * `url_canonicalization.rs` skips host canonicalization, so the site answers on
///   whatever host asked instead of redirecting to `MASTER_HOST`;
/// * it skips HTTPS enforcement, so plain HTTP is served;
/// * `security_headers.rs` omits `Strict-Transport-Security`;
/// * `registered_page_handler.rs` builds absolute URLs with `http://`;
/// * `csrf.rs::is_accepted_host` treats the name as a legitimate request host, which
///   is the check that exists to stop DNS rebinding. That one is a security control,
///   not transport hardening.
///
/// The first two entries below are the exact `Host` values nginx's default
/// `proxy_pass` and Apache without `ProxyPreserveHost On` send upstream. Behind such a
/// front end every production request would match this list and run the whole site in
/// dev mode -- no misconfiguration required, just a different proxy.
///
/// That does not happen today because of two properties of the deployment, both
/// measured against real Caddy rather than assumed:
///
/// 1. Caddy's `reverse_proxy` preserves the client `Host`, so a request for
///    `crackstation.net` arrives here as `crackstation.net` and never as the upstream address.
/// 2. `operations/containers/crackstation-rust/config/Caddyfile` uses *named* site blocks,
///    so a request carrying any other `Host` -- including every name below -- is
///    answered by Caddy and never proxied. The dev branch is unreachable from
///    outside.
///
/// Neither property is written down anywhere but here. Changing the front end, or
/// adding a catch-all site block to the Caddyfile, re-arms this list.
pub const DEV_HOSTS: &[&str] = &[
    "localhost",
    "localhost:3000",
    "localhost:8080",
    "localhost:8443",
    "127.0.0.1",
    "127.0.0.1:3000",
    "127.0.0.1:8080",
    "127.0.0.1:8443",
    "crackstation",
    "crackstation:20443",
    "crackstation.h.defuse.ca",
];

/// Whether to enforce HTTPS (redirect HTTP -> HTTPS)
pub const FORCE_HTTPS: bool = true;

/// Tower layer for URL canonicalization
#[derive(Clone)]
pub struct UrlCanonicalizationLayer;

impl<S> Layer<S> for UrlCanonicalizationLayer {
    type Service = UrlCanonicalizationMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UrlCanonicalizationMiddleware { inner }
    }
}

/// The actual middleware service
#[derive(Clone)]
pub struct UrlCanonicalizationMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for UrlCanonicalizationMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();

            let host_without_port = host.split(':').next().unwrap_or("").to_lowercase();

            let connection_ip = req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip());
            let is_https = connection_ip
                .map(|ip| is_https(ip, req.headers()))
                .unwrap_or(false);

            let uri = req.uri().clone();
            let path = uri.path();
            let query = uri.query();

            let is_dev = is_dev_host(&host);

            // Reject requests with missing or empty Host header
            if host.is_empty() || host_without_port.is_empty() {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing Host header"))
                    .expect("valid response"));
            }

            // Step 1: Host canonicalization
            if !is_dev && host_without_port != MASTER_HOST {
                let use_https = FORCE_HTTPS || is_https;
                let redirect_url = build_redirect_url(use_https, MASTER_HOST, path, query);
                return Ok(redirect_301(&redirect_url));
            }

            // Step 2: HTTPS enforcement (skip for dev hosts)
            if FORCE_HTTPS && !is_https && !is_dev {
                let redirect_url = build_redirect_url(true, &host_without_port, path, query);
                return Ok(redirect_301(&redirect_url));
            }

            // Step 3: URL canonicalization
            if let Some(canonical_path) = canonicalize_url(path, query) {
                let redirect_url = build_redirect_url(is_https, &host, &canonical_path, None);
                return Ok(redirect_301(&redirect_url));
            }

            // No redirect needed, continue to inner service
            inner.call(req).await
        })
    }
}

/// Check if a host is in the dev hosts list (localhost, dev hosts, etc.)
pub fn is_dev_host(host: &str) -> bool {
    DEV_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// Canonicalize the URL path, returning a redirect URL if needed.
fn canonicalize_url(path: &str, query: Option<&str>) -> Option<String> {
    match resolve_path(path) {
        PathLookupResult::Canonical(_) => None,
        PathLookupResult::Redirect { canonical_path, .. } => {
            Some(append_query(&canonical_path, query))
        }
        PathLookupResult::NotFound => None,
    }
}

/// Build a full redirect URL
fn build_redirect_url(https: bool, host: &str, path: &str, query: Option<&str>) -> String {
    let scheme = if https { "https" } else { "http" };
    if let Some(q) = query {
        format!("{}://{}{}?{}", scheme, host, path, q)
    } else {
        format!("{}://{}{}", scheme, host, path)
    }
}

/// Append query string to a path
fn append_query(path: &str, query: Option<&str>) -> String {
    if let Some(q) = query {
        format!("{}?{}", path, q)
    } else {
        path.to_string()
    }
}

/// Create a 301 redirect response
fn redirect_301(url: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, url)
        .body(Body::empty())
        .expect("valid redirect response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_hosts() {
        assert!(is_dev_host("localhost"));
        assert!(is_dev_host("LOCALHOST"));
        assert!(is_dev_host("127.0.0.1"));
        assert!(is_dev_host("crackstation:20443"));
        assert!(!is_dev_host("crackstation.net"));
        assert!(!is_dev_host("evil.com"));
    }

    #[test]
    fn test_canonicalize_adds_htm() {
        let result = canonicalize_url("/about-us", None);
        assert_eq!(result, Some("/about-us.htm".to_string()));
    }

    #[test]
    fn test_canonicalize_preserves_query() {
        let result = canonicalize_url("/about-us", Some("foo=bar"));
        assert_eq!(result, Some("/about-us.htm?foo=bar".to_string()));
    }

    #[test]
    fn test_canonicalize_home_page() {
        let result = canonicalize_url("/index", None);
        assert_eq!(result, Some("/".to_string()));
    }

    #[test]
    fn test_canonicalize_html_to_htm() {
        let result = canonicalize_url("/about-us.html", None);
        assert_eq!(result, Some("/about-us.htm".to_string()));
    }

    #[test]
    fn test_no_redirect_when_canonical() {
        let result = canonicalize_url("/about-us.htm", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_root_no_redirect() {
        let result = canonicalize_url("/", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_case_canonicalization() {
        let result = canonicalize_url("/About-Us.htm", None);
        assert_eq!(result, Some("/about-us.htm".to_string()));
    }
}
