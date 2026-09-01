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
    http::uri::Authority,
    http::{header, Request, Response, StatusCode},
    response::IntoResponse,
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

            // `None` here means the header is not a valid authority at all, which the
            // Host check below turns into a 400 rather than guessing at it.
            let host_without_port = host_name(&host).unwrap_or_default();

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
                // Built through IntoResponse rather than by hand so axum labels it
                // text/plain; charset=utf-8. A hand-built response carries no
                // Content-Type at all, and nothing downstream adds one.
                return Ok((StatusCode::BAD_REQUEST, "Missing Host header").into_response());
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

/// The host name from a `Host` header value, lowercased, or `None` if it is not a valid
/// authority.
///
/// The header is `uri-host [ ":" port ]`, which is not what `split(':').next()` returns.
/// That shortcut was wrong in three ways, and one of them was exploitable:
///
/// * `crackstation.net:@evil.com` split to `crackstation.net` and so matched
///   `MASTER_HOST`, skipping the canonicalisation redirect -- while the real host is
///   `evil.com`, because everything before `@` is userinfo. The raw header then reached
///   the `Location` of the URL-canonicalisation redirect, giving an open redirect from
///   this site's own origin.
/// * `user@crackstation.net` split to `user@crackstation.net`, which matches nothing.
/// * `[::1]:8080` split to `[`. Every IPv6 literal was mangled.
///
/// `Authority` is the parser for this grammar and gets all three right. It does not
/// lowercase, so that is done here: host comparison is case-insensitive (RFC 9110), and
/// every caller compares against a lowercase constant.
pub(crate) fn host_name(host_header: &str) -> Option<String> {
    Authority::try_from(host_header)
        .ok()
        .map(|authority| authority.host().to_lowercase())
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
    use axum::body::to_bytes;

    /// An inner service that would answer 200 if the middleware ever let a request
    /// through -- so a test asserting a 400 is also asserting the request was stopped.
    #[derive(Clone)]
    struct AlwaysOk;

    impl Service<Request<Body>> for AlwaysOk {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Response<Body>, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request<Body>) -> Self::Future {
            std::future::ready(Ok(Response::new(Body::from("inner service ran"))))
        }
    }

    /// The missing-Host rejection is the one response this middleware builds that has a
    /// body, so it is the one that has to declare its own type. It used to be built by
    /// hand with no Content-Type, and `SecurityHeadersLayer` then labelled its plain
    /// text as `text/html`. Nothing supplies a default any more, so an untyped body here
    /// would reach the client untyped.
    #[tokio::test]
    async fn missing_host_is_rejected_as_plain_text() {
        let mut service = UrlCanonicalizationLayer.layer(AlwaysOk);
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("valid request");

        let response = service.call(request).await.expect("infallible");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("a body must declare its type"),
            "text/plain; charset=utf-8"
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must be readable");
        assert_eq!(&body[..], b"Missing Host header");
    }

    /// The gadget this parser exists to close. Everything before `@` in an authority is
    /// userinfo, so the real host is `evil.com` -- but `split(':').next()` returned
    /// `crackstation.net`, which matched MASTER_HOST, skipped the canonical-host redirect,
    /// and let the raw header reach a `Location`. An open redirect from our own origin.
    #[test]
    fn userinfo_does_not_disguise_the_real_host() {
        assert_eq!(host_name("crackstation.net:@evil.com").as_deref(), Some("evil.com"));
        assert_eq!(
            host_name("crackstation.net:8443@evil.com").as_deref(),
            Some("evil.com")
        );
        assert_eq!(host_name("user@crackstation.net").as_deref(), Some("crackstation.net"));
    }

    /// `split(':')` returned `[` for every IPv6 literal.
    #[test]
    fn ipv6_literals_survive() {
        assert_eq!(host_name("[::1]:8080").as_deref(), Some("[::1]"));
        assert_eq!(host_name("[::1]").as_deref(), Some("[::1]"));
        assert_eq!(
            host_name("[2001:db8::1]:443").as_deref(),
            Some("[2001:db8::1]")
        );
    }

    /// The ordinary cases must keep working, including the port forms dev uses.
    #[test]
    fn plain_hosts_and_ports_are_unchanged() {
        assert_eq!(host_name("crackstation.net").as_deref(), Some("crackstation.net"));
        assert_eq!(
            host_name("crackstation.net:443").as_deref(),
            Some("crackstation.net")
        );
        assert_eq!(host_name("localhost:3000").as_deref(), Some("localhost"));
    }

    /// Host comparison is case-insensitive and every caller compares against a lowercase
    /// constant, so the parser must lowercase -- `Authority` does not.
    #[test]
    fn the_host_is_lowercased() {
        assert_eq!(host_name("CRACKSTATION.NET").as_deref(), Some("crackstation.net"));
        assert_eq!(host_name("CrackStation.Net:443").as_deref(), Some("crackstation.net"));
    }

    /// An unparseable authority yields None, which callers turn into a 400 or a
    /// non-matching host rather than a guess.
    #[test]
    fn an_invalid_authority_is_rejected() {
        assert_eq!(host_name(""), None);
        assert_eq!(host_name("not a host"), None);
        assert_eq!(host_name("crackstation.net/path"), None);
    }

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
