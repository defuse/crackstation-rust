//! Security Headers Middleware
//!
//! Adds security-related HTTP headers to all responses:
//! - Content-Type: text/html; charset=utf-8 (explicit, not relying on defaults)
//! - X-Frame-Options: SAMEORIGIN
//! - X-Content-Type-Options: nosniff
//! - Referrer-Policy: strict-origin-when-cross-origin
//! - Strict-Transport-Security (HSTS) - only over HTTPS, not for localhost

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, Response, StatusCode},
};
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use super::url_canonicalization::is_dev_host;
use crate::libs::util::is_https;
use crate::registry::{resolve_path, PathLookupResult};

/// Whether this path's page forbids caching.
fn check_no_cache(path: &str) -> bool {
    match resolve_path(path) {
        PathLookupResult::Canonical(page) => page.no_cache,
        _ => false,
    }
}

/// Tower layer for security headers
#[derive(Clone)]
pub struct SecurityHeadersLayer;

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware { inner }
    }
}

/// The actual middleware service
#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for SecurityHeadersMiddleware<S>
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

        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let connection_ip = req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let is_https = connection_ip
            .map(|ip| is_https(ip, req.headers()))
            .unwrap_or(false);

        let is_dev = is_dev_host(&host);

        // Resolved before the inner service runs, because the response no longer
        // carries the path.
        let is_no_cache_page = check_no_cache(req.uri().path());

        Box::pin(async move {
            let mut response = inner.call(req).await?;
            let headers = response.headers_mut();

            // Content-Type: only set for HTML pages, not static assets
            let existing_content_type = headers.get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if existing_content_type.is_empty()
                || existing_content_type == "text/html"
                || existing_content_type.starts_with("text/html;")
            {
                headers.insert(
                    header::CONTENT_TYPE,
                    "text/html; charset=utf-8".parse().expect("valid header value"),
                );
            }

            // X-Frame-Options: SAMEORIGIN (always)
            headers.insert(
                header::X_FRAME_OPTIONS,
                "SAMEORIGIN".parse().expect("valid header value"),
            );

            // X-Content-Type-Options: nosniff
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().expect("valid header value"),
            );

            // Referrer-Policy
            headers.insert(
                header::REFERRER_POLICY,
                "strict-origin-when-cross-origin".parse().expect("valid header value"),
            );

            // Sensitive pages must not be left in a shared browser's cache or in its
            // back/forward history. The submitted hashes and the recovered plaintexts
            // are in this response body, and nothing else on the site is.
            //
            // Same set of headers defuse-rust sends for its password generator: the
            // Expires date in the past and the Pragma line are for HTTP/1.0-era
            // intermediaries that ignore Cache-Control, and cost nothing to send.
            if is_no_cache_page {
                let headers = response.headers_mut();
                headers.insert(
                    header::CACHE_CONTROL,
                    "no-cache, no-store, must-revalidate".parse().expect("valid header value"),
                );
                headers.insert(
                    header::EXPIRES,
                    "Mon, 01 Jan 1990 00:00:00 GMT".parse().expect("valid header value"),
                );
                headers.insert(
                    header::PRAGMA,
                    "no-cache".parse().expect("valid header value"),
                );
            }

            // Allow belongs on a 405 and nowhere else. axum's MethodRouter stamps its
            // router-wide value (GET,HEAD,POST) onto any response from the method
            // fallback that does not already carry one, so the 404 that fallback returns
            // for an unresolved path would otherwise advertise three methods, two of
            // which answer 404 on that path and one of which is refused everywhere but
            // "/". There is no public way to switch that off: MethodRouter's
            // skip_allow_header is private and reachable only through any(), which
            // cannot also carry the GET and POST routes this router needs.
            if response.status() != StatusCode::METHOD_NOT_ALLOWED {
                response.headers_mut().remove(header::ALLOW);
            }
            let headers = response.headers_mut();

            // HSTS: only over HTTPS and not for localhost/dev hosts
            if is_https && !is_dev {
                headers.insert(
                    header::STRICT_TRANSPORT_SECURITY,
                    "max-age=31536000; includeSubDomains; preload"
                        .parse()
                        .expect("valid header value"),
                );
            }

            Ok(response)
        })
    }
}
