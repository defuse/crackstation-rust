//! Security Headers Middleware
//!
//! Adds security-related HTTP headers to all responses:
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
/// The Content-Security-Policy sent with every response.
///
/// Kept as a constant so the integration tests can assert the exact string a browser
/// receives, rather than a substring of it.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
script-src 'self' https://www.google.com https://www.gstatic.com; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data: https://www.google.com https://www.gstatic.com; \
font-src 'self'; \
connect-src 'self' https://www.google.com; \
frame-src https://www.google.com; \
form-action 'self'; \
base-uri 'none'; \
frame-ancestors 'self'";

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

            // Deliberately no Content-Type handling here. Every response that carries a
            // body already declares its own type -- askama sets text/html; charset=utf-8,
            // axum's (StatusCode, &str) responses set text/plain; charset=utf-8, and
            // ServeDir sets the file's mime type. The responses that arrive here without
            // one are the bodyless ones: 304, 412, and the 301/307 redirects. Supplying a
            // default would land on exactly those, telling a cache that a stored
            // text/css is now HTML, which RFC 9110 5.4.5 forbids a 304 from doing.
            //
            // So: do not add one back. If a response ever shows up untyped and needs a
            // type, fix it where it is built.

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

            // Content-Security-Policy.
            //
            // The site's own inventory is small: three stylesheets under /css, images
            // under /images, and one script, /js/home.js. Everything else linked from a
            // page is an ordinary <a href>, which CSP does not govern.
            //
            // The Google entries are all reCAPTCHA. api.js is fetched from www.google.com
            // and pulls from www.gstatic.com; it renders the widget in an iframe on
            // www.google.com and makes its own requests back there. Those are the reason
            // for the script-src, img-src, connect-src and frame-src entries -- get any of
            // them wrong and the checkbox never appears, which means nobody can submit a
            // hash at all. That is the failure mode to watch for after a change here.
            //
            // 'unsafe-inline' is present for styles and nowhere else. The templates carry
            // ~49 inline style attributes and reCAPTCHA injects its own, so removing it
            // would be a large refactor; style injection is also a much weaker primitive
            // than script injection, which is the one this actually constrains.
            //
            // The inline <script> that used to be in home.html now lives in
            // static/js/home.js precisely so script-src can stay 'self' with no
            // 'unsafe-inline' and no hash to keep in step with the template.
            //
            // default-src 'none' means anything not listed -- objects, workers, manifests,
            // fonts from elsewhere -- is refused rather than quietly allowed.
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                CONTENT_SECURITY_POLICY.parse().expect("valid header value"),
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
