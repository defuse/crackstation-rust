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
    http::{header, Request, Response},
};
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use super::url_canonicalization::is_dev_host;
use crate::libs::util::is_https;

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
