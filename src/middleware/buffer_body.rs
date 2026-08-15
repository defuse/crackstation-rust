//! Reads the request body before a blocking-pool thread is taken.
//!
//! The dispatcher used to await `axum::body::to_bytes` itself, and the dispatcher
//! runs inside `blocking_middleware`'s closure — so the read happened *on a pool
//! thread*. A client that sent POST headers with a large `Content-Length` and then
//! dribbled the body pinned a 2 MiB-stack OS thread for as long as it cared to,
//! and because `spawn_blocking` closures cannot be cancelled, disconnecting was
//! the only thing that freed it.
//!
//! Doing the read here instead — outside `blocking_middleware`, on the async
//! runtime — costs a task rather than a thread, and is cancellable, so an
//! abandoned upload releases everything immediately. The buffered bytes travel to
//! the dispatcher in the request extensions.

use axum::{
    body::{Body, Bytes},
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::handler::PostBody;
use crate::registry::{resolve_path, PathLookupResult};

/// Largest request body accepted, matching PHP's `post_max_size`.
///
/// This is deliberately unchanged for now: shrinking it to something the form can
/// actually use is a separate change with its own user-visible effect (413s where
/// there were 200s).
pub const MAX_BODY_BYTES: usize = 100 * 1024 * 1024;

/// Whether the page this path resolves to will actually consume a POST body.
///
/// Only `/` does. Buffering for anything else would read up to `MAX_BODY_BYTES`
/// and then throw it away when the dispatcher answers 405 or 404 — and the
/// dispatcher returns both of those *before* it looks for the buffered body, so
/// skipping the read here keeps that rejection the cheapest response in the
/// request rather than the most expensive one.
fn will_consume_a_body(path: &str) -> bool {
    match resolve_path(path) {
        PathLookupResult::Canonical(page) => {
            page.handler.is_some_and(|handler| handler.accepts_post())
        }
        PathLookupResult::Redirect { .. } | PathLookupResult::NotFound => false,
    }
}

/// Buffer the body of a POST before the request reaches the blocking pool.
pub async fn buffer_body_middleware(request: Request, next: Next) -> Response {
    if request.method() != Method::POST || !will_consume_a_body(request.uri().path()) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    let bytes: Bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    parts.extensions.insert(PostBody(bytes));
    next.run(Request::from_parts(parts, Body::empty())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the home page consumes a POST body. Everything else must be answered
    /// without reading one, or a 100 MB POST to a page that rejects POST would be
    /// buffered in full and then discarded.
    #[test]
    fn only_the_home_page_consumes_a_body() {
        assert!(will_consume_a_body("/"));

        for path in [
            "/about-us.htm",
            "/legal-privacy.htm",
            "/crackstation-wordlist-password-cracking-dictionary.htm",
            "/css/main.css",
            "/no-such-page.htm",
            "/index.htm",
        ] {
            assert!(
                !will_consume_a_body(path),
                "{path} must not have its body buffered"
            );
        }
    }
}
