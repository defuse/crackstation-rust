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
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::handler::PostBody;
use crate::registry::{resolve_path, PathLookupResult};

/// Largest request body accepted.
///
/// Sized for what the form can actually send, not for PHP's `post_max_size`. The only
/// route that consumes a body is `/`, whose ceiling is twenty hashes -- at most 128 hex
/// characters each -- plus a captcha token bounded at 8 KB by `recaptcha`. That is
/// under 11 KB, so 128 KB is more than ten times any legitimate submission.
///
/// The old value was 100 MB, and the number mattered because of what the handler does
/// with a body rather than the body itself. `form_urlencoded::parse(..).collect()`
/// materialises one `(Cow<str>, Cow<str>)` per pair, 64 bytes each, and the densest
/// input expressible is the two-byte `a&`. That is 32 bytes of `Vec` spine per byte
/// sent -- 100 MB became ~3.2 GB live, ~4.3 GB once the capacity rounded to a power of
/// two, and ~6.4 GB transiently while the final realloc held both halves. At 128 KB the
/// same ratio tops out around 8 MB.
///
/// Shrinking it is user-visible: a submission over the cap now gets a 413 where it used
/// to get a 200 and twenty "Unrecognized hash format" rows.
pub const MAX_BODY_BYTES: usize = 128 * 1024;

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

    if declares_oversized_body(request.headers()) {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
    }

    let (mut parts, body) = request.into_parts();
    let bytes: Bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        // A body that overran the cap without announcing a length lands here too.
        // Telling that apart from a truncated or malformed body would mean downcasting
        // axum's boxed error, and the honest answer for both is that the request could
        // not be read -- the announced-length case, which is every real client and the
        // whole of the attack, is already answered above with the right status.
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    parts.extensions.insert(PostBody(bytes));
    next.run(Request::from_parts(parts, Body::empty())).await
}

/// Whether the request announces a body larger than we will accept.
///
/// Checked before reading so an oversized upload costs nothing and gets the status that
/// describes it. `to_bytes` would also stop at the cap, but only after buffering up to
/// it, and its error cannot say *why* it failed.
fn declares_oversized_body(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_length(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, value.parse().expect("valid header"));
        headers
    }

    /// The attack this cap exists for: 100 MB announced up front, which the handler
    /// would have turned into gigabytes of `Vec` spine.
    #[test]
    fn a_body_far_over_the_cap_is_refused_before_it_is_read() {
        assert!(declares_oversized_body(&headers_with_length("104857600")));
    }

    /// One byte over is over. The boundary is where an off-by-one would hide.
    #[test]
    fn the_cap_is_exclusive_at_the_boundary() {
        assert!(!declares_oversized_body(&headers_with_length(
            &MAX_BODY_BYTES.to_string()
        )));
        assert!(declares_oversized_body(&headers_with_length(
            &(MAX_BODY_BYTES + 1).to_string()
        )));
    }

    /// A real submission is nowhere near the cap, and must not be refused.
    #[test]
    fn a_legitimate_submission_is_not_oversized() {
        assert!(!declares_oversized_body(&headers_with_length("11000")));
        assert!(!declares_oversized_body(&headers_with_length("0")));
    }

    /// No length, or a length that is not a number, is not a claim that the body is
    /// too large -- `to_bytes` still enforces the cap for those.
    #[test]
    fn an_absent_or_unparseable_length_is_not_a_refusal() {
        assert!(!declares_oversized_body(&HeaderMap::new()));
        assert!(!declares_oversized_body(&headers_with_length(
            "not-a-number"
        )));
        assert!(!declares_oversized_body(&headers_with_length("-1")));
    }

    /// The cap must stay clear of what the form can legitimately send: twenty hashes of
    /// 128 hex characters plus an 8 KB captcha token, under 11 KB in total.
    #[test]
    fn the_cap_leaves_room_for_the_largest_legitimate_submission() {
        let largest_form = 20 * (128 + 3) + 8 * 1024 + 128;
        assert!(
            MAX_BODY_BYTES > largest_form * 4,
            "{MAX_BODY_BYTES} leaves too little room over {largest_form} bytes of form"
        );
    }

    /// Only the home page consumes a POST body. Everything else must be answered
    /// without reading one, or an oversized POST to a page that rejects POST would be
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
