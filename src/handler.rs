//! PageHandler trait for registry-driven routing.
//!
//! All registered pages implement this trait. The registered_page_handler calls
//! the appropriate method based on the HTTP method of the request.

use std::future::Future;
use std::pin::Pin;

use axum::response::Response;
use bytes::Bytes;

use crate::app_state::AppState;
use crate::context::PageContext;

/// Represents a parsed POST body (form-urlencoded).
///
/// `Clone` is required to travel in the request extensions, which is how
/// `buffer_body_middleware` hands the body to the dispatcher. `Bytes` is
/// reference-counted, so cloning does not copy the body.
#[derive(Debug, Clone)]
pub struct PostBody(pub Bytes);

pub type BoxFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// Each registered page implements this trait to define its request handlers.
///
/// Code in registered_page_handler.rs looks up the handler in the registry and
/// calls the appropriate method based on the HTTP request method.
pub trait PageHandler: Send + Sync + 'static {
    /// Handle GET requests.
    fn get(&self, ctx: PageContext, state: &AppState) -> BoxFuture;

    /// Whether this page accepts POST. A page that returns true MUST implement `post`.
    ///
    /// This is asked separately from `post` so that the dispatcher can answer 405
    /// before it reads the request body and before it records a hit, and so that
    /// `allowed_methods` below has a single source of truth to derive from.
    fn accepts_post(&self) -> bool {
        false
    }

    /// Handle POST requests. Only called when `accepts_post` returns true.
    fn post(&self, _ctx: PageContext, _state: &AppState, _body: PostBody) -> BoxFuture {
        unreachable!("BUG: post() called on a page whose accepts_post() is false")
    }

    /// The methods this page supports, formatted as an `Allow` header value.
    ///
    /// RFC 9110 §15.5.6 makes `Allow` mandatory on a 405, and the list is a property
    /// of the resource, not of the router: only `/` accepts POST. Derived from
    /// `accepts_post` so the two answers cannot drift apart.
    fn allowed_methods(&self) -> &'static str {
        if self.accepts_post() {
            "GET, HEAD, POST"
        } else {
            "GET, HEAD"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pages;
    use crate::registry::PAGE_REGISTRY;

    #[test]
    fn pages_without_a_post_handler_allow_get_and_head_only() {
        assert!(!pages::about::Handler.accepts_post());
        assert_eq!(pages::about::Handler.allowed_methods(), "GET, HEAD");
        assert!(!pages::not_found::Handler.accepts_post());
        assert_eq!(pages::not_found::Handler.allowed_methods(), "GET, HEAD");
    }

    #[test]
    fn the_home_page_allows_post() {
        assert!(pages::home::Handler.accepts_post());
        assert_eq!(pages::home::Handler.allowed_methods(), "GET, HEAD, POST");
    }

    #[test]
    fn the_home_page_is_the_only_page_that_allows_post() {
        let mut posting_slugs: Vec<&'static str> = PAGE_REGISTRY
            .values()
            .filter(|page| page.handler.map_or(false, |h| h.accepts_post()))
            .map(|page| page.slug)
            .collect();
        posting_slugs.sort_unstable();
        assert_eq!(posting_slugs, vec![""]);
    }
}

/// Macro for simple pages that just render a template with PageContext.
#[macro_export]
macro_rules! simple_page {
    ($template:ident, $path:expr) => {
        use askama::Template;
        use axum::response::IntoResponse;

        use $crate::context::PageContext;
        use $crate::handler::{BoxFuture, PageHandler};
        use $crate::app_state::AppState;
        #[allow(unused_imports)]

        pub struct Handler;

        impl PageHandler for Handler {
            fn get(&self, ctx: PageContext, _state: &AppState) -> BoxFuture {
                Box::pin(async move { $template { ctx }.into_response() })
            }
        }

        #[derive(Template)]
        #[template(path = $path)]
        struct $template {
            ctx: PageContext,
        }
    };
}
