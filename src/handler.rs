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
#[derive(Debug)]
pub struct PostBody(pub Bytes);

pub type BoxFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// Each registered page implements this trait to define its request handlers.
///
/// Code in registered_page_handler.rs looks up the handler in the registry and
/// calls the appropriate method based on the HTTP request method.
pub trait PageHandler: Send + Sync + 'static {
    /// Handle GET requests.
    fn get(&self, ctx: PageContext, state: &AppState) -> BoxFuture;

    /// Handle POST requests. Returns None if POST is not supported (405 Method Not Allowed).
    fn post(&self, _ctx: PageContext, _state: &AppState, _body: PostBody) -> Option<BoxFuture> {
        None
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
        use $crate::prelude::*;

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
