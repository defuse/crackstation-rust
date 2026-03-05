//! 404 Not Found page.
//!
//! This module provides the NotFoundPage template struct used by the dispatcher,
//! and a Handler for use in the registry.

use askama::Template;
use axum::response::IntoResponse;

use crate::context::PageContext;
use crate::handler::{BoxFuture, PageHandler};
use crate::app_state::AppState;

pub struct Handler;

impl PageHandler for Handler {
    fn get(&self, ctx: PageContext, _state: &AppState) -> BoxFuture {
        Box::pin(async move {
            (axum::http::StatusCode::NOT_FOUND, NotFoundPage { ctx }).into_response()
        })
    }
}

#[derive(Template)]
#[template(path = "pages/not_found.html")]
pub struct NotFoundPage {
    pub ctx: PageContext,
}
