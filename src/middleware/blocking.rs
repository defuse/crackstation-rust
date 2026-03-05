//! Blocking middleware - runs handlers on the blocking thread pool.
//!
//! This middleware wraps all request handlers so they run on Tokio's blocking
//! thread pool instead of the async runtime. This provides OS-level preemption
//! for CPU-bound work (hash lookups), preventing a single slow request from
//! blocking the entire async runtime.

use axum::{extract::Request, middleware::Next, response::Response};
use tokio::runtime::Handle;

/// Middleware that runs the inner handler on the blocking thread pool.
pub async fn blocking_middleware(request: Request, next: Next) -> Response {
    let handle = Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(next.run(request)))
        .await
        .expect("blocking execution of a handler panicked")
}
