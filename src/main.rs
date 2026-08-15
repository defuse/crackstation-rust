//! crackstation.net - Port of crackstation.net from PHP to Rust.
//! Copyright (C) 2026  Taylor Hornby
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as
//! published by the Free Software Foundation, either version 3 of the
//! License, or (at your option) any later version.

use axum::{
    error_handling::HandleErrorLayer, http::StatusCode, middleware as axum_middleware,
    routing::any, BoxError, Router,
};
use tower::{
    limit::GlobalConcurrencyLimitLayer, load_shed::LoadShedLayer, ServiceBuilder,
};
use tower_http::{catch_panic::CatchPanicLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod app_state;
mod context;
mod cracking;
mod handler;
mod libs;
mod middleware;
mod pages;
mod prelude;
mod registered_page_handler;
mod registry;

use app_state::AppState;
use libs::PhpCountService;
use middleware::{
    blocking_middleware, buffer_body_middleware, SecurityHeadersLayer, UrlCanonicalizationLayer,
};

/// Directory holding CSS, images, robots.txt and favicon.ico, relative to the
/// process working directory.
const STATIC_DIR: &str = "static";

/// The wordlist archives the wordlist page links as `/files/<name>`.
///
/// Kept next to the startup check so the list cannot drift from
/// `templates/pages/wordlist.html`; a test asserts the two agree.
const WORDLIST_MIRROR_FILES: &[&str] = &["crackstation.txt.gz", "crackstation-human-only.txt.gz"];

/// Size of Tokio's blocking thread pool.
///
/// Every request runs its handler on one of these (see `blocking_middleware`), so
/// this is the ceiling on threads the request path can consume.
const MAX_BLOCKING_THREADS: usize = 4096;

/// How many requests may be in the blocking middleware at once.
///
/// **This is a correctness bound, not a tuning knob.** The pool is used
/// re-entrantly: a request holds one thread for its whole lifetime, and the
/// handler stack running inside it draws a *second* thread from the same pool —
/// `ServeDir` probes the filesystem through `tokio::fs`, which is `spawn_blocking`,
/// and the reCAPTCHA call resolves DNS the same way. Both are leaves, and at most
/// one is outstanding per request, so peak demand is `2 * MAX_CONCURRENT_REQUESTS`.
///
/// If that can reach `MAX_BLOCKING_THREADS`, the pool deadlocks *permanently*:
/// every thread ends up parked waiting on a nested task queued behind it in the
/// same FIFO, and none of the escapes apply — tokio will not exceed the cap
/// (`blocking/pool.rs`: the at-cap branch is empty, the task simply waits), a
/// thread inside `task.run()` is never counted idle so the keep-alive timer never
/// reaps it, and `spawn_blocking` closures cannot be cancelled, so client
/// disconnects and proxy timeouts free nothing. The process must be restarted, and
/// it still answers TCP handshakes meanwhile, so connect-based health checks pass.
///
/// Keeping this at a quarter of the pool leaves peak demand at half the cap.
const MAX_CONCURRENT_REQUESTS: usize = MAX_BLOCKING_THREADS / 4;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
        .expect("failed to build Tokio runtime");

    runtime.block_on(async_main());
}

async fn async_main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crackstation_rust=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listen_addr =
        std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    // Required configuration (fail fast if not set)
    let cracking_dir = std::path::PathBuf::from(
        std::env::var("CRACKING_DIR").expect("CRACKING_DIR must be set"),
    );

    // Static assets are served from a path relative to the working directory, and
    // ServeDir does not validate it — a missing directory yields a 404 per asset
    // rather than an error, so every page would render with no CSS and no images
    // while still returning 200. Refuse to start instead, the way a missing
    // CRACKING_DIR does.
    let static_dir = std::path::Path::new(STATIC_DIR);
    if !static_dir.is_dir() {
        panic!(
            "static asset directory {:?} not found (working directory is {:?}). \
             Run the server from the repository root, or the site would serve \
             every page without stylesheets or images.",
            STATIC_DIR,
            std::env::current_dir().expect("working directory must be readable"),
        );
    }
    tracing::info!("Serving static assets from {}", static_dir.display());

    // The wordlist page advertises an "HTTP Mirror (Slow)" for each download, and
    // those two blobs are the product the page exists to deliver. Nothing in the
    // application referenced them before: /files is a Caddy `handle_path` pointing at
    // /storage/extras/files, so a deployment that forgot the rule, or a storage volume
    // that came up without the blobs, served a 404 from the one link a user without a
    // torrent client has to use — and the site looked completely healthy otherwise.
    //
    // Name the dependency and check it here. Caddy still answers /files/* first in
    // production, so this ServeDir is what makes the URLs testable and a working
    // fallback if the front-end rule is ever dropped.
    let wordlist_files_dir = std::path::PathBuf::from(
        std::env::var("WORDLIST_FILES_DIR").expect("WORDLIST_FILES_DIR must be set"),
    );
    for file_name in WORDLIST_MIRROR_FILES {
        let path = wordlist_files_dir.join(file_name);
        if !path.is_file() {
            panic!(
                "wordlist mirror file {:?} not found. The wordlist page links it as \
                 /files/{}, so without it that download 404s while every other page \
                 looks healthy. Set WORDLIST_FILES_DIR to the directory holding the \
                 wordlist archives (production: /storage/extras/files).",
                path.display(),
                file_name,
            );
        }
    }
    tracing::info!(
        "Serving wordlist downloads from {}",
        wordlist_files_dir.display()
    );

    // Database connection at startup (fail fast on misconfiguration)
    let phpcount_url = std::env::var("PHPCOUNT_DATABASE_URL").expect("PHPCOUNT_DATABASE_URL must be set");
    tracing::info!("Connecting to PHPCount database...");
    let phpcount = PhpCountService::connect(&phpcount_url).await.expect("Failed to connect to PHPCount database");
    tracing::info!("PHPCount database connected");

    // Validate required env vars
    std::env::var("RECAPTCHA_SECRET_KEY").expect("RECAPTCHA_SECRET_KEY must be set");

    let use_dev_recaptcha = std::env::var("USE_DEV_RECAPTCHA_KEY")
        .map(|v| v == "true")
        .unwrap_or(false);
    if use_dev_recaptcha {
        tracing::info!("Using dev reCAPTCHA site key (USE_DEV_RECAPTCHA_KEY=true)");
    }

    // Initialize PreimageOracle from CRACKING_DIR
    tracing::info!("Loading hash lookup tables from {}...", cracking_dir.display());
    let oracle = cracking::init_oracle(&cracking_dir);
    tracing::info!("Hash lookup tables loaded");

    // Create application state
    let state = AppState::new(phpcount, oracle, use_dev_recaptcha);

    // Build the router
    let app = Router::new()
        // Wordlist archives. Caddy's handle_path answers these first in production;
        // this makes the dependency explicit and the URLs testable.
        .nest_service("/files", ServeDir::new(&wordlist_files_dir))
        .fallback_service(
            axum::routing::get_service(
                ServeDir::new(STATIC_DIR)
                    .fallback(any(registered_page_handler::handle).with_state(state.clone())),
            )
            .post(registered_page_handler::handle)
            // Everything except GET/HEAD/POST. Without this, axum answers those
            // methods with a router-wide `Allow: GET,HEAD,POST`, which advertises
            // POST on the nine pages that reject it.
            .fallback(registered_page_handler::handle_unsupported_method)
            .with_state(state.clone()),
        )
        // Middleware stack (innermost first):
        // 1. BlockingMiddleware: runs handlers on blocking thread pool for OS preemption
        .layer(axum_middleware::from_fn(blocking_middleware))
        .with_state(state.clone())
        // 2. Admission control, immediately outside the blocking middleware so that
        //    it gates entry to the pool and nothing else. See MAX_CONCURRENT_REQUESTS:
        //    the limit is what makes the pool's re-entrant use safe. LoadShed turns the
        //    concurrency limit's backpressure into an immediate 503 rather than an
        //    unbounded queue, and HandleError maps that back into a response, since
        //    axum's router requires an infallible service.
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::SERVICE_UNAVAILABLE
                }))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS)),
        )
        // 3. Buffer the POST body on the async runtime, before a pool thread is
        //    taken, so a slow body cannot pin one.
        .layer(axum_middleware::from_fn(buffer_body_middleware))
        // 4. URL canonicalization: normalize URLs, redirect to canonical form
        .layer(UrlCanonicalizationLayer)
        // 5. Security headers: HSTS, X-Frame-Options, etc.
        .layer(SecurityHeadersLayer)
        // 6. Catch panics: convert panics to 500 errors
        .layer(CatchPanicLayer::new());

    tracing::info!("Listening on http://{}", listen_addr);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await
        .expect("failed to bind listener");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
        eprintln!("Shutting down gracefully (Ctrl+C again to force quit)...");
        // Reset SIGINT to default OS behavior so the next Ctrl+C kills immediately
        unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL); }
    })
    .await
    .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::WORDLIST_MIRROR_FILES;

    /// The startup check and the page have to name the same files. If someone adds a
    /// download to the template, the check must grow with it, or the new link is
    /// exactly as unguarded as these two were.
    #[test]
    fn wordlist_mirror_files_match_the_links_on_the_page() {
        let template = include_str!("../templates/pages/wordlist.html");

        let linked: Vec<&str> = template
            .match_indices("href=\"/files/")
            .map(|(index, matched)| {
                let rest = &template[index + matched.len()..];
                &rest[..rest.find('"').expect("href must be closed")]
            })
            .collect();

        assert_eq!(
            linked, WORDLIST_MIRROR_FILES,
            "the /files links on the wordlist page and WORDLIST_MIRROR_FILES disagree"
        );
    }
}
