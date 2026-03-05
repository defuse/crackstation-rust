//! crackstation.net - Port of crackstation.net from PHP to Rust.
//! Copyright (C) 2026  Taylor Hornby
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as
//! published by the Free Software Foundation, either version 3 of the
//! License, or (at your option) any later version.

use axum::{middleware as axum_middleware, routing::any, Router};
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
use middleware::{blocking_middleware, SecurityHeadersLayer, UrlCanonicalizationLayer};

fn main() {
    // Build runtime with a higher blocking thread pool limit.
    // Every request runs on a blocking thread (via blocking_middleware), so this
    // effectively limits max concurrent requests.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(4096)
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

    // Database connection at startup (fail fast on misconfiguration)
    let phpcount_url = std::env::var("PHPCOUNT_DATABASE_URL").expect("PHPCOUNT_DATABASE_URL must be set");
    tracing::info!("Connecting to PHPCount database...");
    let phpcount = PhpCountService::connect(&phpcount_url).await.expect("Failed to connect to PHPCount database");
    tracing::info!("PHPCount database connected");

    // Validate required env vars
    std::env::var("RECAPTCHA_SECRET_KEY").expect("RECAPTCHA_SECRET_KEY must be set");

    // Initialize PreimageOracle from CRACKING_DIR
    tracing::info!("Loading hash lookup tables from {}...", cracking_dir.display());
    let oracle = cracking::init_oracle(&cracking_dir);
    tracing::info!("Hash lookup tables loaded");

    // Create application state
    let state = AppState::new(phpcount, oracle);

    // Build the router
    let app = Router::new()
        .fallback_service(
            axum::routing::get_service(
                ServeDir::new("static")
                    .fallback(any(registered_page_handler::handle).with_state(state.clone())),
            )
            .post(registered_page_handler::handle)
            .with_state(state.clone()),
        )
        // Middleware stack (innermost first):
        // 1. BlockingMiddleware: runs handlers on blocking thread pool for OS preemption
        .layer(axum_middleware::from_fn(blocking_middleware))
        .with_state(state.clone())
        // 2. URL canonicalization: normalize URLs, redirect to canonical form
        .layer(UrlCanonicalizationLayer)
        // 3. Security headers: HSTS, X-Frame-Options, etc.
        .layer(SecurityHeadersLayer)
        // 4. Catch panics: convert panics to 500 errors
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
