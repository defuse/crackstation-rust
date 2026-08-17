//! reCAPTCHA verification — centralized helper matching defuse-rust's pattern.
//!
//! Returns `Ok(true)` when the user passed, `Ok(false)` when the user failed,
//! and `Err(...)` when infrastructure is broken (network, config, parsing).
//! This distinction prevents misconfiguration or outages from being silently
//! swallowed as "bad captcha."

use anyhow::{Context, Result};

/// Verify a reCAPTCHA response token with Google's API.
///
/// Returns `Ok(true)` if the captcha was solved correctly, `Ok(false)` if the
/// user failed the challenge.
///
/// # Errors
///
/// Returns an error on network failure, JSON parse failure, or missing
/// `RECAPTCHA_SECRET_KEY` env var (should not happen if startup validates it).
///
/// # Panics
///
/// Panics if `RECAPTCHA_SECRET_KEY` is not set. This is intentional — the env
/// var is validated at startup in main.rs, so a missing value here indicates a
/// programming error, not a runtime condition.
pub async fn verify(token: &str, remote_ip: &str) -> Result<bool> {
    let secret = std::env::var("RECAPTCHA_SECRET_KEY")
        .expect("RECAPTCHA_SECRET_KEY must be set (validated at startup)");

    let client = reqwest::Client::new();
    let resp = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", token),
            ("remoteip", remote_ip),
        ])
        .send()
        .await
        .context("reCAPTCHA verification request failed")?;

    let json: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse reCAPTCHA response JSON")?;

    let success = json["success"].as_bool().unwrap_or(false);
    let hostname = json["hostname"].as_str();

    // Google names the domain the challenge was solved on, and hands back
    // "testkey.google.com" for every verification made with its published test secret.
    // That is the request-time signature of the configuration check_captcha_config
    // refuses to boot on: a production site key paired with the test secret, where the
    // visitor sees a real challenge and the server accepts anything.
    //
    // Startup already blocks that pairing, so reaching here means the secret changed
    // underneath a running process -- the secret is re-read from the environment on
    // every call. Treat it as a hard error rather than a failed captcha, so it is
    // logged as infrastructure breakage instead of being shown to a visitor as their
    // own mistake.
    if hostname == Some(TEST_KEY_HOSTNAME) {
        anyhow::bail!(
            "reCAPTCHA verified against {TEST_KEY_HOSTNAME}, which means the request was \
             checked with Google's test secret -- any token, including none, would be \
             accepted. Refusing to treat this as a passed captcha."
        );
    }

    Ok(success)
}

/// The hostname Google returns for any verification made with its published test
/// secret, regardless of where the challenge was actually solved.
const TEST_KEY_HOSTNAME: &str = "testkey.google.com";
