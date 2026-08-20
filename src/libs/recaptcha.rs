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
/// `serves_test_site_key` says which site key the browser was given, which decides
/// whether a verdict from Google's test secret is the expected development setup or a
/// silent bypass -- see `is_bypass_signature`.
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
pub async fn verify(token: &str, remote_ip: &str, serves_test_site_key: bool) -> Result<bool> {
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

    if is_bypass_signature(hostname, serves_test_site_key) {
        anyhow::bail!(
            "reCAPTCHA verified against {TEST_KEY_HOSTNAME} while the browser was served the \
             production site key, which means the request was checked with Google's test \
             secret -- any token, including none, would be accepted. Refusing to treat this \
             as a passed captcha."
        );
    }

    Ok(success)
}

/// Whether a verdict proves the secret in use validates anything at all.
///
/// Google reports `testkey.google.com` as the hostname for every verification made with
/// its published test secret, whatever domain the challenge was actually solved on. What
/// that means depends entirely on which site key the browser was served:
///
/// * With the matching *test* site key it is expected and harmless. The visitor sees
///   Google's "for testing purposes only" banner, so the site is visibly open rather
///   than deceptively so, and the pairing is the local-development configuration
///   `check_captcha_config` warns about but deliberately allows. Rejecting it here would
///   make the sanctioned dev setup unable to pass a captcha at all.
/// * With the *production* site key it is the signature of a total bypass: the visitor
///   solves a genuine challenge, and the server accepts any token, including none.
///   Startup refuses to boot on that pairing, so seeing it at request time means the
///   secret changed underneath a running process -- it is re-read from the environment
///   on every call.
///
/// Only the second case is an error, and a hard one rather than a failed captcha, so it
/// is logged as infrastructure breakage instead of shown to a visitor as their mistake.
fn is_bypass_signature(hostname: Option<&str>, serves_test_site_key: bool) -> bool {
    hostname == Some(TEST_KEY_HOSTNAME) && !serves_test_site_key
}

/// The hostname Google returns for any verification made with its published test
/// secret, regardless of where the challenge was actually solved.
const TEST_KEY_HOSTNAME: &str = "testkey.google.com";

#[cfg(test)]
mod tests {
    use super::{is_bypass_signature, TEST_KEY_HOSTNAME};

    /// The dangerous cell: a genuine challenge verified by a secret that accepts
    /// anything. This is the only combination that may be refused.
    #[test]
    fn a_test_secret_verdict_under_the_production_site_key_is_a_bypass() {
        assert!(is_bypass_signature(Some(TEST_KEY_HOSTNAME), false));
    }

    /// The sanctioned development pairing. Refusing it would leave the documented
    /// local setup unable to pass a captcha at all.
    #[test]
    fn a_test_secret_verdict_under_the_test_site_key_is_expected() {
        assert!(!is_bypass_signature(Some(TEST_KEY_HOSTNAME), true));
    }

    /// A real domain means a real secret answered, whichever site key was served.
    #[test]
    fn a_real_hostname_is_never_a_bypass() {
        assert!(!is_bypass_signature(Some("crackstation.net"), false));
        assert!(!is_bypass_signature(Some("crackstation.net"), true));
    }

    /// Google omits the hostname on a failed verification, which is a plain `false`
    /// verdict, not evidence about the secret.
    #[test]
    fn an_absent_hostname_is_never_a_bypass() {
        assert!(!is_bypass_signature(None, false));
        assert!(!is_bypass_signature(None, true));
    }
}
