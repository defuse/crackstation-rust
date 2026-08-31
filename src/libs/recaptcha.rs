//! reCAPTCHA verification — centralized helper matching defuse-rust's pattern.
//!
//! Returns `Ok(true)` when the user passed, `Ok(false)` when the user failed,
//! and `Err(...)` when infrastructure is broken (network, config, parsing).
//! This distinction prevents misconfiguration or outages from being silently
//! swallowed as "bad captcha."

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};

/// How long a single verification may take, end to end.
///
/// reqwest applies no timeout of its own, so without this a slow or blackholed
/// connection parks the handler forever. That is not merely a slow captcha: the request
/// is holding one of `MAX_CONCURRENT_REQUESTS` admission slots while it waits, so an
/// unreachable Google consumes the admission budget and takes down pages that never
/// touch the captcha. Ten seconds is generous for an overloaded Google and still bounds
/// the failure.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the TCP + TLS handshake may take, inside the overall budget above.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest token worth sending to Google.
///
/// reCAPTCHA v2 tokens run roughly 500-2000 characters. The form field is unbounded
/// otherwise, so whatever arrives gets re-uploaded to Google -- the requester chooses
/// how many bytes the server sends and how long it holds a slot doing so. 8 KB is four
/// times the top of the observed range, which leaves room for a future token format
/// while removing the amplification.
const MAX_TOKEN_LEN: usize = 8 * 1024;

/// The ceiling must stay well clear of real token sizes, or a future format change
/// would silently start failing every captcha. v2 tokens top out around 2000 bytes, so
/// require at least four times that. Enforced at compile time rather than by a test,
/// because a value that is too small breaks the site rather than a test run.
const _: () = assert!(MAX_TOKEN_LEN >= 4 * 2000);

/// Most of Google's answer we will read.
///
/// A siteverify response is a couple of hundred bytes of JSON. Reading it with no bound
/// means anything able to answer for that host -- Google on a bad day, or whoever holds
/// the connection if TLS is ever terminated elsewhere -- can hand back as much as it
/// likes and have it buffered.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The shared HTTP client, built once.
///
/// A fresh `Client` per request meant a fresh connection pool and a fresh DNS
/// resolution every time. `getaddrinfo` is a blocking-pool draw, on the same pool whose
/// re-entrant use `MAX_CONCURRENT_REQUESTS` exists to bound -- so the per-request client
/// was quietly adding a second draw to every captcha check.
pub fn http_client() -> &'static reqwest::Client {
    static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(VERIFY_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("failed to build the reCAPTCHA HTTP client")
    })
}

/// Whether a token is worth spending a network round trip on.
///
/// An absent or oversized token is a failed captcha, decided here rather than by Google,
/// so neither costs an outbound request.
fn is_plausible_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_TOKEN_LEN
}

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
    if !is_plausible_token(token) {
        tracing::warn!(
            "captcha token was absent or implausible ({} bytes, limit {}); rejected without \
             asking Google",
            token.len(),
            MAX_TOKEN_LEN,
        );
        return Ok(false);
    }

    let secret = std::env::var("RECAPTCHA_SECRET_KEY")
        .expect("RECAPTCHA_SECRET_KEY must be set (validated at startup)");

    let mut resp = http_client()
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", token),
            ("remoteip", remote_ip),
        ])
        .send()
        .await
        .context("reCAPTCHA verification request failed")?;

    let body = read_bounded(&mut resp).await?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).context("failed to parse reCAPTCHA response JSON")?;

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

/// Read at most `MAX_RESPONSE_BYTES` of a response body.
///
/// Streams rather than trusting `Content-Length`, which may be absent or wrong, and
/// errors instead of truncating -- a clipped body would parse as a failed captcha and
/// blame the visitor for an infrastructure problem.
async fn read_bounded(resp: &mut reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    while let Some(chunk) = resp
        .chunk()
        .await
        .context("reading the reCAPTCHA response failed")?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "reCAPTCHA response exceeded {MAX_RESPONSE_BYTES} bytes; refusing to buffer it"
            );
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
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
    use super::{is_bypass_signature, is_plausible_token, MAX_TOKEN_LEN, TEST_KEY_HOSTNAME};

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

    /// A real v2 token sits well inside the ceiling.
    #[test]
    fn a_normal_token_is_worth_asking_google_about() {
        assert!(is_plausible_token(&"a".repeat(500)));
        assert!(is_plausible_token(&"a".repeat(2000)));
    }

    /// An absent token is a failed captcha, not a question for Google. Deciding it here
    /// is what stops a bare POST loop from costing an outbound request each time.
    #[test]
    fn an_absent_token_is_rejected_without_a_round_trip() {
        assert!(!is_plausible_token(""));
    }

    /// The amplification this bound exists for: whatever arrives in the form field is
    /// what gets re-uploaded to Google.
    #[test]
    fn an_oversized_token_is_rejected_without_a_round_trip() {
        assert!(!is_plausible_token(&"a".repeat(MAX_TOKEN_LEN + 1)));
        assert!(!is_plausible_token(&"a".repeat(1024 * 1024)));
    }

    /// Exactly at the ceiling is still sent -- the bound is a limit, not a margin.
    #[test]
    fn a_token_at_the_ceiling_is_still_sent() {
        assert!(is_plausible_token(&"a".repeat(MAX_TOKEN_LEN)));
    }
}
