//! Home page handler — hash cracking form (GET) and crack submission (POST).

use askama::Template;
use axum::response::IntoResponse;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

use crate::app_state::AppState;
use crate::context::PageContext;
use crate::cracking::{self, CrackResult};
use crate::handler::{BoxFuture, PageHandler, PostBody};

pub struct Handler;

impl PageHandler for Handler {
    fn get(&self, ctx: PageContext, _state: &AppState) -> BoxFuture {
        Box::pin(async move {
            HomePage {
                ctx,
                results: None,
                error: None,
                submitted_hashes: String::new(),
            }
            .into_response()
        })
    }

    fn post(&self, ctx: PageContext, state: &AppState, body: PostBody) -> Option<BoxFuture> {
        let oracle = state.oracle.clone();
        Some(Box::pin(async move {
            let form_data = form_urlencoded::parse(&body.0).collect::<Vec<_>>();

            let hashes_raw = form_data
                .iter()
                .find(|(k, _)| k == "hashes")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();

            let recaptcha_response = form_data
                .iter()
                .find(|(k, _)| k == "g-recaptcha-response")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();

            // Check captcha: either verify with Google or accept bypass header
            let captcha_ok = if is_captcha_bypassed(&ctx) {
                true
            } else {
                verify_recaptcha(&recaptcha_response, &ctx.client_ip).await
            };

            if !captcha_ok {
                return HomePage {
                    ctx,
                    results: None,
                    error: Some("Incorrect captcha. Please try again.".to_string()),
                    submitted_hashes: hashes_raw,
                }
                .into_response();
            }

            // Parse hashes: normalize line endings, split, trim, filter empty
            let normalized = hashes_raw.replace("\r\n", "\n").replace('\r', "\n");
            let hashes: Vec<String> = normalized
                .split('\n')
                .map(|h| h.trim().trim_matches('*').to_string())
                .filter(|h| !h.is_empty())
                .collect();

            if hashes.len() > 20 {
                return HomePage {
                    ctx,
                    results: None,
                    error: Some("Please enter 20 or less hashes.".to_string()),
                    submitted_hashes: hashes_raw,
                }
                .into_response();
            }

            if hashes.is_empty() {
                return HomePage {
                    ctx,
                    results: None,
                    error: None,
                    submitted_hashes: hashes_raw,
                }
                .into_response();
            }

            let results = cracking::crack_hashes(&oracle, &hashes);

            HomePage {
                ctx,
                results: Some(results),
                error: None,
                submitted_hashes: hashes_raw,
            }
            .into_response()
        }))
    }
}

/// SHA256 hash of the captcha bypass key (stored in crackstation-tester/secrets/captcha-bypass-key.txt).
/// To recompute: printf '%s' "$(cat crackstation-tester/secrets/captcha-bypass-key.txt)" | sha256sum
const CAPTCHA_BYPASS_KEY_HASH: &str = "37eea42865627aaa4a298cbdae055021298906e2a069983d15ea046e3846edea";

/// Check if the captcha bypass header contains the correct key.
///
/// SECURITY: The server only stores the SHA256 hash of the key. The raw key
/// lives only in the tester's gitignored secrets/ directory. Comparison uses
/// constant-time equality to prevent timing attacks.
fn is_captcha_bypassed(ctx: &PageContext) -> bool {
    let bypass_header = match &ctx.captcha_bypass_header {
        Some(h) => h,
        None => return false,
    };

    let received_hash = hex::encode(Sha256::digest(bypass_header.as_bytes()));
    received_hash.as_bytes().ct_eq(CAPTCHA_BYPASS_KEY_HASH.as_bytes()).into()
}

/// Verify reCAPTCHA response with Google's API.
async fn verify_recaptcha(token: &str, remote_ip: &str) -> bool {
    let secret = match std::env::var("RECAPTCHA_SECRET_KEY") {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("RECAPTCHA_SECRET_KEY not set");
            return false;
        }
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", token),
            ("remoteip", remote_ip),
        ])
        .send()
        .await;

    match resp {
        Ok(r) => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => json["success"].as_bool().unwrap_or(false),
                Err(e) => {
                    tracing::error!("Failed to parse reCAPTCHA response: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            tracing::error!("reCAPTCHA verification request failed: {}", e);
            false
        }
    }
}

#[derive(Template)]
#[template(path = "pages/home.html")]
struct HomePage {
    ctx: PageContext,
    results: Option<Vec<CrackResult>>,
    error: Option<String>,
    submitted_hashes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute SHA256 hex digest of a string, same as `is_captcha_bypassed` does.
    fn sha256_hex(input: &str) -> String {
        hex::encode(Sha256::digest(input.as_bytes()))
    }

    /// Read the actual bypass key from the tester's secrets directory and verify
    /// that its SHA256 matches the compiled-in constant.
    #[test]
    fn correct_key_matches_compiled_hash() {
        let key_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .join("crackstation-tester/secrets/captcha-bypass-key.txt");
        let key = std::fs::read_to_string(&key_file)
            .unwrap_or_else(|e| panic!(
                "Cannot read {}: {}. Generate with: xxd -l 32 -p /dev/urandom | tr -d '\\n' > {}",
                key_file.display(), e, key_file.display()
            ))
            .trim()
            .to_string();

        assert_eq!(
            sha256_hex(&key),
            CAPTCHA_BYPASS_KEY_HASH,
            "SHA256 of the key file does not match CAPTCHA_BYPASS_KEY_HASH — \
             regenerate the constant with: printf '%s' \"$(cat {})\" | sha256sum",
            key_file.display()
        );
    }

    /// A wrong key must not match the compiled hash.
    #[test]
    fn wrong_key_does_not_match() {
        let wrong_key = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_ne!(
            sha256_hex(wrong_key),
            CAPTCHA_BYPASS_KEY_HASH,
            "An obviously wrong key should not match CAPTCHA_BYPASS_KEY_HASH"
        );
    }

    /// Empty header must not bypass captcha.
    #[test]
    fn empty_key_does_not_match() {
        assert_ne!(
            sha256_hex(""),
            CAPTCHA_BYPASS_KEY_HASH,
            "Empty string should not match CAPTCHA_BYPASS_KEY_HASH"
        );
    }
}
