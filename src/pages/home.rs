//! Home page handler — hash cracking form (GET) and crack submission (POST).

use askama::Template;
use axum::response::IntoResponse;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

use crate::app_state::AppState;
use crate::context::PageContext;
use crate::cracking::{self, CrackResult};
use crate::handler::{BoxFuture, PageHandler, PostBody};
use crate::libs;

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

    fn accepts_post(&self) -> bool {
        true
    }

    fn post(&self, ctx: PageContext, state: &AppState, body: PostBody) -> BoxFuture {
        let oracle = state.oracle.clone();
        let serves_test_site_key = state.serves_test_site_key();
        Box::pin(async move {
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
            if !is_captcha_bypassed(&ctx) {
                match libs::recaptcha::verify(
                    &recaptcha_response,
                    &ctx.client_ip,
                    serves_test_site_key,
                )
                .await
                {
                    Ok(true) => {} // passed
                    Ok(false) => {
                        return HomePage {
                            ctx,
                            results: None,
                            error: Some("Incorrect captcha. Please try again.".to_string()),
                            submitted_hashes: hashes_raw,
                        }
                        .into_response();
                    }
                    Err(e) => {
                        tracing::error!("reCAPTCHA verification failed: {:#}", e);
                        return HomePage {
                            ctx,
                            results: None,
                            error: Some(
                                "Could not verify captcha (server error). Please try again."
                                    .to_string(),
                            ),
                            submitted_hashes: hashes_raw,
                        }
                        .into_response();
                    }
                }
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
        })
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
    use crate::cracking::{CrackMatch, NearMiss};

    /// Helper: compute SHA256 hex digest of a string, same as `is_captcha_bypassed` does.
    fn sha256_hex(input: &str) -> String {
        hex::encode(Sha256::digest(input.as_bytes()))
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

    /// A payload exercising every character Askama's HTML escaper rewrites.
    const XSS: &str = r#"<script>alert('pwn&"you')</script>"#;
    /// What that payload must look like once escaped by Askama. Note `&#x27;` for the
    /// apostrophe: an approved, encoding-only divergence from PHP's `&#039;`.
    const XSS_ESCAPED: &str =
        "&lt;script&gt;alert(&#x27;pwn&amp;&quot;you&#x27;)&lt;/script&gt;";
    /// The plaintext cell is escaped by `html_escape::escape_text` instead, so that
    /// whitespace survives the table's collapsing context. That escaper is a port of
    /// defuse.ca's and emits PHP's `&#039;`. Same characters neutralised, one
    /// different spelling of the apostrophe entity.
    const XSS_ESCAPED_PLAINTEXT: &str =
        "&lt;script&gt;alert(&#039;pwn&amp;&quot;you&#039;)&lt;/script&gt;";

    fn home_context() -> PageContext {
        PageContext {
            // The home page is registered under the empty slug.
            page_info: crate::registry::lookup_page("").expect("home page must be registered"),
            client_ip: "192.0.2.1".to_string(),
            dnt_enabled: false,
            hit_counts: crate::libs::phpcount::HitCounts::default(),
            captcha_bypass_header: None,
            query_string: None,
            url_prefix: "https://crackstation.net".to_string(),
            recaptcha_site_key: crate::app_state::PRODUCTION_RECAPTCHA_SITE_KEY,
        }
    }

    /// Return the single rendered line containing `needle`, so the assertion can be an
    /// exact whole-line comparison rather than a substring probe.
    fn line_containing<'a>(html: &'a str, needle: &str) -> &'a str {
        let mut matching = html.lines().filter(|line| line.contains(needle));
        let line = matching
            .next()
            .unwrap_or_else(|| panic!("no rendered line contains {needle:?}"));
        assert!(
            matching.next().is_none(),
            "expected exactly one line containing {needle:?}"
        );
        line.trim()
    }

    /// Askama's automatic HTML escaping is this site's only defence against a wordlist
    /// entry -- assembled from public breach dumps -- executing script in the browser of
    /// whoever cracked it. Nothing else escapes, and a single `askama.toml` at the crate
    /// root would silently turn it off site-wide. Render every interpolation site on the
    /// results page with hostile input and assert on the exact bytes produced.
    #[test]
    fn every_interpolated_value_on_the_results_page_is_html_escaped() {
        let page = HomePage {
            ctx: home_context(),
            results: Some(vec![
                CrackResult {
                    hash: XSS.to_string(),
                    matches: vec![
                        CrackMatch {
                            plaintext: XSS.to_string(),
                            algorithm_name: XSS.to_string(),
                            near_miss: None,
                        },
                        CrackMatch {
                            plaintext: XSS.to_string(),
                            algorithm_name: XSS.to_string(),
                            near_miss: Some(NearMiss {
                                matched: XSS.to_string(),
                                rest: XSS.to_string(),
                            }),
                        },
                    ],
                    total_matches: 2,
                    format_error: false,
                },
                CrackResult {
                    hash: XSS.to_string(),
                    matches: Vec::new(),
                    total_matches: 0,
                    format_error: true,
                },
            ]),
            error: Some(XSS.to_string()),
            submitted_hashes: XSS.to_string(),
        };

        let html = page.render().expect("results page must render");

        // The raw payload must appear nowhere, in any context, at all.
        assert!(
            !html.contains(XSS),
            "the unescaped payload was rendered into the page"
        );
        assert!(
            !html.contains("<script>alert"),
            "an executable script tag reached the output"
        );

        // Exact output for each interpolation site.
        assert_eq!(
            line_containing(&html, "class=\"suc\""),
            format!("<tr class=\"suc\"><td>{XSS_ESCAPED}</td><td>{XSS_ESCAPED}</td><td>{XSS_ESCAPED_PLAINTEXT}</td></tr>"),
            "full-match row"
        );
        assert_eq!(
            line_containing(&html, "class=\"part\""),
            format!(
                "<tr class=\"part\"><td><span class=\"matched\">{XSS_ESCAPED}</span>{XSS_ESCAPED}</td>\
                 <td>{XSS_ESCAPED}</td><td>{XSS_ESCAPED_PLAINTEXT}</td></tr>"
            ),
            "partial-match row"
        );
        assert_eq!(
            line_containing(&html, "Unrecognized hash format."),
            format!("<tr class=\"fail\"><td>{XSS_ESCAPED}</td><td>Unknown</td><td>Unrecognized hash format.</td></tr>"),
            "format-error row"
        );
        assert_eq!(
            line_containing(&html, "<b>&lt;script"),
            format!("<b>{XSS_ESCAPED}</b>"),
            "error message"
        );
        assert_eq!(
            line_containing(&html, "</textarea>"),
            format!("name=\"hashes\" >{XSS_ESCAPED}</textarea>"),
            "the submission echoed back into the textarea"
        );
    }

    /// A password whose whitespace HTML would collapse must render so the user can
    /// read and copy it back exactly. Before this, "a  b" displayed as "a b" and
    /// " hunter2" lost its leading space -- indistinguishable from a different
    /// password, on the one cell whose whole job is to be copied.
    #[test]
    fn plaintext_whitespace_survives_the_table_cell() {
        for (plaintext, expected) in [
            ("a  b", "a &nbsp;b"),
            (" hunter2", "&nbsp;hunter2"),
            ("trailing ", "trailing&nbsp;"),
            // 5 spaces to the next tab stop, rendered as space-nbsp-space-nbsp-space
            // so the line can still break while showing all five columns.
            ("tab\there", "tab &nbsp; &nbsp; here"),
            ("plain", "plain"),
        ] {
            let page = HomePage {
                ctx: home_context(),
                results: Some(vec![CrackResult {
                    hash: "abc".to_string(),
                    matches: vec![CrackMatch {
                        plaintext: plaintext.to_string(),
                        algorithm_name: "md5".to_string(),
                        near_miss: None,
                    }],
                    total_matches: 1,
                    format_error: false,
                }]),
                error: None,
                submitted_hashes: String::new(),
            };

            let html = page.render().expect("must render");
            assert_eq!(
                line_containing(&html, "class=\"suc\""),
                format!("<tr class=\"suc\"><td>abc</td><td>md5</td><td>{expected}</td></tr>"),
                "plaintext {plaintext:?}"
            );
        }
    }

    /// A near-miss row shows the digest that word really produces, not the query, with
    /// the agreeing head marked. Without it a yellow row asserts a prefix matched and
    /// gives the reader no way to see how much, or what the word actually hashes to.
    #[test]
    fn a_near_miss_row_shows_the_real_hash_with_the_matched_prefix_marked() {
        let page = HomePage {
            ctx: home_context(),
            results: Some(vec![CrackResult {
                hash: "d0763edaa9d9bd2a0000000000000000".to_string(),
                matches: vec![CrackMatch {
                    plaintext: "monkey".to_string(),
                    algorithm_name: "md5".to_string(),
                    near_miss: Some(NearMiss {
                        matched: "d0763edaa9d9bd2a".to_string(),
                        rest: "9516280e9044d885".to_string(),
                    }),
                }],
                total_matches: 1,
                format_error: false,
            }]),
            error: None,
            submitted_hashes: String::new(),
        };

        let html = page.render().expect("must render");
        assert_eq!(
            line_containing(&html, "class=\"part\""),
            "<tr class=\"part\"><td><span class=\"matched\">d0763edaa9d9bd2a</span>9516280e9044d885</td>\
             <td>md5</td><td>monkey</td></tr>"
        );
        assert!(
            !html.contains("d0763edaa9d9bd2a0000000000000000"),
            "the query's wrong tail describes nothing and must not be shown as a digest"
        );
    }

    /// When a result set is capped the table must say so, with both numbers, rather
    /// than presenting the first twenty near misses as though they were all of them.
    #[test]
    fn a_truncated_result_set_says_how_much_is_hidden() {
        let page = HomePage {
            ctx: home_context(),
            results: Some(vec![CrackResult {
                hash: "abc".to_string(),
                matches: vec![CrackMatch {
                    plaintext: "shown".to_string(),
                    algorithm_name: "md5".to_string(),
                    near_miss: Some(NearMiss {
                        matched: "dead".to_string(),
                        rest: "beef".to_string(),
                    }),
                }],
                total_matches: 4096,
                format_error: false,
            }]),
            error: None,
            submitted_hashes: String::new(),
        };

        let html = page.render().expect("must render");
        assert_eq!(
            line_containing(&html, "class=\"more\""),
            "<tr class=\"more\"><td>abc</td><td>&nbsp;</td><td>4095 more not shown (of 4096 total).</td></tr>"
        );
    }

    /// An uncapped result set must not gain a row claiming nothing is hidden.
    #[test]
    fn an_untruncated_result_set_gets_no_extra_row() {
        let page = HomePage {
            ctx: home_context(),
            results: Some(vec![CrackResult {
                hash: "abc".to_string(),
                matches: vec![CrackMatch {
                    plaintext: "only".to_string(),
                    algorithm_name: "md5".to_string(),
                    near_miss: None,
                }],
                total_matches: 1,
                format_error: false,
            }]),
            error: None,
            submitted_hashes: String::new(),
        };

        let html = page.render().expect("must render");
        assert!(
            !html.contains("class=\"more\""),
            "no truncation row when nothing was truncated"
        );
    }

    /// The "Not found." row is the other arm of the results table and interpolates the
    /// submitted hash, so it needs escaping too.
    #[test]
    fn the_not_found_row_escapes_the_submitted_hash() {
        let page = HomePage {
            ctx: home_context(),
            results: Some(vec![CrackResult {
                hash: XSS.to_string(),
                matches: Vec::new(),
                total_matches: 0,
                format_error: false,
            }]),
            error: None,
            submitted_hashes: String::new(),
        };

        let html = page.render().expect("results page must render");

        assert!(!html.contains(XSS), "the unescaped payload was rendered");
        assert_eq!(
            line_containing(&html, "<td>Not found.</td>"),
            format!("<tr class=\"fail\"><td>{XSS_ESCAPED}</td><td>Unknown</td><td>Not found.</td></tr>"),
            "not-found row"
        );
    }
}
