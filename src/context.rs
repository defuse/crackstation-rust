//! Request context - extracted once per request, shared with all templates.

use std::fmt;

use crate::libs::phpcount::HitCounts;
use crate::registry::PageInfo;

#[derive(Debug, Clone)]
/// PageContext contains all per-request data needed by templates: page
/// metadata, client info, and hit counts. Constructed by registered_page_handler.
pub struct PageContext {
    /// PageInfo holds all the page metadata (title, keywords, description, etc.)
    pub page_info: &'static PageInfo,
    pub client_ip: String,
    pub dnt_enabled: bool,
    pub hit_counts: HitCounts,
    /// CAPTCHA bypass header (256-bit secret) for automated testing
    pub captcha_bypass_header: Option<BypassSecret>,
    /// Query string from the URL (without leading ?)
    pub query_string: Option<String>,
    /// URL prefix for building absolute URLs (e.g., "https://crackstation.net" or "http://localhost:3000")
    pub url_prefix: String,
    /// reCAPTCHA site key for the client-side widget
    pub recaptcha_site_key: &'static str,
}

impl PageContext {
    pub fn is_home(&self) -> bool {
        self.page_info.slug.is_empty()
    }
}

/// The captcha bypass header, carried so that printing it does not disclose it.
///
/// `PageContext` derives `Debug`, and this field is a 256-bit shared secret that grants
/// captcha bypass to anyone holding it. Any `{:?}` of the context -- a `tracing` field, a
/// panic message, a debugger -- would have written it wherever that output goes. The
/// redaction lives on the value rather than on `PageContext`'s `Debug` impl so that it
/// travels with the secret, and so that a future field added to the context cannot
/// silently reintroduce the leak.
#[derive(Clone)]
pub struct BypassSecret(String);

impl BypassSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret itself. Named so that call sites reading it are easy to find.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BypassSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BypassSecret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::BypassSecret;

    const SECRET: &str = "3f8a1c0b9e7d6a5f4c3b2a1908172635445362718091a2b3c4d5e6f708192a3b";

    /// The whole point: no formatting of this value may contain it.
    #[test]
    fn debug_output_does_not_contain_the_secret() {
        let secret = BypassSecret::new(SECRET.to_string());

        assert_eq!(format!("{secret:?}"), "BypassSecret([redacted])");
        assert!(!format!("{secret:?}").contains(SECRET));
    }

    /// It must still be readable, or the bypass stops working.
    #[test]
    fn the_secret_is_still_available_to_code_that_asks() {
        assert_eq!(BypassSecret::new(SECRET.to_string()).expose(), SECRET);
    }

    /// The leak this exists to stop is the *containing* struct being printed, so check
    /// that path rather than only the field in isolation.
    #[test]
    fn debug_of_an_option_of_it_does_not_contain_the_secret() {
        let held = Some(BypassSecret::new(SECRET.to_string()));

        assert_eq!(format!("{held:?}"), "Some(BypassSecret([redacted]))");
        assert!(!format!("{held:?}").contains(SECRET));
    }
}
