use std::sync::Arc;

use crate::libs::PhpCountService;
use preimage::PreimageOracle;

/// Production reCAPTCHA site key (domain-locked to crackstation.net).
pub(crate) const PRODUCTION_RECAPTCHA_SITE_KEY: &str = "6LcnNi8UAAAAALJikXrc6jwNWUm00Yjx_rHCJW7u";

/// Google's test site key — works on any domain including localhost.
/// https://developers.google.com/recaptcha/docs/faq#id-like-to-run-automated-tests-with-recaptcha.-what-should-i-do
const DEV_RECAPTCHA_SITE_KEY: &str = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";

/// Holds shared application state: hit counter and hash cracking oracle.
#[derive(Clone)]
pub struct AppState {
    pub phpcount: PhpCountService,
    pub oracle: Arc<PreimageOracle>,
    pub recaptcha_site_key: &'static str,
}

impl AppState {
    pub fn new(phpcount: PhpCountService, oracle: PreimageOracle, use_dev_recaptcha: bool) -> Self {
        Self {
            phpcount,
            oracle: Arc::new(oracle),
            recaptcha_site_key: site_key_for(use_dev_recaptcha),
        }
    }

    /// Whether the browser is being served Google's test site key.
    ///
    /// Verification needs this to read a verdict correctly: the same answer from
    /// Google's test secret is the expected development setup under the test site key
    /// and a silent bypass under the production one. Derived from the key actually
    /// served rather than kept as a second copy of the flag, so the two can never
    /// disagree about what the visitor saw.
    pub fn serves_test_site_key(&self) -> bool {
        is_test_site_key(self.recaptcha_site_key)
    }
}

/// The site key the browser is served for a given `USE_DEV_RECAPTCHA_KEY` setting.
fn site_key_for(use_dev_recaptcha: bool) -> &'static str {
    if use_dev_recaptcha {
        DEV_RECAPTCHA_SITE_KEY
    } else {
        PRODUCTION_RECAPTCHA_SITE_KEY
    }
}

/// Whether a site key is Google's test key.
fn is_test_site_key(site_key: &str) -> bool {
    site_key == DEV_RECAPTCHA_SITE_KEY
}

#[cfg(test)]
mod tests {
    use super::{
        is_test_site_key, site_key_for, DEV_RECAPTCHA_SITE_KEY, PRODUCTION_RECAPTCHA_SITE_KEY,
    };

    /// The two keys must differ, or `is_test_site_key` cannot tell them apart and every
    /// deployment would be read as development.
    #[test]
    fn the_dev_and_production_site_keys_are_distinct() {
        assert_ne!(DEV_RECAPTCHA_SITE_KEY, PRODUCTION_RECAPTCHA_SITE_KEY);
    }

    #[test]
    fn the_flag_selects_the_site_key() {
        assert_eq!(site_key_for(true), DEV_RECAPTCHA_SITE_KEY);
        assert_eq!(site_key_for(false), PRODUCTION_RECAPTCHA_SITE_KEY);
    }

    #[test]
    fn only_the_dev_key_is_recognized_as_the_test_key() {
        assert!(is_test_site_key(DEV_RECAPTCHA_SITE_KEY));
        assert!(!is_test_site_key(PRODUCTION_RECAPTCHA_SITE_KEY));
        assert!(!is_test_site_key(""));
    }

    /// What verification actually depends on: the answer must describe the key the
    /// visitor was served, so the two halves of the captcha cannot disagree.
    #[test]
    fn the_served_key_reports_its_own_kind() {
        assert!(is_test_site_key(site_key_for(true)));
        assert!(!is_test_site_key(site_key_for(false)));
    }
}
