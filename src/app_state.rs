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
            recaptcha_site_key: if use_dev_recaptcha {
                DEV_RECAPTCHA_SITE_KEY
            } else {
                PRODUCTION_RECAPTCHA_SITE_KEY
            },
        }
    }
}
