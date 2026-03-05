//! Request context - extracted once per request, shared with all templates.

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
    pub captcha_bypass_header: Option<String>,
    /// Query string from the URL (without leading ?)
    pub query_string: Option<String>,
    /// URL prefix for building absolute URLs (e.g., "https://crackstation.net" or "http://localhost:3000")
    pub url_prefix: String,
}

impl PageContext {
    pub fn is_home(&self) -> bool {
        self.page_info.slug.is_empty()
    }
}
