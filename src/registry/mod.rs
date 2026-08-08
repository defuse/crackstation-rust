//! Page Registry - Single source of truth for all pages and their metadata.
//!
//! This is the Rust equivalent of PHP's $PAGE_INFO array in URLParse.php.

mod pages;

pub use pages::PAGE_REGISTRY;

use crate::handler::PageHandler;

/// Information about a single page
pub struct PageInfo {
    /// The handler for this page (implements PageHandler trait).
    /// None for aliases (they redirect, don't render).
    pub handler: Option<&'static dyn PageHandler>,

    /// URL slug - the canonical name as it appears in URLs
    /// - Empty string "" = homepage (canonical URL is "/")
    /// - Otherwise = regular page (canonical URL is "/{slug}.htm")
    pub slug: &'static str,

    /// Page title (empty = use DEFAULT_TITLE)
    pub title: &'static str,

    /// Meta description (empty = use DEFAULT_META_DESCRIPTION)
    pub description: &'static str,

    /// Meta keywords (empty = use DEFAULT_META_KEYWORDS)
    pub keywords: &'static str,

    /// Legacy hit counter ID from PHP version.
    pub legacy_hit_count_id: &'static str,

    /// Redirect target - if Some, this page is an alias
    pub redirect: Option<&'static str>,
}

// Manual Clone implementation - needed because of dyn trait object
impl Clone for PageInfo {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler,
            slug: self.slug,
            title: self.title,
            description: self.description,
            keywords: self.keywords,
            legacy_hit_count_id: self.legacy_hit_count_id,
            redirect: self.redirect,
        }
    }
}

// Manual Debug implementation - dyn PageHandler doesn't implement Debug
impl std::fmt::Debug for PageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageInfo")
            .field("handler", &self.handler.map(|_| "<handler>"))
            .field("slug", &self.slug)
            .field("title", &self.title)
            .field("redirect", &self.redirect)
            .finish_non_exhaustive()
    }
}

/// Helper macro for defining alias pages (redirects)
macro_rules! alias {
    ($slug:expr => $target:expr) => {
        PageInfo {
            slug: $slug,
            redirect: Some($target),
            ..PageInfo::DEFAULT
        }
    };
}
pub(crate) use alias;

/// Helper macro for defining regular pages WITH a handler implementation.
macro_rules! page {
    (
        handler: $($handler:ident)::+,
        slug: $slug:expr,
        title: $title:expr,
        description: $description:expr,
        keywords: $keywords:expr,
        legacy_hit_count_id: $legacy_hit_count_id:expr
        $(,)?
    ) => {
        PageInfo {
            handler: Some(&crate::pages::$($handler)::+::Handler),
            slug: $slug,
            title: $title,
            description: $description,
            keywords: $keywords,
            legacy_hit_count_id: $legacy_hit_count_id,
            ..PageInfo::DEFAULT
        }
    };
}
pub(crate) use page;

impl PageInfo {
    /// Default values for all fields.
    pub const DEFAULT: Self = PageInfo {
        handler: None,
        slug: "",
        title: "",
        description: "",
        keywords: "",
        legacy_hit_count_id: "",
        redirect: None,
    };

    /// Get the relative URL path for this page
    pub fn relative_url(&self) -> String {
        if self.slug.is_empty() {
            "/".to_string()
        } else {
            format!("/{}.htm", self.slug)
        }
    }

    /// Get the page ID for PHPCount hit tracking
    pub fn hit_counter_id(&self) -> &'static str {
        self.legacy_hit_count_id
    }

    /// Get title, falling back to default if empty
    pub fn title_or_default(&self) -> &'static str {
        if self.title.is_empty() { DEFAULT_TITLE } else { self.title }
    }

    /// Get description, falling back to the site default if empty.
    ///
    /// PHP's `getPageMetaDescription` goes straight to the default when a page
    /// declares no description — it never substitutes the title.
    pub fn description_or_default(&self) -> &'static str {
        if self.description.is_empty() {
            DEFAULT_META_DESCRIPTION
        } else {
            self.description
        }
    }

    /// Get keywords, falling back to default if empty
    pub fn keywords_or_default(&self) -> &'static str {
        if self.keywords.is_empty() { DEFAULT_META_KEYWORDS } else { self.keywords }
    }
}

// Default metadata values (matching PHP's URLParse.php)
pub const DEFAULT_TITLE: &str = "CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.";
pub const DEFAULT_META_DESCRIPTION: &str = "Crackstation is the most effective hash cracking service. We crack: MD5, SHA1, SHA2, WPA, and much more...";
pub const DEFAULT_META_KEYWORDS: &str = "md5 cracking, sha1 cracking, hash cracking, password cracking";

/// Page info for the 404 Not Found page.
///
/// It declares no title or description, so the page renders the site defaults.
/// PHP does the same: ProcessURL() returns the string "404", which is not a
/// $PAGE_INFO key, so getPageTitle() falls through to $DEFAULT_TITLE and the
/// P_TITL "File Not Found" in $FILE_NOT_FOUND is never read.
pub static NOT_FOUND_PAGE_INFO: PageInfo = PageInfo {
    slug: "404",
    ..PageInfo::DEFAULT
};

/// Look up a page by name/slug (case-insensitive)
pub fn lookup_page(name: &str) -> Option<&'static PageInfo> {
    let lowercase = name.to_lowercase();
    PAGE_REGISTRY.get(lowercase.as_str()).map(|p| p as &'static PageInfo)
}

/// Result of resolving a URL path to a page
#[derive(Debug, Clone)]
pub enum PathLookupResult {
    /// Page found and URL is already canonical - serve it
    Canonical(&'static PageInfo),

    /// Page found but URL should redirect to canonical form
    Redirect {
        canonical_path: String,
    },

    /// Path is invalid or page not found - 404
    NotFound,
}

/// Resolve a URL path to a page, determining if a redirect is needed.
pub fn resolve_path(path: &str) -> PathLookupResult {
    // Handle root path and empty string -> home page
    if path == "/" || path.is_empty() {
        let page = lookup_page("").expect("home page must exist");
        let page = resolve_alias(page);
        let canonical = page.relative_url();
        return if path == canonical {
            PathLookupResult::Canonical(page)
        } else {
            PathLookupResult::Redirect { canonical_path: canonical }
        };
    }

    let path_without_slash = path.strip_prefix('/').unwrap_or(path);

    // If path ends with /, it's claiming to be a directory - crackstation has none
    if path_without_slash.ends_with('/') {
        return PathLookupResult::NotFound;
    }

    // Detect and strip .htm or .html extension (case-insensitive)
    let path_lower = path_without_slash.to_lowercase();
    let (name, _had_extension) = if path_lower.ends_with(".htm") {
        (&path_without_slash[..path_without_slash.len() - 4], true)
    } else if path_lower.ends_with(".html") {
        (&path_without_slash[..path_without_slash.len() - 5], true)
    } else {
        (path_without_slash, false)
    };

    // Reject invalid paths like "/.htm"
    if name.is_empty() || name.ends_with('/') {
        return PathLookupResult::NotFound;
    }

    let page = lookup_page(name);

    match page {
        Some(page) => {
            let page = resolve_alias(page);
            let canonical = page.relative_url();
            if path == canonical {
                PathLookupResult::Canonical(page)
            } else {
                PathLookupResult::Redirect { canonical_path: canonical }
            }
        }
        None => PathLookupResult::NotFound,
    }
}

/// Resolve alias chains to get the final target page
fn resolve_alias(page: &'static PageInfo) -> &'static PageInfo {
    if let Some(target) = page.redirect {
        let target_page = lookup_page(target).expect("BUG: redirect target must exist");
        resolve_alias(target_page)
    } else {
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PHP's $PAGE_INFO redirects this legacy URL to the wordlist page. Both the
    /// bare and .htm spellings must land on the canonical wordlist URL.
    #[test]
    fn test_wordlist_legacy_alias_redirects() {
        for path in [
            "/buy-crackstation-wordlist-password-cracking-dictionary",
            "/buy-crackstation-wordlist-password-cracking-dictionary.htm",
        ] {
            match resolve_path(path) {
                PathLookupResult::Redirect { canonical_path } => assert_eq!(
                    canonical_path, "/crackstation-wordlist-password-cracking-dictionary.htm",
                    "wrong redirect target for {}", path
                ),
                other => panic!("{} should redirect, got {:?}", path, other),
            }
        }
    }

    /// The 404 page declares no metadata, so it renders the site defaults —
    /// matching what PHP serves, where the "File Not Found" title is dead code.
    ///
    /// Asserts against NOT_FOUND_PAGE_INFO specifically, because that is the value
    /// registered_page_handler.rs renders for a miss; the "404" registry entry is
    /// a different object and checking it alone would prove nothing about output.
    #[test]
    fn test_not_found_page_uses_default_metadata() {
        assert_eq!(NOT_FOUND_PAGE_INFO.title_or_default(), DEFAULT_TITLE);
        assert_eq!(
            NOT_FOUND_PAGE_INFO.description_or_default(),
            DEFAULT_META_DESCRIPTION
        );
        assert_eq!(
            NOT_FOUND_PAGE_INFO.keywords_or_default(),
            DEFAULT_META_KEYWORDS
        );

        let registry_entry = lookup_page("404").expect("404 page must be registered");
        assert_eq!(registry_entry.title_or_default(), DEFAULT_TITLE);
        assert_eq!(
            registry_entry.description_or_default(),
            DEFAULT_META_DESCRIPTION
        );
    }

    /// A page with a title but no description takes the site default description,
    /// not its own title. PHP's getPageMetaDescription has no title fallback.
    #[test]
    fn test_missing_description_uses_default_not_title() {
        let page = PageInfo {
            title: "Some Page Title",
            ..PageInfo::DEFAULT
        };
        assert_eq!(page.description_or_default(), DEFAULT_META_DESCRIPTION);
    }

    #[test]
    fn test_home_page_exists() {
        assert!(lookup_page("").is_some());
    }

    #[test]
    fn test_case_insensitive_lookup() {
        assert!(lookup_page("about-us").is_some());
        assert!(lookup_page("About-Us").is_some());
        assert!(lookup_page("ABOUT-US").is_some());
    }

    #[test]
    fn test_resolve_path_canonical() {
        assert!(matches!(resolve_path("/"), PathLookupResult::Canonical(_)));
        assert!(matches!(resolve_path("/about-us.htm"), PathLookupResult::Canonical(_)));
    }

    #[test]
    fn test_resolve_path_redirects_missing_extension() {
        match resolve_path("/about-us") {
            PathLookupResult::Redirect { canonical_path } => {
                assert_eq!(canonical_path, "/about-us.htm");
            }
            other => panic!("Expected Redirect, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_path_redirects_html_to_htm() {
        match resolve_path("/about-us.html") {
            PathLookupResult::Redirect { canonical_path } => {
                assert_eq!(canonical_path, "/about-us.htm");
            }
            other => panic!("Expected Redirect, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_path_redirects_wrong_case() {
        match resolve_path("/About-Us.HTM") {
            PathLookupResult::Redirect { canonical_path } => {
                assert_eq!(canonical_path, "/about-us.htm");
            }
            other => panic!("Expected Redirect, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_path_index_alias() {
        match resolve_path("/index") {
            PathLookupResult::Redirect { canonical_path } => {
                assert_eq!(canonical_path, "/");
            }
            other => panic!("Expected Redirect for /index, got {:?}", other),
        }

        match resolve_path("/index.htm") {
            PathLookupResult::Redirect { canonical_path } => {
                assert_eq!(canonical_path, "/");
            }
            other => panic!("Expected Redirect for /index.htm, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_path_not_found() {
        assert!(matches!(resolve_path("/nonexistent"), PathLookupResult::NotFound));
        assert!(matches!(resolve_path("/nonexistent.htm"), PathLookupResult::NotFound));
        assert!(matches!(resolve_path("/.htm"), PathLookupResult::NotFound));
    }
}
