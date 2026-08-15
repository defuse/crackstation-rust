//! Page definitions for the registry.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::{alias, page, PageInfo};

/// Registry for all pages on crackstation.net. Matches PHP's URLParse.php routes.
pub static PAGE_REGISTRY: LazyLock<HashMap<&'static str, PageInfo>> = LazyLock::new(|| {
    let pages: &[PageInfo] = &[
        // ===== Home page (PHP specifies no metadata — uses defaults) =====
        page! {
            handler: home,
            slug: "",
            title: "",
            description: "",
            keywords: "",
            legacy_hit_count_id: "pages/home.php",
        },

        // ===== Home page aliases =====
        alias!("index" => ""),

        // ===== Content pages (metadata matches PHP's URLParse.php exactly) =====
        page! {
            handler: hashing_security,
            slug: "hashing-security",
            title: "Secure Salted Password Hashing - How to do it Properly",
            description: "How to hash passwords properly using salt. Why hashes should be salted and how to use salt correctly.",
            keywords: "salt, salted hashing, secure password hashing, password hashing, proper way to hash passwords",
            legacy_hit_count_id: "pages/hashing-security.php",
        },
        page! {
            handler: hashing_security_draft,
            slug: "hashing-security-draft",
            title: "Secure Salted Password Hashing - How to do it Properly",
            description: "How to hash passwords properly using salt. Why hashes should be salted and how to use salt correctly.",
            keywords: "salt, salted hashing, secure password hashing, password hashing, proper way to hash passwords",
            legacy_hit_count_id: "pages/hashing-security-draft.php",
        },
        page! {
            handler: downloads,
            slug: "downloads",
            title: "CrackStation Tools & Downloads",
            description: "Free tools & Downloads provided by CrackStation",
            keywords: "hash tools, hash cracking, password cracking",
            legacy_hit_count_id: "pages/downloads.php",
        },
        page! {
            handler: contact,
            slug: "contact-us",
            title: "CrackStation Contact",
            description: "Instructions for contacting CrackStation",
            keywords: "crackstation contact",
            legacy_hit_count_id: "pages/contactus.php",
        },
        // NOTE: PHP has title "CrackStation Contact" and keywords "crackstation contact"
        // for this page too — appears to be a copy-paste error, but we match it exactly.
        page! {
            handler: about,
            slug: "about-us",
            title: "CrackStation Contact",
            description: "What CrackStation is and why we exist",
            keywords: "crackstation contact",
            legacy_hit_count_id: "pages/aboutus.php",
        },
        page! {
            handler: wordlist,
            slug: "crackstation-wordlist-password-cracking-dictionary",
            title: "CrackStation's Password Cracking Dictionary (Pay what you want!)",
            description: "Download CrackStation's password cracking wordlist.",
            keywords: "password cracking wordlist, biggest password cracking wordlist, cracking dictionary",
            legacy_hit_count_id: "pages/buy-crackstation-wordlist-cracking-dictionary.php",
        },

        // Legacy URL for the wordlist page, still linked from elsewhere.
        alias!(
            "buy-crackstation-wordlist-password-cracking-dictionary"
                => "crackstation-wordlist-password-cracking-dictionary"
        ),
        page! {
            handler: legal_privacy,
            slug: "legal-privacy",
            title: "CrackStation - Legal and Privacy",
            description: "CrackStation.net's privacy policy",
            keywords: "hash cracking legal, penetration testing, password security",
            legacy_hit_count_id: "pages/legal-privacy.php",
        },
        page! {
            handler: thank_you,
            slug: "thank-you",
            title: "Thanks!",
            description: "Donation Confirmation Page",
            keywords: "",
            legacy_hit_count_id: "pages/thank-you.php",
        },
        // The 404 page carries no metadata of its own, so it renders the site
        // defaults. PHP does the same, though by accident: ProcessURL() returns
        // the string "404", which is not a $PAGE_INFO key, so getPageTitle()
        // falls through to $DEFAULT_TITLE and the P_TITL "File Not Found" in
        // $FILE_NOT_FOUND is never read.
        page! {
            handler: not_found,
            slug: "404",
            title: "",
            description: "",
            keywords: "",
            legacy_hit_count_id: "pages/404.php",
        },
    ];

    let mut map = HashMap::new();
    for page in pages {
        let key = page.slug.to_lowercase();
        if map.contains_key(key.as_str()) {
            panic!("Duplicate page slug: {}", page.slug);
        }
        // Leak the key so it lives for 'static
        let key: &'static str = Box::leak(key.into_boxed_str());
        map.insert(key, page.clone());
    }
    map
});
