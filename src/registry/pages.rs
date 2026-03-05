//! Page definitions for the registry.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::{alias, page, PageInfo};

/// Registry for all pages on crackstation.net. Matches PHP's URLParse.php routes.
pub static PAGE_REGISTRY: LazyLock<HashMap<&'static str, PageInfo>> = LazyLock::new(|| {
    let pages: &[PageInfo] = &[
        // ===== Home page =====
        page! {
            handler: home,
            slug: "",
            title: "CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.",
            description: "CrackStation uses massive pre-computed lookup tables to crack password hashes. Free hash cracking. Supports MD5, SHA1, SHA256, NTLM, and more.",
            keywords: "crack, password, hash, md5, sha1, sha256, sha512, ntlm, lm, rainbow, table, online, free, lookup, decrypt",
            legacy_hit_count_id: "pages/home.php",
        },

        // ===== Home page aliases =====
        alias!("index" => ""),
        alias!("index.htm" => ""),
        alias!("index.html" => ""),
        alias!("index.php" => ""),

        // ===== Content pages =====
        page! {
            handler: hashing_security,
            slug: "hashing-security",
            title: "Salted Password Hashing - Doing it Right",
            description: "Salted Password Hashing - Doing it Right. A guide to properly implementing password hashing.",
            keywords: "password, hash, hashing, salted, security, how to, tutorial, guide, secure, bcrypt, scrypt, pbkdf2",
            legacy_hit_count_id: "pages/hashing-security.php",
        },
        page! {
            handler: downloads,
            slug: "downloads",
            title: "Downloads - CrackStation",
            description: "CrackStation downloads.",
            keywords: "",
            legacy_hit_count_id: "pages/downloads.php",
        },
        page! {
            handler: contact,
            slug: "contact-us",
            title: "Contact Us - CrackStation",
            description: "Contact CrackStation.",
            keywords: "",
            legacy_hit_count_id: "pages/contactus.php",
        },
        page! {
            handler: about,
            slug: "about-us",
            title: "About Us - CrackStation",
            description: "About CrackStation.",
            keywords: "",
            legacy_hit_count_id: "pages/aboutus.php",
        },
        page! {
            handler: wordlist,
            slug: "crackstation-wordlist-password-cracking-dictionary",
            title: "CrackStation's Password Cracking Dictionary (Pay What You Want!)",
            description: "CrackStation's password cracking wordlist. 1.5 billion passwords for download.",
            keywords: "wordlist, dictionary, password, cracking, download, free, large, big",
            legacy_hit_count_id: "pages/buy-crackstation-wordlist-cracking-dictionary.php",
        },
        page! {
            handler: legal_privacy,
            slug: "legal-privacy",
            title: "Terms of Service and Privacy Policy - CrackStation",
            description: "CrackStation Terms of Service and Privacy Policy.",
            keywords: "",
            legacy_hit_count_id: "pages/legal-privacy.php",
        },
        page! {
            handler: thank_you,
            slug: "thank-you",
            title: "Thank You! - CrackStation",
            description: "Thank you for your purchase!",
            keywords: "",
            legacy_hit_count_id: "pages/thank-you.php",
        },
        page! {
            handler: not_found,
            slug: "404",
            title: "Page Not Found - CrackStation",
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
