//! CSRF protection via Origin/Referer header validation.
//! 
//! WARNING: This has not been audited, do not rely on it as a complete CSRF
//! defense without careful review.
//!
//! Ported unchanged from defuse-rust's src/libs/csrf.rs, which is the pattern
//! source for this project. Note what this is *not*: CORS headers cannot do this
//! job. A form POST of application/x-www-form-urlencoded is a CORS "simple
//! request", so no preflight happens -- the browser sends it, the server runs the
//! handler, and Access-Control-Allow-Origin only decides whether the *calling
//! page* may read the response. The side effect has already happened by then.
//! Refusing the request server-side, on Origin, is the control that actually
//! stops it.
//!
//! Rejects cross-origin POST requests by checking that the Origin header
//! (or Referer as fallback) matches the request's Host header. This prevents
//! malicious sites from submitting forms or AJAX requests on behalf of users.
//!
//! Modern browsers always send Origin on POST requests, so this is reliable.

use axum::http::HeaderMap;

use crate::middleware::url_canonicalization::{is_dev_host, MASTER_HOST};

/// Check if a POST request passes CSRF origin validation.
///
/// Returns `Ok(())` if the request is safe, or `Err(reason)` with a
/// human-readable rejection reason for logging.
///
/// Rules:
/// - If Origin is present, its host must match the request's Host header.
/// - If Origin is absent, Referer's host must match instead.
/// - If neither header is present, the request is rejected.
pub fn check_origin(headers: &HeaderMap) -> Result<(), &'static str> {
    let request_host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Try Origin first (preferred, always sent by modern browsers on POST)
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let origin_host = host_from_url(origin);
        return if hosts_match(origin_host, request_host) {
            Ok(())
        } else {
            Err("Origin header does not match Host")
        };
    }

    // Fall back to Referer
    if let Some(referer) = headers.get("referer").and_then(|v| v.to_str().ok()) {
        let referer_host = host_from_url(referer);
        return if hosts_match(referer_host, request_host) {
            Ok(())
        } else {
            Err("Referer header does not match Host")
        };
    }

    Err("Neither Origin nor Referer header present")
}

/// Extract the host (with port if present) from a URL string.
/// e.g. "https://crackstation.net/foo" -> "crackstation.net"
/// e.g. "https://localhost:3000/bar" -> "localhost:3000"
fn host_from_url(url: &str) -> &str {
    // Strip scheme
    let after_scheme = url
        .find("://")
        .map(|i| &url[i + 3..])
        .unwrap_or(url);
    // Take up to the first /
    let host_and_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    host_and_port
}

/// Check if the Origin host is valid for a request to the given Host.
///
/// Strips port numbers before comparing, since Origin may include a port
/// while Host may not (or vice versa). Both the canonical production host
/// and dev hosts are accepted.
///
/// SECURITY: The request Host must be an accepted host. Without this check,
/// a DNS rebinding attack could bypass CSRF protection: attacker.com points
/// to our IP, so both Host and Origin are attacker.com and would match.
fn hosts_match(origin_host: &str, request_host: &str) -> bool {
    // Reject requests to unknown hosts (prevents DNS rebinding)
    if !is_accepted_host(request_host) {
        return false;
    }

    let origin_name = strip_port(origin_host);
    let request_name = strip_port(request_host);

    // Origin matches the request host
    origin_name.eq_ignore_ascii_case(request_name)
        // Or origin is the master host (e.g. origin=crackstation.net, host=localhost:3000)
        || origin_name.eq_ignore_ascii_case(MASTER_HOST)
}

/// Check if a host (with port) is either the master host or a dev host
fn is_accepted_host(host: &str) -> bool {
    let name = strip_port(host);
    name.eq_ignore_ascii_case(MASTER_HOST) || is_dev_host(host)
}

/// Strip port from a host string: "localhost:3000" -> "localhost"
fn strip_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_host_from_url() {
        assert_eq!(host_from_url("https://crackstation.net/foo"), "crackstation.net");
        assert_eq!(host_from_url("http://localhost:3000/bar"), "localhost:3000");
        assert_eq!(host_from_url("https://crackstation.net"), "crackstation.net");
        assert_eq!(host_from_url("https://crackstation.net:443/path"), "crackstation.net:443");
    }

    #[test]
    fn test_matching_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("origin", HeaderValue::from_static("https://crackstation.net"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_matching_origin_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:3000"));
        headers.insert("origin", HeaderValue::from_static("http://localhost:3000"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_cross_origin_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("origin", HeaderValue::from_static("https://evil.com"));
        assert!(check_origin(&headers).is_err());
    }

    #[test]
    fn test_referer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("referer", HeaderValue::from_static("https://crackstation.net/about.htm"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_cross_origin_referer_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("referer", HeaderValue::from_static("https://evil.com/attack"));
        assert!(check_origin(&headers).is_err());
    }

    #[test]
    fn test_no_origin_or_referer_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        assert!(check_origin(&headers).is_err());
    }

    #[test]
    fn test_origin_preferred_over_referer() {
        // If Origin is present and matches, Referer is irrelevant
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("origin", HeaderValue::from_static("https://crackstation.net"));
        headers.insert("referer", HeaderValue::from_static("https://evil.com/attack"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("CrackStation.NET"));
        headers.insert("origin", HeaderValue::from_static("https://crackstation.net"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_port_mismatch_still_matches() {
        // Origin might say :443, Host might not include port
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("crackstation.net"));
        headers.insert("origin", HeaderValue::from_static("https://crackstation.net:443"));
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn test_dns_rebinding_rejected() {
        // Attacker points attacker.com at our IP. Browser sends both
        // Host: attacker.com and Origin: https://attacker.com — they match
        // each other but neither is an accepted host.
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("attacker.com"));
        headers.insert("origin", HeaderValue::from_static("https://attacker.com"));
        assert!(check_origin(&headers).is_err());
    }

    #[test]
    fn test_dns_rebinding_with_referer_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("attacker.com"));
        headers.insert("referer", HeaderValue::from_static("https://attacker.com/page"));
        assert!(check_origin(&headers).is_err());
    }
}
