//! Shared utility functions.

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trusted proxy IPs that are allowed to set X-Forwarded-For / X-Real-IP headers.
/// Only connections from these IPs will have forwarding headers trusted.
const TRUSTED_PROXIES: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
];

/// Extract the client IP address from connection info and headers.
///
/// If the connection is from a trusted proxy (localhost), checks X-Forwarded-For
/// and X-Real-IP headers. Otherwise, uses the actual connection IP.
///
/// SECURITY: Forwarding headers are only trusted from TRUSTED_PROXIES to prevent
/// IP spoofing from direct connections.
pub fn client_ip(connection_ip: IpAddr, headers: &HeaderMap) -> String {
    if TRUSTED_PROXIES.contains(&connection_ip) {
        // Check X-Forwarded-For first (standard proxy header)
        let forwarded_ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string());

        // Check X-Real-IP as fallback
        let forwarded_ip = forwarded_ip.or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });

        // Use forwarded IP if available, otherwise connection IP
        forwarded_ip.unwrap_or_else(|| connection_ip.to_string())
    } else {
        // Direct connection - use actual connection IP, ignore any headers
        connection_ip.to_string()
    }
}

/// Determine if the request was made over HTTPS by checking X-Forwarded-Proto.
///
/// SECURITY: Only trusts X-Forwarded-Proto when the connection comes from a
/// trusted proxy IP, to prevent clients from spoofing the protocol.
pub fn is_https(connection_ip: IpAddr, headers: &HeaderMap) -> bool {
    if TRUSTED_PROXIES.contains(&connection_ip) {
        headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .map(|p| p == "https")
            .unwrap_or(false)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    const LOCALHOST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    const EXTERNAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));

    // ---- client_ip: trusted proxy ----

    #[test]
    fn trusted_proxy_uses_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), "198.51.100.42");
    }

    #[test]
    fn trusted_proxy_uses_first_ip_in_x_forwarded_for_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, 10.0.0.1, 192.168.1.1".parse().unwrap(),
        );
        assert_eq!(client_ip(LOCALHOST_V4, &headers), "198.51.100.42");
    }

    #[test]
    fn trusted_proxy_falls_back_to_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), "198.51.100.99");
    }

    #[test]
    fn trusted_proxy_prefers_x_forwarded_for_over_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), "198.51.100.42");
    }

    #[test]
    fn trusted_proxy_no_headers_uses_connection_ip() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip(LOCALHOST_V4, &headers), "127.0.0.1");
    }

    #[test]
    fn trusted_proxy_ipv6_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V6, &headers), "198.51.100.42");
    }

    // ---- client_ip: untrusted source ----

    #[test]
    fn untrusted_source_ignores_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(EXTERNAL_IP, &headers), "203.0.113.50");
    }

    #[test]
    fn untrusted_source_ignores_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(EXTERNAL_IP, &headers), "203.0.113.50");
    }

    // ---- is_https: trusted proxy ----

    #[test]
    fn trusted_proxy_https_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(is_https(LOCALHOST_V4, &headers));
    }

    #[test]
    fn trusted_proxy_http_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!is_https(LOCALHOST_V4, &headers));
    }

    #[test]
    fn trusted_proxy_no_proto_header() {
        let headers = HeaderMap::new();
        assert!(!is_https(LOCALHOST_V4, &headers));
    }

    // ---- is_https: untrusted source ----

    #[test]
    fn untrusted_source_ignores_x_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(!is_https(EXTERNAL_IP, &headers));
    }
}
