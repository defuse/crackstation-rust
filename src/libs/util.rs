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
