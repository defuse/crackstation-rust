//! Shared utility functions.

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trusted proxy IPs that are allowed to set forwarding headers.
/// Only connections from these IPs will have forwarding headers trusted.
const TRUSTED_PROXIES: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
];

/// How many proxies of our own sit between the internet and this process.
///
/// DEPLOYMENT CONTRACT, and load-bearing for the correctness of `client_ip`. Exactly
/// one: Caddy terminates TLS and reverse-proxies to loopback, and the container
/// publishes only Caddy's ports, so nothing else can reach this process. Put a second
/// proxy or a CDN in front without raising this number and the address below becomes
/// attacker-chosen again -- silently, because a spoofed value looks exactly like a real
/// one.
const TRUSTED_HOPS: usize = 1;

/// Whether a peer address is one of our own proxies.
///
/// Canonicalises first, which is load-bearing rather than tidy. A socket bound to `[::]`
/// accepts IPv4 connections and reports their peer as an IPv4-mapped address:
/// `::ffff:127.0.0.1`, which is not equal to `127.0.0.1` and matches nothing in
/// `TRUSTED_PROXIES`. The forwarding headers would then be ignored on every request,
/// `is_https` would be false for all of them, and the HTTPS-enforcement redirect would
/// bounce each one straight back to a proxy that forwards it again -- an infinite 301
/// loop taking the whole site down, with every visitor collapsed onto one identity for
/// good measure.
///
/// `LISTEN_ADDR` is environment-configurable while this list is not, so that outage was
/// one character of deployment config away and nothing anywhere said so. `to_canonical`
/// maps the v4-mapped form back to plain IPv4 and removes the trap.
fn is_trusted_proxy(connection_ip: IpAddr) -> bool {
    TRUSTED_PROXIES.contains(&connection_ip.to_canonical())
}

/// The client address, as vouched for by our own proxy.
///
/// `X-Forwarded-For` is a chain that each hop *appends* to, so it arrives as
/// `<whatever the requester sent>, <what hop 1 saw>, ... <what hop n saw>`. Only the
/// entries our own proxies appended mean anything; everything to their left is chosen
/// by the requester. Caddy appends (as do Apache's `mod_proxy` and the documented nginx
/// idiom), so the useful element is the `TRUSTED_HOPS`-th from the *right*. Taking the
/// leftmost -- which this function used to do -- returns precisely the attacker's half.
///
/// Checking the peer address is necessary but not sufficient on its own: the peer being
/// our proxy says nothing about whether it vouched for the header *contents*. Counting
/// in from the right is what makes the value trustworthy, and it is correct whether the
/// proxy appends or overwrites.
///
/// `X-Real-IP` is deliberately not consulted. Caddy does not set it, so behind this
/// deployment a value in it can only have come from the requester.
///
/// Returning `IpAddr` rather than `String` is what keeps arbitrary header text out of
/// database keys, reverse-DNS lookups and third-party API fields: a chain that is
/// absent, too short or unparseable falls back to the peer address rather than being
/// passed along as-is.
pub fn client_ip(connection_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
    let connection_ip = connection_ip.to_canonical();

    if !is_trusted_proxy(connection_ip) {
        // Direct connection - use the actual peer, ignore any headers.
        return connection_ip;
    }

    // Repeated header lines are equivalent to one comma-joined line (RFC 9110 5.3), and
    // `get_all` is what makes them visible -- `get` returns only the first, so a client
    // sending its own line could otherwise hide the proxy's.
    let chain: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .collect();

    match chain
        .iter()
        .rev()
        .nth(TRUSTED_HOPS - 1)
        .and_then(|element| element.trim().parse::<IpAddr>().ok())
    {
        Some(ip) => ip,
        None if chain.is_empty() => {
            // Nothing in front of us: the peer really is the client. This is the local
            // development case -- `cargo run` with no proxy -- so it is not a warning,
            // or every request would log one.
            tracing::debug!("no X-Forwarded-For from a loopback peer; using the peer address");
            connection_ip
        }
        None => {
            // A chain arrived but the position our proxy owns is missing or malformed.
            // Nothing here is attacker-reachable behind a proxy that appends, so this
            // means the proxy is misconfigured -- and every visitor is about to share
            // one identity. Say so.
            tracing::warn!(
                "X-Forwarded-For from a trusted peer yielded no address {} hop(s) from the \
                 right ({} element(s) present); falling back to the peer address. Every \
                 request will share one identity until the proxy is fixed.",
                TRUSTED_HOPS,
                chain.len(),
            );
            connection_ip
        }
    }
}

/// Determine if the request was made over HTTPS by checking X-Forwarded-Proto.
///
/// SECURITY: Only trusts X-Forwarded-Proto when the connection comes from a
/// trusted proxy IP, to prevent clients from spoofing the protocol.
pub fn is_https(connection_ip: IpAddr, headers: &HeaderMap) -> bool {
    if is_trusted_proxy(connection_ip) {
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

    /// An IP-address literal, for comparing against what `client_ip` returns.
    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("test address must parse")
    }

    /// The ordinary case: our proxy appended the peer it saw, and nothing else is there.
    #[test]
    fn trusted_proxy_uses_the_address_the_proxy_appended() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), ip("198.51.100.42"));
    }

    /// The attack this function exists to stop. A requester who sends their own
    /// `X-Forwarded-For` stays *leftmost* once the proxy appends, so the leftmost
    /// element -- which this code used to return -- is the attacker's choice. Only the
    /// entry our own proxy added may be believed.
    #[test]
    fn a_client_supplied_chain_does_not_displace_what_the_proxy_appended() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, 10.0.0.1, 203.0.113.9".parse().unwrap(),
        );
        assert_eq!(
            client_ip(LOCALHOST_V4, &headers),
            ip("203.0.113.9"),
            "the rightmost element is the only one our proxy vouched for"
        );
    }

    /// `HeaderMap::get` returns only the first line, so a requester sending its own
    /// header line could hide the proxy's if the whole chain were not read.
    #[test]
    fn a_second_header_line_cannot_hide_the_proxys_line() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.42".parse().unwrap());
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), ip("203.0.113.9"));
    }

    /// `X-Real-IP` is not set by our proxy, so anything in it came from the requester.
    #[test]
    fn x_real_ip_is_ignored_entirely() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        assert_eq!(
            client_ip(LOCALHOST_V4, &headers),
            LOCALHOST_V4,
            "an unforgeable fallback beats a forgeable header"
        );
    }

    #[test]
    fn x_real_ip_cannot_override_the_forwarded_chain() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), ip("203.0.113.9"));
    }

    #[test]
    fn trusted_proxy_no_headers_uses_connection_ip() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip(LOCALHOST_V4, &headers), LOCALHOST_V4);
    }

    #[test]
    fn trusted_proxy_ipv6_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V6, &headers), ip("203.0.113.9"));
    }

    /// An IPv6 client is written bare into the chain and must survive the round trip.
    #[test]
    fn an_ipv6_client_address_parses() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "2001:db8::dead:beef".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), ip("2001:db8::dead:beef"));
    }

    // ---- client_ip: values that are not addresses ----

    /// The header admits any visible ASCII. Returning it unparsed put arbitrary text
    /// into a database key and a third-party API field; now it cannot leave this
    /// function at all.
    #[test]
    fn a_chain_that_is_not_an_address_falls_back_to_the_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), LOCALHOST_V4);
    }

    #[test]
    fn a_long_junk_value_falls_back_to_the_peer() {
        let junk = "A".repeat(2048);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", junk.parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), LOCALHOST_V4);
    }

    /// A trailing comma leaves an empty rightmost element. It is still the position the
    /// proxy owns, so nothing further left may be promoted into its place.
    #[test]
    fn an_empty_rightmost_element_does_not_promote_the_one_before_it() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42,".parse().unwrap());
        assert_eq!(client_ip(LOCALHOST_V4, &headers), LOCALHOST_V4);
    }

    /// Whitespace around elements is normal in a chain and is not part of the address.
    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "10.0.0.1,   203.0.113.9  ".parse().unwrap(),
        );
        assert_eq!(client_ip(LOCALHOST_V4, &headers), ip("203.0.113.9"));
    }

    // ---- client_ip: address families ----

    /// A socket bound to `[::]` reports an IPv4 peer as `::ffff:127.0.0.1`. Our own
    /// proxy must still be recognised through that form, or every request is treated as
    /// untrusted and the site redirect-loops itself off the internet.
    #[test]
    fn an_ipv4_mapped_proxy_is_still_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());

        assert_eq!(
            client_ip(ip("::ffff:127.0.0.1"), &headers),
            ip("203.0.113.9"),
            "the v4-mapped form of loopback is the same proxy"
        );
    }

    /// The peer we fall back to is reported in its canonical form, so one client does
    /// not become two identities depending on which socket family accepted it.
    #[test]
    fn a_mapped_peer_falls_back_to_its_canonical_form() {
        assert_eq!(
            client_ip(ip("::ffff:127.0.0.1"), &HeaderMap::new()),
            LOCALHOST_V4
        );
    }

    #[test]
    fn a_mapped_untrusted_peer_is_reported_canonically() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());

        assert_eq!(client_ip(ip("::ffff:203.0.113.50"), &headers), EXTERNAL_IP);
    }

    /// Canonicalisation must not widen the trusted set: a v4-mapped address that is not
    /// loopback is still an outsider.
    #[test]
    fn canonicalising_does_not_trust_anything_new() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());

        for peer in ["::ffff:203.0.113.50", "::ffff:10.0.0.1", "2001:db8::1"] {
            assert_eq!(
                client_ip(ip(peer), &headers),
                ip(peer).to_canonical(),
                "{peer} must not be treated as our proxy"
            );
        }
    }

    /// is_https reads the same trust decision, so it inherits the same trap.
    #[test]
    fn is_https_trusts_an_ipv4_mapped_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());

        assert!(is_https(ip("::ffff:127.0.0.1"), &headers));
        assert!(!is_https(ip("::ffff:203.0.113.50"), &headers));
    }

    // ---- client_ip: untrusted source ----

    #[test]
    fn untrusted_source_ignores_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(EXTERNAL_IP, &headers), EXTERNAL_IP);
    }

    #[test]
    fn untrusted_source_ignores_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.42".parse().unwrap());
        assert_eq!(client_ip(EXTERNAL_IP, &headers), EXTERNAL_IP);
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
