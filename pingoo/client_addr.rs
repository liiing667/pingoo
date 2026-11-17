use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;

/// Trusted proxies are the IP ranges (CIDR) of the proxies / load balancers
/// that are allowed to set the `X-Forwarded-For` header.
/// `X-Forwarded-For` headers coming from any other peer are ignored.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Vec<IpNetwork>,
}

impl TrustedProxies {
    pub fn new(networks: Vec<IpNetwork>) -> Self {
        return TrustedProxies { networks };
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        return self.networks.iter().any(|network| network.contains(ip));
    }

    pub fn is_empty(&self) -> bool {
        return self.networks.is_empty();
    }
}

/// The result of resolving the address of a client, computed once per connection / request
/// and shared by the rules engine, GeoIP lookups, logs and proxying.
#[derive(Clone, Debug)]
pub struct ClientAddrDetermination {
    /// The address of the direct TCP peer.
    pub socket_addr: SocketAddr,
    /// The resolved address of the client.
    /// Fails closed to `socket_addr` whenever the proxy chain is unknown or malformed.
    pub client_addr: SocketAddr,
    /// The verified `X-Forwarded-For` entries, in received order, vouched for by trusted
    /// proxies (the resolved client and the trusted hops behind it).
    /// Entries claimed by untrusted clients are stripped.
    pub forwarded_chain: Vec<IpAddr>,
}

/// Resolve the real address of a client from the address of the direct TCP peer and the
/// `X-Forwarded-For` headers of the request, according to the listener's trusted proxies.
///
/// The resolution fails closed: if the peer is not trusted, if the chain contains a malformed
/// entry, or if the whole chain is composed of trusted proxies (the client is unknown),
/// the peer address is used and the forwarded chain is discarded.
pub fn resolve_client_addr(
    peer: SocketAddr,
    x_forwarded_for: &[&str],
    trusted_proxies: &TrustedProxies,
) -> ClientAddrDetermination {
    let fail_closed = || ClientAddrDetermination {
        socket_addr: peer,
        client_addr: peer,
        forwarded_chain: Vec::new(),
    };

    // only trusted peers are allowed to set X-Forwarded-For
    if trusted_proxies.is_empty() || !trusted_proxies.is_trusted(peer.ip()) {
        return fail_closed();
    }

    // parse all the entries of the chain. A single malformed entry poisons the whole chain.
    let mut entries: Vec<IpAddr> = Vec::new();
    for header_value in x_forwarded_for {
        for entry in header_value.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<IpAddr>() {
                Ok(ip) => entries.push(ip),
                Err(_) => return fail_closed(),
            }
        }
    }

    // walk the chain from the closest hop to the furthest, skipping trusted proxies.
    // The first untrusted entry is the client. Entries on its left are claims made by
    // the (untrusted) client itself and are stripped.
    return match entries.iter().rposition(|ip| !trusted_proxies.is_trusted(*ip)) {
        Some(client_index) => ClientAddrDetermination {
            socket_addr: peer,
            client_addr: SocketAddr::new(entries[client_index], peer.port()),
            forwarded_chain: entries[client_index..].to_vec(),
        },
        // the chain is empty or only contains trusted proxies: the client is unknown, fail closed
        None => fail_closed(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_proxies(cidrs: &[&str]) -> TrustedProxies {
        let networks = cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNetwork>().expect("valid CIDR"))
            .collect();
        return TrustedProxies::new(networks);
    }

    fn peer(ip: &str) -> SocketAddr {
        return format!("{ip}:4321").parse().expect("valid socket address");
    }

    fn ip(addr: &str) -> IpAddr {
        return addr.parse().expect("valid IP address");
    }

    #[test]
    fn no_trusted_proxies_ignores_x_forwarded_for() {
        let determination = resolve_client_addr(peer("10.0.0.1"), &["203.0.113.10"], &TrustedProxies::default());
        assert_eq!(determination.client_addr, peer("10.0.0.1"));
        assert!(determination.forwarded_chain.is_empty());
    }

    #[test]
    fn untrusted_peer_ignores_x_forwarded_for() {
        let determination = resolve_client_addr(peer("203.0.113.10"), &["1.1.1.1"], &trusted_proxies(&["10.0.0.0/8"]));
        assert_eq!(determination.client_addr, peer("203.0.113.10"));
        assert!(determination.forwarded_chain.is_empty());
    }

    #[test]
    fn trusted_peer_resolves_client() {
        let determination = resolve_client_addr(peer("10.0.0.1"), &["203.0.113.10"], &trusted_proxies(&["10.0.0.0/8"]));
        assert_eq!(determination.client_addr, peer("203.0.113.10"));
        assert_eq!(determination.forwarded_chain, vec![ip("203.0.113.10")]);
    }

    #[test]
    fn trusted_peer_skips_trusted_hops() {
        let determination =
            resolve_client_addr(peer("10.0.0.1"), &["203.0.113.10, 10.0.0.2"], &trusted_proxies(&["10.0.0.0/8"]));
        assert_eq!(determination.client_addr, peer("203.0.113.10"));
        assert_eq!(determination.forwarded_chain, vec![ip("203.0.113.10"), ip("10.0.0.2")]);
    }

    #[test]
    fn spoofed_entries_on_the_left_are_stripped() {
        let determination = resolve_client_addr(
            peer("10.0.0.1"),
            &["1.1.1.1, 203.0.113.10, 10.0.0.2"],
            &trusted_proxies(&["10.0.0.0/8"]),
        );
        assert_eq!(determination.client_addr, peer("203.0.113.10"));
        assert_eq!(determination.forwarded_chain, vec![ip("203.0.113.10"), ip("10.0.0.2")]);
    }

    #[test]
    fn chain_with_only_trusted_proxies_fails_closed() {
        let determination =
            resolve_client_addr(peer("10.0.0.1"), &["10.0.0.2, 10.0.0.3"], &trusted_proxies(&["10.0.0.0/8"]));
        assert_eq!(determination.client_addr, peer("10.0.0.1"));
        assert!(determination.forwarded_chain.is_empty());
    }

    #[test]
    fn malformed_entry_fails_closed() {
        let determination = resolve_client_addr(
            peer("10.0.0.1"),
            &["203.0.113.10, not-an-ip"],
            &trusted_proxies(&["10.0.0.0/8"]),
        );
        assert_eq!(determination.client_addr, peer("10.0.0.1"));
        assert!(determination.forwarded_chain.is_empty());
    }

    #[test]
    fn empty_chain_fails_closed() {
        let determination = resolve_client_addr(peer("10.0.0.1"), &[], &trusted_proxies(&["10.0.0.0/8"]));
        assert_eq!(determination.client_addr, peer("10.0.0.1"));
        assert!(determination.forwarded_chain.is_empty());
    }

    #[test]
    fn multiple_header_values_are_joined() {
        let determination = resolve_client_addr(
            peer("10.0.0.1"),
            &["203.0.113.10", "10.0.0.2"],
            &trusted_proxies(&["10.0.0.0/8"]),
        );
        assert_eq!(determination.client_addr, peer("203.0.113.10"));
        assert_eq!(determination.forwarded_chain, vec![ip("203.0.113.10"), ip("10.0.0.2")]);
    }

    #[test]
    fn ipv6_entries_are_supported() {
        let determination =
            resolve_client_addr(peer("[fd00::1]"), &["2001:db8::42, fd00::2"], &trusted_proxies(&["fd00::/8"]));
        assert_eq!(determination.client_addr, peer("[2001:db8::42]"));
        assert_eq!(determination.forwarded_chain, vec![ip("2001:db8::42"), ip("fd00::2")]);
    }
}
