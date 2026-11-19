use core::str::FromStr;

use wildcard::{Wildcard, WildcardBuilder};

use crate::Error;

/// Maximum allowed length for a hostname (SNI / HTTP Host header), in bytes.
pub const HOSTNAME_MAX_LENGTH: usize = 255;

/// Normalized representation of a hostname shared by the TLS layer (SNI/certificate selection)
/// and the HTTP routing layer (Host header / service routes).
///
/// Normalization rules:
/// - ASCII only (internationalized domain names must be punycode-encoded by the client)
/// - lower-cased, because DNS hostnames are case-insensitive
/// - no userinfo, no port, no trailing dot
/// - bounded length, so the value can be stored in a `heapless::String`
///
/// Two hostnames refer to the same security identity only if their normalized forms are equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostIdentity {
    hostname: heapless::String<HOSTNAME_MAX_LENGTH>,
}

impl HostIdentity {
    /// Parses and normalizes a hostname coming from an untrusted source (TLS SNI or HTTP Host header).
    ///
    /// Returns an error for anything that does not unambiguously identify a single host:
    /// empty values, non-ASCII characters, userinfo, URI separators, invalid characters,
    /// malformed ports, oversized inputs or leading/trailing dots. A valid port suffix
    /// (HTTP `Host` header) is stripped instead of rejected.
    pub fn parse(raw_host: &str) -> Result<Self, Error> {
        let host = raw_host.trim();

        if host.is_empty() {
            return Err(Error::Tls("empty hostname".to_string()));
        }
        if !host.is_ascii() {
            return Err(Error::Tls(format!("hostname {host:?} is not ASCII (punycode required)")));
        }

        // reject anything that is not a bare hostname: userinfo, IP literals, URI separators
        if host.contains(['@', '[', ']', '/', '?', '#', ' ']) {
            return Err(Error::Tls(format!("hostname {host:?} contains invalid characters")));
        }

        // the HTTP Host header may carry a port; SNI never does. Strip a single, valid port suffix.
        let host = if let Some((hostname_part, port_part)) = host.rsplit_once(':') {
            if port_part.is_empty() || port_part.bytes().any(|byte| !byte.is_ascii_digit()) {
                return Err(Error::Tls(format!("hostname {host:?} has an invalid port")));
            }
            hostname_part
        } else {
            host
        };

        // a trailing dot is the DNS root label and must not be part of the identity comparison
        let host = host.trim_end_matches('.');
        if host.is_empty() || host.starts_with('.') || host.contains("..") {
            return Err(Error::Tls(format!("hostname {host:?} is not valid")));
        }

        if host.len() > HOSTNAME_MAX_LENGTH {
            return Err(Error::Tls(format!("hostname {host:?} exceeds {HOSTNAME_MAX_LENGTH} bytes")));
        }

        let normalized = host.to_ascii_lowercase();
        if normalized
            .bytes()
            .any(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_'))
        {
            return Err(Error::Tls(format!("hostname {host:?} contains invalid characters")));
        }

        let hostname = heapless::String::from_str(&normalized)
            .map_err(|err| Error::Tls(format!("hostname {host:?} is not valid: {err}")))?;

        return Ok(HostIdentity { hostname });
    }

    pub fn as_str(&self) -> &str {
        self.hostname.as_str()
    }

    /// Exact match against an already-normalized hostname (e.g. a certificate SAN).
    #[cfg(test)]
    pub fn matches_exact(&self, other: &str) -> bool {
        self.hostname.as_str() == other
    }

    /// Match against a DNS wildcard pattern such as `*.example.com`.
    ///
    /// The wildcard only replaces the left-most label, per RFC 6125:
    /// `*.example.com` matches `api.example.com` but not `a.b.example.com` or `example.com`.
    pub fn matches_wildcard(&self, wildcard_pattern: &str) -> bool {
        let Some(pattern_suffix) = wildcard_pattern.strip_prefix("*.") else {
            return false;
        };

        let hostname = self.hostname.as_str();
        let Some(prefix_with_dot) = hostname.strip_suffix(pattern_suffix) else {
            return false;
        };

        // `strip_suffix` leaves the separating dot attached to the prefix, e.g. "api." for
        // "api.example.com". The part matched by `*` must be a single, non-empty label.
        let matched_label = prefix_with_dot.strip_suffix('.').unwrap_or("");
        if matched_label.is_empty() || matched_label.contains('.') {
            return false;
        }

        return true;
    }
}

impl core::fmt::Display for HostIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.hostname.as_str())
    }
}

/// Builds the case-insensitive, single-label wildcard matchers used by the certificate store.
///
/// Unlike a raw `wildcard::Wildcard` over the whole SAN string, the pattern is constrained to the
/// left-most label (`*.example.com`) so that wildcards can never match across label boundaries.
pub fn build_wildcard_matcher(pattern: &str) -> Result<Wildcard<'static>, Error> {
    if !pattern.starts_with("*.") {
        return Err(Error::Tls(format!("TLS wildcard SAN {pattern:?} must start with '*.'")));
    }

    let matcher = WildcardBuilder::from_owned(pattern.to_ascii_lowercase().into_bytes())
        .case_insensitive(true)
        .without_one_metasymbol()
        .build()
        .map_err(|err| Error::Tls(format!("TLS hostname {pattern:?} is not valid: {err}")))?;

    return Ok(matcher);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let identity = HostIdentity::parse("API.Example.COM.").unwrap();
        assert_eq!(identity.as_str(), "api.example.com");
        assert!(identity.matches_exact("api.example.com"));
    }

    #[test]
    fn strips_ports_and_rejects_userinfo() {
        assert_eq!(HostIdentity::parse("example.com:443").unwrap().as_str(), "example.com");
        assert!(HostIdentity::parse("example.com:notaport").is_err());
        assert!(HostIdentity::parse("user@example.com").is_err());
        assert!(HostIdentity::parse("[2001:db8::1]").is_err());
        assert!(HostIdentity::parse("").is_err());
        assert!(HostIdentity::parse("example..com").is_err());
        assert!(HostIdentity::parse(".example.com").is_err());
        assert!(HostIdentity::parse("exa mple.com").is_err());
        assert!(HostIdentity::parse("example.com/").is_err());
    }

    #[test]
    fn wildcard_only_matches_single_leftmost_label() {
        let identity = HostIdentity::parse("api.example.com").unwrap();
        assert!(identity.matches_wildcard("*.example.com"));

        let nested = HostIdentity::parse("a.b.example.com").unwrap();
        assert!(!nested.matches_wildcard("*.example.com"));

        let apex = HostIdentity::parse("example.com").unwrap();
        assert!(!apex.matches_wildcard("*.example.com"));
    }

    #[test]
    fn sni_and_host_share_identity_only_when_normalized_forms_match() {
        let parse = |value| HostIdentity::parse(value).ok();
        assert_eq!(parse("API.Example.com"), parse("api.example.com:443"));
        assert_eq!(parse("api.example.com"), parse("api.example.com"));
        assert_ne!(parse("evil.example.org"), parse("api.example.com"));
        assert_ne!(None, parse("api.example.com"));
    }

    #[test]
    fn wildcard_builder_rejects_bare_star_and_non_wildcard_patterns() {
        // the legacy default certificate used a bare "*" SAN which must never be accepted
        assert!(build_wildcard_matcher("*").is_err());
        assert!(build_wildcard_matcher("example.com").is_err());
        assert!(build_wildcard_matcher("api.*.com").is_err());
        assert!(build_wildcard_matcher("*.example.com").is_ok());
    }
}
