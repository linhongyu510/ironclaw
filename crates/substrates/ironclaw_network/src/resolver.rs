use std::net::{IpAddr, ToSocketAddrs};

use ironclaw_host_api::action::{NetworkPolicy, NetworkTarget};

use crate::{error::NetworkHttpError, policy::is_private_or_loopback_ip, url_target::default_port};

pub trait NetworkResolver: Send + Sync {
    fn resolve_ips(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, NetworkHttpError>;

    /// Whether the deployment operator has named this exact host as one allowed
    /// to resolve inside a private range. Defaults to `false`, so a resolver
    /// that does not opt in keeps the private-address denial intact.
    fn permits_private_ip(&self, _host: &str) -> bool {
        false
    }
}

/// The private-host allowlist is deployment-owned: it is supplied where the
/// resolver is constructed, never from a manifest, so an extension cannot name
/// a private target for itself.
#[derive(Debug, Clone, Default)]
pub struct SystemNetworkResolver {
    private_host_allowlist: Vec<String>,
}

impl SystemNetworkResolver {
    pub fn with_private_host_allowlist(hosts: Vec<String>) -> Self {
        Self {
            private_host_allowlist: hosts
                .into_iter()
                .map(|host| normalize_host(&host))
                .filter(|host| !host.is_empty())
                .collect(),
        }
    }
}

/// Compares on the bracket-free, dot-trimmed, lowercased host so an operator
/// writes an entry the way they write the address, not the way a URL spells it.
fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

impl NetworkResolver for SystemNetworkResolver {
    fn permits_private_ip(&self, host: &str) -> bool {
        let host = normalize_host(host);
        !host.is_empty() && self.private_host_allowlist.contains(&host)
    }

    fn resolve_ips(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        (host, port)
            .to_socket_addrs()
            .map_err(|error| NetworkHttpError::Dns {
                reason: error.to_string(),
                request_bytes: 0,
                response_bytes: 0,
            })
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
    }
}

pub(crate) fn resolve_public_ips<R>(
    target: &NetworkTarget,
    policy: &NetworkPolicy,
    resolver: &R,
    request_bytes: u64,
) -> Result<Vec<IpAddr>, NetworkHttpError>
where
    R: NetworkResolver,
{
    let resolved_ips = if let Ok(ip) = target.host.parse::<IpAddr>() {
        vec![ip]
    } else {
        let port = target.port.unwrap_or_else(|| default_port(target.scheme));
        resolver
            .resolve_ips(&target.host, port)
            .map_err(|error| NetworkHttpError::Dns {
                reason: error.to_string(),
                request_bytes,
                response_bytes: error.response_bytes(),
            })?
    };
    if resolved_ips.is_empty() {
        return Err(NetworkHttpError::Dns {
            reason: "network target did not resolve to any IP addresses".to_string(),
            request_bytes,
            response_bytes: 0,
        });
    }
    if policy.deny_private_ip_ranges
        && resolved_ips.iter().copied().any(is_private_or_loopback_ip)
        && !resolver.permits_private_ip(&target.host)
    {
        tracing::debug!(
            target: "ironclaw_network",
            host = %target.host,
            "resolver denied a private target; host is not in the private-host allowlist"
        );
        return Err(NetworkHttpError::PolicyDenied {
            reason: "network target resolves to a private or host-local IP".to_string(),
            request_bytes,
            response_bytes: 0,
        });
    }
    Ok(resolved_ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::action::NetworkScheme;

    struct PrivateResolver;

    impl NetworkResolver for PrivateResolver {
        fn resolve_ips(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
            Ok(vec!["100.107.146.125".parse().expect("literal ip")])
        }
    }

    fn denying_policy() -> NetworkPolicy {
        NetworkPolicy {
            allowed_targets: Vec::new(),
            deny_private_ip_ranges: true,
            max_egress_bytes: None,
        }
    }

    fn target(host: &str) -> NetworkTarget {
        NetworkTarget {
            scheme: NetworkScheme::Https,
            host: host.to_string(),
            port: None,
        }
    }

    #[test]
    fn a_resolver_that_does_not_opt_in_keeps_denying_private_targets() {
        let error = resolve_public_ips(
            &target("mnesis.test"),
            &denying_policy(),
            &PrivateResolver,
            0,
        )
        .expect_err("private target is denied");
        assert!(matches!(error, NetworkHttpError::PolicyDenied { .. }));
    }

    #[test]
    fn the_default_system_resolver_permits_no_private_host() {
        assert!(!SystemNetworkResolver::default().permits_private_ip("mnesis.test"));
    }

    #[test]
    fn an_allowlisted_host_resolves_despite_the_private_range() {
        struct Allowed(SystemNetworkResolver);
        impl NetworkResolver for Allowed {
            fn resolve_ips(&self, _h: &str, _p: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
                Ok(vec!["100.107.146.125".parse().expect("literal ip")])
            }
            fn permits_private_ip(&self, host: &str) -> bool {
                self.0.permits_private_ip(host)
            }
        }
        let resolver = Allowed(SystemNetworkResolver::with_private_host_allowlist(vec![
            "mnesis.test".to_string(),
        ]));
        let ips = resolve_public_ips(&target("mnesis.test"), &denying_policy(), &resolver, 0)
            .expect("allowlisted host resolves");
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn the_allowlist_is_exact_and_does_not_admit_a_sibling_host() {
        let resolver =
            SystemNetworkResolver::with_private_host_allowlist(vec!["mnesis.test".to_string()]);
        assert!(resolver.permits_private_ip("mnesis.test"));
        assert!(!resolver.permits_private_ip("evil-mnesis.test"));
        assert!(!resolver.permits_private_ip("mnesis.test.attacker.example"));
        assert!(!resolver.permits_private_ip("sub.mnesis.test"));
    }

    #[test]
    fn allowlist_matching_normalizes_case_trailing_dot_and_brackets() {
        let resolver = SystemNetworkResolver::with_private_host_allowlist(vec![
            "  MNESIS.Test.  ".to_string(),
            "[fd00::1]".to_string(),
        ]);
        assert!(resolver.permits_private_ip("mnesis.test"));
        assert!(resolver.permits_private_ip("MNESIS.TEST."));
        assert!(resolver.permits_private_ip("fd00::1"));
        assert!(resolver.permits_private_ip("[fd00::1]"));
    }

    #[test]
    fn a_blank_allowlist_entry_never_matches_a_blank_host() {
        let resolver = SystemNetworkResolver::with_private_host_allowlist(vec![
            String::new(),
            "   ".to_string(),
        ]);
        assert!(!resolver.permits_private_ip(""));
        assert!(!resolver.permits_private_ip("   "));
        assert!(!resolver.permits_private_ip("mnesis.test"));
    }
}
