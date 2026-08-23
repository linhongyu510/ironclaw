use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::MnesisError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointProfile {
    #[default]
    Production,
    LoopbackDevelopment,
}

pub(crate) fn check_endpoint(
    url: &str,
    profile: EndpointProfile,
    allowlist: &[String],
) -> Result<(), MnesisError> {
    let parsed = reqwest::Url::parse(url).map_err(|error| MnesisError::InvalidEndpoint {
        reason: error.to_string(),
    })?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(MnesisError::InvalidEndpoint {
            reason: format!("only http/https are allowed (got '{scheme}')"),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(MnesisError::InvalidEndpoint {
            reason: "must not embed credentials in the endpoint (userinfo is not allowed)"
                .to_string(),
        });
    }

    if parsed.fragment().is_some() {
        return Err(MnesisError::InvalidEndpoint {
            reason: "must not carry a fragment".to_string(),
        });
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| MnesisError::InvalidEndpoint {
            reason: "missing host".to_string(),
        })?;

    let normalized_host = host.trim_start_matches('[').trim_end_matches(']');
    let literal_ip = normalized_host.parse::<IpAddr>().ok();

    if let Some(ip) = literal_ip
        && is_always_blocked(&ip)
    {
        return Err(MnesisError::InvalidEndpoint {
            reason: format!("host '{host}' is not a permitted endpoint"),
        });
    }

    let loopback = literal_ip.map(|ip| ip.is_loopback()).unwrap_or_else(|| {
        normalized_host
            .trim_end_matches('.')
            .eq_ignore_ascii_case("localhost")
    });

    if scheme == "http" {
        if !loopback {
            return Err(MnesisError::InvalidEndpoint {
                reason: "plain http is only permitted to loopback; use https".to_string(),
            });
        }
        if profile != EndpointProfile::LoopbackDevelopment {
            return Err(MnesisError::InvalidEndpoint {
                reason: "loopback http requires the explicit development endpoint profile"
                    .to_string(),
            });
        }
    }

    if !allowlist.is_empty() && !allowlist_permits(host, allowlist) {
        return Err(MnesisError::InvalidEndpoint {
            reason: "host is not in the operator endpoint allowlist".to_string(),
        });
    }

    Ok(())
}

fn allowlist_permits(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowlist
        .iter()
        .any(|entry| entry.trim_end_matches('.').to_ascii_lowercase() == host)
}

// Private ranges are deliberately NOT blocked: the endpoint is operator
// configured, and an internally hosted Mnesis is a supported deployment. The
// control for narrowing that is `host_allowlist`, not this list. Link-local is
// blocked, which covers the cloud metadata address.
fn is_always_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_always_blocked(&IpAddr::V4(v4));
            }
            v6.is_unspecified() || v6.octets()[0] == 0xff || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_ALLOWLIST: &[String] = &[];

    fn production(url: &str) -> Result<(), MnesisError> {
        check_endpoint(url, EndpointProfile::Production, NO_ALLOWLIST)
    }

    fn development(url: &str) -> Result<(), MnesisError> {
        check_endpoint(url, EndpointProfile::LoopbackDevelopment, NO_ALLOWLIST)
    }

    #[test]
    fn accepts_https_endpoints() {
        production("https://mnesis.example.com/rar/mcp").unwrap();
        production("https://mnesis.example.com:8443/memory/mcp").unwrap();
    }

    #[test]
    fn rejects_remote_plain_http_under_every_profile() {
        production("http://mnesis.example.com").unwrap_err();
        development("http://mnesis.example.com").unwrap_err();
        development("http://10.0.0.5:3443").unwrap_err();
    }

    #[test]
    fn permits_loopback_http_only_under_the_development_profile() {
        development("http://127.0.0.1:3443/rar/mcp").unwrap();
        development("http://localhost:3443/rar/mcp").unwrap();
        development("http://[::1]:3443/rar/mcp").unwrap();
        production("http://127.0.0.1:3443/rar/mcp").unwrap_err();
        production("http://localhost:3443").unwrap_err();
    }

    #[test]
    fn accepts_loopback_https_under_both_profiles() {
        production("https://127.0.0.1:3443").unwrap();
        development("https://127.0.0.1:3443").unwrap();
    }

    #[test]
    fn rejects_always_blocked_literal_addresses() {
        for blocked in [
            "https://169.254.169.254",
            "https://[fe80::1]",
            "https://224.0.0.1",
            "https://0.0.0.0",
            "https://[::]",
            "https://[::ffff:169.254.169.254]",
        ] {
            production(blocked).unwrap_err();
            development(blocked).unwrap_err();
        }
    }

    #[test]
    fn rejects_embedded_credentials_without_echoing_them() {
        let error = production("https://operator:s3cr3t-token@mnesis.example.com").unwrap_err();
        assert!(matches!(error, MnesisError::InvalidEndpoint { .. }));
        assert!(!error.to_string().contains("s3cr3t-token"));
        production("https://operator@mnesis.example.com").unwrap_err();
    }

    #[test]
    fn rejects_non_http_schemes_and_fragments() {
        production("file:///etc/passwd").unwrap_err();
        production("ftp://mnesis.example.com").unwrap_err();
        production("https://mnesis.example.com/rar/mcp#frag").unwrap_err();
    }

    #[test]
    fn allowlist_is_authoritative_and_exact() {
        let allowlist = vec!["mnesis.example.com".to_string()];
        check_endpoint(
            "https://mnesis.example.com/rar/mcp",
            EndpointProfile::Production,
            &allowlist,
        )
        .unwrap();
        check_endpoint(
            "https://MNESIS.EXAMPLE.COM./rar/mcp",
            EndpointProfile::Production,
            &allowlist,
        )
        .unwrap();
        check_endpoint(
            "https://evil.example.com/rar/mcp",
            EndpointProfile::Production,
            &allowlist,
        )
        .unwrap_err();
        check_endpoint(
            "https://sub.mnesis.example.com/rar/mcp",
            EndpointProfile::Production,
            &allowlist,
        )
        .unwrap_err();
    }

    #[test]
    fn a_scheme_rejection_never_echoes_the_host_path_or_query() {
        let error = production("ftp://secret-host.internal/path?token=swordfish").unwrap_err();
        let rendered = error.to_string();
        assert!(!rendered.contains("secret-host.internal"));
        assert!(!rendered.contains("swordfish"));
    }

    #[test]
    fn a_blocked_address_names_the_host_but_never_the_path_or_query() {
        // Naming the refused host is the point of this message, and an operator
        // supplied literal address is not a secret. The path and query still
        // are, so they must not survive into the error.
        let error =
            production("https://169.254.169.254/latest/meta-data?token=swordfish").unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("169.254.169.254"));
        assert!(!rendered.contains("meta-data"));
        assert!(!rendered.contains("swordfish"));
    }

    #[test]
    fn private_ranges_stay_reachable_because_the_allowlist_is_the_control() {
        production("https://10.0.0.5/memory/mcp").unwrap();
        production("https://192.168.1.10:8443/rar/mcp").unwrap();
        let allowlist = vec!["mnesis.internal".to_string()];
        check_endpoint(
            "https://10.0.0.5/memory/mcp",
            EndpointProfile::Production,
            &allowlist,
        )
        .unwrap_err();
    }
}
