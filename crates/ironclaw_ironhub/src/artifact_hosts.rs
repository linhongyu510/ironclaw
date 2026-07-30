use ironclaw_host_api::action::{NetworkPolicy, NetworkScheme, NetworkTargetPattern};

const IRONHUB_ARTIFACT_HOSTS: &[&str] = &[
    "hub.ironclaw.com",
    "github.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "raw.githubusercontent.com",
];
const IRONHUB_ARTIFACT_HOST_SUFFIX: &str = ".githubusercontent.com";

pub(crate) fn is_allowed_artifact_host(host: &str) -> bool {
    IRONHUB_ARTIFACT_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
        || host
            .to_ascii_lowercase()
            .ends_with(IRONHUB_ARTIFACT_HOST_SUFFIX)
}

pub fn artifact_network_policy() -> NetworkPolicy {
    let mut allowed_targets = IRONHUB_ARTIFACT_HOSTS
        .iter()
        .map(|host| NetworkTargetPattern {
            scheme: Some(NetworkScheme::Https),
            host_pattern: (*host).to_string(),
            port: None,
        })
        .collect::<Vec<_>>();
    allowed_targets.push(NetworkTargetPattern {
        scheme: Some(NetworkScheme::Https),
        host_pattern: format!("*{IRONHUB_ARTIFACT_HOST_SUFFIX}"),
        port: None,
    });
    NetworkPolicy {
        allowed_targets,
        deny_private_ip_ranges: true,
        max_egress_bytes: None,
    }
}
