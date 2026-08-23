use ironclaw_memory_mnesis::{EndpointProfile, MnesisConfig, MnesisHttpTransport, MnesisLimits};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    url: String,
    profile: String,
    accepted: bool,
    why: String,
}

fn corpus() -> Corpus {
    let raw = include_str!("fixtures/url-validation-corpus.json");
    serde_json::from_str(raw).expect("the corpus fixture parses")
}

fn accepts(url: &str, profile: EndpointProfile) -> bool {
    let config = MnesisConfig {
        knowledge_endpoint: url.to_string(),
        memory_endpoint: url.to_string(),
        host_allowlist: Vec::new(),
        profile,
        limits: MnesisLimits::default(),
    };
    MnesisHttpTransport::new(&config, "knowledge-token", "memory-token").is_ok()
}

#[test]
fn every_corpus_case_matches_the_implemented_verdict() {
    let corpus = corpus();
    assert!(corpus.cases.len() >= 30, "the corpus must stay broad");

    for case in &corpus.cases {
        let profile = match case.profile.as_str() {
            "production" => EndpointProfile::Production,
            "loopback_development" => EndpointProfile::LoopbackDevelopment,
            other => panic!("unknown profile '{other}' for {}", case.url),
        };
        assert_eq!(
            accepts(&case.url, profile),
            case.accepted,
            "{} under {} expected accepted={} ({})",
            case.url,
            case.profile,
            case.accepted,
            case.why
        );
    }
}

#[test]
fn the_corpus_covers_every_always_blocked_address_family() {
    let corpus = corpus();
    let urls: Vec<&str> = corpus.cases.iter().map(|case| case.url.as_str()).collect();
    for required in [
        "https://169.254.169.254",
        "https://[::ffff:169.254.169.254]",
        "https://[fe80::1]",
        "https://224.0.0.1",
        "https://[ff02::1]",
        "https://0.0.0.0",
        "https://[::]",
    ] {
        assert!(urls.contains(&required), "corpus is missing {required}");
    }
}

#[test]
fn alternate_host_encodings_normalize_to_the_address_they_denote() {
    for loopback in [
        "https://2130706433",
        "https://0177.0.0.1",
        "https://0x7f000001",
    ] {
        assert!(
            accepts(loopback, EndpointProfile::Production),
            "{loopback} denotes 127.0.0.1, which is permitted over TLS"
        );
        assert!(
            accepts(
                &loopback.replace("https://", "http://"),
                EndpointProfile::LoopbackDevelopment
            ),
            "{loopback} denotes 127.0.0.1, so the loopback http exemption applies"
        );
        assert!(
            !accepts(
                &loopback.replace("https://", "http://"),
                EndpointProfile::Production
            ),
            "{loopback} is still loopback http, refused under the production profile"
        );
    }
}

#[test]
fn an_always_blocked_address_stays_blocked_in_every_encoding() {
    for metadata in [
        "https://169.254.169.254",
        "https://2852039166",
        "https://0251.0376.0251.0376",
        "https://[::ffff:169.254.169.254]",
    ] {
        assert!(
            !accepts(metadata, EndpointProfile::Production),
            "{metadata} denotes the cloud metadata address and must be refused"
        );
        assert!(
            !accepts(metadata, EndpointProfile::LoopbackDevelopment),
            "{metadata} must be refused under every profile"
        );
    }
}
