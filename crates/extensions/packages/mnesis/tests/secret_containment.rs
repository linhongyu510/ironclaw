use ironclaw_memory_mnesis::{
    EndpointProfile, MnesisConfig, MnesisError, MnesisHttpTransport, MnesisLimits, SecretHandle,
};

const CREDENTIAL: &str = "mnesis-canary-bearer-a1b2c3d4e5f6";

fn config() -> MnesisConfig {
    MnesisConfig {
        knowledge_endpoint: "https://mnesis.example.com/rar/mcp".to_string(),
        memory_endpoint: "https://mnesis.example.com/memory/mcp".to_string(),
        knowledge_credential: SecretHandle::new("services/rar-clients").unwrap(),
        memory_credential: SecretHandle::new("services/memory-clients").unwrap(),
        host_allowlist: Vec::new(),
        profile: EndpointProfile::Production,
        limits: MnesisLimits::default(),
    }
}

#[test]
fn the_transport_debug_impl_renders_neither_the_credential_nor_its_client() {
    let transport = MnesisHttpTransport::new(&config(), CREDENTIAL, CREDENTIAL).unwrap();
    let rendered = format!("{transport:?}");
    assert!(!rendered.contains(CREDENTIAL), "{rendered}");
    assert!(!rendered.contains("Bearer"), "{rendered}");
    assert!(!rendered.contains("client"), "{rendered}");
    assert!(rendered.contains("mnesis.example.com"));
}

#[test]
fn the_alternate_debug_form_is_also_clean() {
    let transport = MnesisHttpTransport::new(&config(), CREDENTIAL, CREDENTIAL).unwrap();
    let rendered = format!("{transport:#?}");
    assert!(!rendered.contains(CREDENTIAL), "{rendered}");
}

#[test]
fn config_carries_a_handle_and_never_material_in_any_rendering() {
    let config = config();
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        assert!(!rendered.contains(CREDENTIAL), "{rendered}");
        assert!(!rendered.contains("Bearer"), "{rendered}");
        assert!(rendered.contains("services/rar-clients"), "{rendered}");
    }
}

#[test]
fn a_serialized_config_snapshot_contains_no_credential_material() {
    let serialized = serde_json::to_string_pretty(&config()).unwrap();
    assert!(!serialized.contains(CREDENTIAL), "{serialized}");
    assert!(!serialized.contains("Bearer"), "{serialized}");
    assert!(serialized.contains("services/rar-clients"));
}

#[test]
fn a_construction_failure_message_never_echoes_the_credential() {
    let error = MnesisHttpTransport::new(&config(), "bad\nvalue-with-secret-suffix", CREDENTIAL)
        .unwrap_err();
    let rendered = error.to_string();
    assert!(!rendered.contains("value-with-secret-suffix"), "{rendered}");
    assert!(matches!(error, MnesisError::Client { .. }));

    let debugged = format!("{error:?}");
    assert!(!debugged.contains("value-with-secret-suffix"), "{debugged}");
}

#[test]
fn an_endpoint_rejection_never_echoes_the_configured_url_or_its_query() {
    let mut config = config();
    config.knowledge_endpoint = "ftp://internal-host.example/path?token=leaked-token".to_string();
    let error = MnesisHttpTransport::new(&config, CREDENTIAL, CREDENTIAL).unwrap_err();
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("leaked-token"), "{rendered}");
        assert!(!rendered.contains("internal-host.example"), "{rendered}");
    }
}

#[test]
fn a_panic_payload_from_an_expect_on_the_transport_stays_clean() {
    let transport = MnesisHttpTransport::new(&config(), CREDENTIAL, CREDENTIAL).unwrap();
    let rendered_transport = format!("{transport:?}");
    let payload = std::panic::catch_unwind(move || {
        panic!("transport failed: {rendered_transport}");
    })
    .unwrap_err();

    let rendered = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(!rendered.is_empty());
    assert!(!rendered.contains(CREDENTIAL), "{rendered}");
}
