use std::{ffi::OsString, str::FromStr};

use ironclaw_config::{
    DeploymentSecurityEnvelope, DurableStateKind, LayoutManifest, LayoutRequirement,
    ProfileTransitionAdmission, REBORN_PROFILE_ENV, RebornBootConfig, RebornConfigError,
    RebornHome, RebornProfile, RebornStoragePaths, StateLayoutVersion, TenancyModel,
    WorkspaceAccessFloor,
};

#[test]
fn profile_wire_values_are_stable() {
    assert_eq!(RebornProfile::Standalone.as_str(), "local-dev");
    assert_eq!(
        RebornProfile::StandaloneUnrestricted.as_str(),
        "local-dev-yolo"
    );
    assert_eq!(
        RebornProfile::HostedSingleTenant.as_str(),
        "hosted-single-tenant"
    );
    assert_eq!(
        RebornProfile::HostedSingleTenantVolume.as_str(),
        "hosted-single-tenant-volume"
    );
    assert_eq!(
        RebornProfile::HostedSingleTenantVolumeSandboxed.as_str(),
        "hosted-single-tenant-volume-sandboxed"
    );
    assert_eq!(
        RebornProfile::HostedSingleTenantVolumeSandboxedRailway.as_str(),
        "hosted-single-tenant-volume-sandboxed-railway"
    );
    assert_eq!(RebornProfile::Production.as_str(), "production");
    assert_eq!(RebornProfile::MigrationDryRun.as_str(), "migration-dry-run");
}

#[test]
fn all_profiles_are_exposed_in_display_order() {
    assert_eq!(
        RebornProfile::all(),
        &[
            RebornProfile::Standalone,
            RebornProfile::StandaloneUnrestricted,
            RebornProfile::HostedSingleTenant,
            RebornProfile::HostedSingleTenantVolume,
            RebornProfile::HostedSingleTenantVolumeSandboxed,
            RebornProfile::HostedSingleTenantVolumeSandboxedRailway,
            RebornProfile::Production,
            RebornProfile::MigrationDryRun,
        ]
    );
}

#[test]
fn profile_parsing_accepts_expected_values() {
    assert_eq!(
        RebornProfile::from_str("local-dev"),
        Ok(RebornProfile::Standalone)
    );
    assert_eq!(
        RebornProfile::from_str("local-dev-yolo"),
        Ok(RebornProfile::StandaloneUnrestricted)
    );
    assert_eq!(
        RebornProfile::from_str("hosted-single-tenant"),
        Ok(RebornProfile::HostedSingleTenant)
    );
    assert_eq!(
        RebornProfile::from_str("hosted-single-tenant-volume"),
        Ok(RebornProfile::HostedSingleTenantVolume)
    );
    assert_eq!(
        RebornProfile::from_str("hosted-single-tenant-volume-sandboxed"),
        Ok(RebornProfile::HostedSingleTenantVolumeSandboxed)
    );
    assert_eq!(
        RebornProfile::from_str("hosted-single-tenant-volume-sandboxed-railway"),
        Ok(RebornProfile::HostedSingleTenantVolumeSandboxedRailway)
    );
    assert_eq!(
        RebornProfile::from_str("production"),
        Ok(RebornProfile::Production)
    );
    assert_eq!(
        RebornProfile::from_str("migration-dry-run"),
        Ok(RebornProfile::MigrationDryRun)
    );
}

#[test]
fn profile_predicates_capture_hosted_volume_local_runtime_contract() {
    assert!(!RebornProfile::Standalone.starts_hosted_single_tenant_listener());
    assert!(!RebornProfile::StandaloneUnrestricted.starts_hosted_single_tenant_listener());
    assert!(RebornProfile::HostedSingleTenant.starts_hosted_single_tenant_listener());
    assert!(RebornProfile::HostedSingleTenantVolume.starts_hosted_single_tenant_listener());
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxed.starts_hosted_single_tenant_listener()
    );
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxedRailway
            .starts_hosted_single_tenant_listener()
    );
    assert!(!RebornProfile::Production.starts_hosted_single_tenant_listener());
    assert!(!RebornProfile::MigrationDryRun.starts_hosted_single_tenant_listener());

    assert!(RebornProfile::Standalone.uses_standalone_local_runtime_volume());
    assert!(RebornProfile::StandaloneUnrestricted.uses_standalone_local_runtime_volume());
    assert!(!RebornProfile::HostedSingleTenant.uses_standalone_local_runtime_volume());
    assert!(RebornProfile::HostedSingleTenantVolume.uses_standalone_local_runtime_volume());
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxed.uses_standalone_local_runtime_volume()
    );
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxedRailway
            .uses_standalone_local_runtime_volume()
    );
    assert!(!RebornProfile::Production.uses_standalone_local_runtime_volume());
    assert!(!RebornProfile::MigrationDryRun.uses_standalone_local_runtime_volume());

    assert!(RebornProfile::Standalone.supports_local_runtime_skill_management());
    assert!(RebornProfile::StandaloneUnrestricted.supports_local_runtime_skill_management());
    assert!(RebornProfile::HostedSingleTenant.supports_local_runtime_skill_management());
    assert!(RebornProfile::HostedSingleTenantVolume.supports_local_runtime_skill_management());
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxed.supports_local_runtime_skill_management()
    );
    assert!(
        RebornProfile::HostedSingleTenantVolumeSandboxedRailway
            .supports_local_runtime_skill_management()
    );
    assert!(!RebornProfile::Production.supports_local_runtime_skill_management());
    assert!(!RebornProfile::MigrationDryRun.supports_local_runtime_skill_management());
}

#[test]
fn profile_default_is_standalone_for_explicit_binary_invocations() {
    assert_eq!(RebornProfile::default(), RebornProfile::Standalone);
}

#[test]
fn invalid_profile_is_rejected() {
    let err = RebornProfile::from_str("prod").expect_err("invalid profile should fail");

    assert_eq!(
        err,
        RebornConfigError::InvalidProfile {
            name: REBORN_PROFILE_ENV,
            value: "prod".to_string(),
        }
    );
}

#[test]
fn boot_config_resolves_home_and_profile_from_env_parts() {
    let temp = tempfile::tempdir().expect("tempdir");

    let config = RebornBootConfig::resolve_from_env_parts(
        Some(temp.path().join("reborn-home").into_os_string()),
        None,
        None,
        Some(OsString::from("production")),
    )
    .expect("boot config should resolve");

    assert_eq!(
        config.home().path(),
        temp.path().join("reborn-home").as_path()
    );
    assert_eq!(config.profile(), RebornProfile::Production);
}

#[test]
fn boot_config_defaults_profile_to_standalone() {
    let temp = tempfile::tempdir().expect("tempdir");

    let config =
        RebornBootConfig::resolve_from_env_parts(None, Some(temp.path().into()), None, None)
            .expect("boot config should resolve");

    assert_eq!(config.profile(), RebornProfile::Standalone);
}

#[test]
fn boot_config_rejects_invalid_profile_from_env_parts() {
    let temp = tempfile::tempdir().expect("tempdir");

    let error = RebornBootConfig::resolve_from_env_parts(
        Some(temp.path().join("reborn-home").into_os_string()),
        None,
        None,
        Some(OsString::from("prod")),
    )
    .expect_err("invalid boot profile should fail through the caller-level config path");

    assert_eq!(
        error,
        RebornConfigError::InvalidProfile {
            name: REBORN_PROFILE_ENV,
            value: "prod".to_string(),
        }
    );
}

#[test]
fn boot_config_rejects_empty_profile_from_env_parts() {
    let temp = tempfile::tempdir().expect("tempdir");

    let error = RebornBootConfig::resolve_from_env_parts(
        Some(temp.path().join("reborn-home").into_os_string()),
        None,
        None,
        Some(OsString::from("")),
    )
    .expect_err("empty boot profile should fail through the caller-level config path");

    assert_eq!(
        error,
        RebornConfigError::InvalidProfile {
            name: REBORN_PROFILE_ENV,
            value: String::new(),
        }
    );
}

#[test]
fn storage_paths_are_derived_from_reborn_home_without_creating_directories() {
    let temp = tempfile::tempdir().expect("tempdir");
    let expected_home = temp.path().join("reborn-home");
    let home = RebornHome::resolve_from_env_parts(
        Some(expected_home.clone().into_os_string()),
        None,
        None,
    )
    .expect("Reborn home should resolve");

    let paths = RebornStoragePaths::from_home(&home);

    assert_eq!(paths.state_root(), expected_home.join("state"));
    assert_eq!(paths.system_root(), expected_home.join("system"));
    assert_eq!(paths.workspace_root(), expected_home.join("workspaces"));
    assert_eq!(paths.runtime_root(), expected_home.join("runtime"));
    assert!(
        !expected_home.exists(),
        "deriving pure layout paths must not create the Reborn home"
    );
}

#[test]
fn layout_manifest_v1_toml_wire_values_are_stable() {
    struct Case {
        name: &'static str,
        requirement: LayoutRequirement,
        expected_toml: &'static str,
    }

    let cases = [
        Case {
            name: "embedded single trusted operator",
            requirement: LayoutRequirement {
                durable_state: DurableStateKind::EmbeddedLibSql,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::SingleUser,
                    workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
                },
            },
            expected_toml: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
        },
        Case {
            name: "embedded single isolated",
            requirement: LayoutRequirement {
                durable_state: DurableStateKind::EmbeddedLibSql,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::SingleUser,
                    workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
                },
            },
            expected_toml: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"per-caller-isolated\"\n",
        },
        Case {
            name: "external multi trusted operator",
            requirement: LayoutRequirement {
                durable_state: DurableStateKind::ExternalPostgres,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::MultiUser,
                    workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
                },
            },
            expected_toml: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"external-postgres\"\n\n[security]\ntenancy = \"multi-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
        },
        Case {
            name: "external multi isolated",
            requirement: LayoutRequirement {
                durable_state: DurableStateKind::ExternalPostgres,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::MultiUser,
                    workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
                },
            },
            expected_toml: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"external-postgres\"\n\n[security]\ntenancy = \"multi-user\"\nworkspace_access_floor = \"per-caller-isolated\"\n",
        },
    ];

    for case in cases {
        let manifest = LayoutManifest::new(case.requirement);

        assert_eq!(manifest.schema_version(), 1, "case: {}", case.name);
        assert_eq!(
            manifest.state_layout_version(),
            StateLayoutVersion::V1,
            "case: {}",
            case.name
        );
        assert_eq!(
            toml::to_string(&manifest).expect("manifest should serialize"),
            case.expected_toml,
            "case: {}",
            case.name
        );
        assert_eq!(
            toml::from_str::<LayoutManifest>(case.expected_toml)
                .expect("manifest should deserialize"),
            manifest,
            "case: {}",
            case.name
        );
    }
}

#[test]
fn layout_manifest_rejects_unsupported_or_unowned_wire_fields() {
    struct Case {
        name: &'static str,
        manifest: &'static str,
        expected_error_fragment: &'static str,
    }

    let cases = [
        Case {
            name: "unsupported schema version",
            manifest: "schema_version = 2\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "unsupported layout manifest schema_version 2",
        },
        Case {
            name: "unsupported state layout version",
            manifest: "schema_version = 1\nstate_layout_version = 2\ndurable_state = \"embedded-libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "unsupported state layout version 2",
        },
        Case {
            name: "non kebab case durable state",
            manifest: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded_libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "embedded_libsql",
        },
        Case {
            name: "profile name",
            manifest: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\nprofile = \"local-dev\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "profile",
        },
        Case {
            name: "state path",
            manifest: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\nstate_root = \"/operator/state\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "state_root",
        },
        Case {
            name: "process backend",
            manifest: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\nprocess_backend = \"docker\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "process_backend",
        },
        Case {
            name: "transient execution authority",
            manifest: "schema_version = 1\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\nruntime_authority = \"unrestricted\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
            expected_error_fragment: "runtime_authority",
        },
    ];

    for case in cases {
        let error = toml::from_str::<LayoutManifest>(case.manifest)
            .expect_err("unsupported manifest input must fail closed");

        assert!(
            error.to_string().contains(case.expected_error_fragment),
            "case: {} error: {error}",
            case.name
        );
    }
}

#[test]
fn layout_manifest_transition_admission_preserves_durable_security_assumptions() {
    struct Case {
        name: &'static str,
        stored: LayoutRequirement,
        requested: LayoutRequirement,
        expected: ProfileTransitionAdmission,
    }

    let embedded_single_trusted = LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::SingleUser,
            workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
        },
    };
    let embedded_single_isolated = LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::SingleUser,
            workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
        },
    };
    let embedded_multi_isolated = LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::MultiUser,
            workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
        },
    };
    let embedded_multi_trusted = LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::MultiUser,
            workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
        },
    };
    let external_multi_isolated = LayoutRequirement {
        durable_state: DurableStateKind::ExternalPostgres,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::MultiUser,
            workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
        },
    };

    let cases = [
        Case {
            name: "same local profile requirement",
            stored: embedded_single_trusted,
            requested: embedded_single_trusted,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "local dev to local dev yolo",
            stored: embedded_single_trusted,
            requested: embedded_single_trusted,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "hosted volume without processes to docker sandbox",
            stored: embedded_multi_isolated,
            requested: embedded_multi_isolated,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "docker sandbox to railway sandbox",
            stored: embedded_multi_isolated,
            requested: embedded_multi_isolated,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "railway sandbox to hosted volume without processes",
            stored: embedded_multi_isolated,
            requested: embedded_multi_isolated,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "tightening workspace access floor",
            stored: embedded_single_trusted,
            requested: embedded_single_isolated,
            expected: ProfileTransitionAdmission::Allowed,
        },
        Case {
            name: "weakening workspace access floor",
            stored: embedded_multi_isolated,
            requested: embedded_multi_trusted,
            expected: ProfileTransitionAdmission::Rejected {
                reason: "workspace access floor cannot weaken from per-caller-isolated to single-trusted-operator".to_owned(),
            },
        },
        Case {
            name: "multi user isolated to local host",
            stored: embedded_multi_isolated,
            requested: embedded_single_trusted,
            expected: ProfileTransitionAdmission::Rejected {
                reason: "tenancy transition from multi-user to single-user requires an explicit ownership migration".to_owned(),
            },
        },
        Case {
            name: "single user to multi user",
            stored: embedded_single_trusted,
            requested: embedded_multi_isolated,
            expected: ProfileTransitionAdmission::Rejected {
                reason: "tenancy transition from single-user to multi-user requires an explicit ownership migration".to_owned(),
            },
        },
        Case {
            name: "embedded libsql to external postgres",
            stored: embedded_multi_isolated,
            requested: external_multi_isolated,
            expected: ProfileTransitionAdmission::Rejected {
                reason: "durable state transition from embedded-libsql to external-postgres requires an explicit storage migration".to_owned(),
            },
        },
        Case {
            name: "external postgres to embedded libsql",
            stored: external_multi_isolated,
            requested: embedded_multi_isolated,
            expected: ProfileTransitionAdmission::Rejected {
                reason: "durable state transition from external-postgres to embedded-libsql requires an explicit storage migration".to_owned(),
            },
        },
    ];

    for case in cases {
        assert_eq!(
            LayoutManifest::new(case.stored).admit(case.requested),
            case.expected,
            "case: {}",
            case.name
        );
    }
}
