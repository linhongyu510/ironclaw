use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

use ironclaw_approvals::{
    CapabilityPermissionOverride, CapabilityPermissionOverrideInput,
    CapabilityPermissionOverrideKey,
};
use ironclaw_composition::test_support::{
    open_standalone_approval_settings_stores_for_test,
    open_standalone_extension_installation_store_for_test,
    open_standalone_skill_management_after_adoption_for_test,
    open_standalone_thread_service_for_test,
};
use ironclaw_composition::{LegacySkillSnapshotSource, open_standalone_secret_store};
use ironclaw_config::RebornStoragePaths;
use ironclaw_extension_registry::{
    ExtensionInstallation, ExtensionInstallationId, ExtensionManifestRecord, ExtensionManifestRef,
    InstallationOwner, ManifestSource,
};
use ironclaw_host_api::ids::{
    AgentId, CapabilityId, ExtensionId, SecretHandle, TenantId, ThreadId, UserId,
};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_host_api::scope::Principal;
use ironclaw_secrets::SecretMaterial;
use ironclaw_threads::{
    AppendFinalizedAssistantMessageRequest, EnsureThreadRequest, MessageContent,
    SessionThreadService, ThreadHistoryRequest, ThreadScope,
};
use secrecy::ExposeSecret as _;

const MASTER_KEY_FILE: &str = ".reborn-local-dev-secrets-master-key";

fn reborn_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ironclaw")
}

fn move_children(source: &std::path::Path, destination: &std::path::Path) {
    fs::create_dir_all(destination).expect("create legacy destination");
    for entry in fs::read_dir(source).expect("read seeded canonical directory") {
        let entry = entry.expect("read seeded canonical entry");
        fs::rename(entry.path(), destination.join(entry.file_name()))
            .expect("move seeded entry into released legacy root");
    }
}

#[tokio::test]
async fn released_local_dev_adoption_preserves_durable_state_and_user_isolation() {
    const THREAD_MESSAGE: &str = "ADOPTED_THREAD_MESSAGE_SENTINEL";
    const HOST_SECRET: &str = "ADOPTED_HOST_SECRET_SENTINEL";
    const USER_SKILL: &str = "adopted-user-skill";
    const USER_SKILL_CONTENT: &str = "---\nname: adopted-user-skill\ndescription: adopted user skill\n---\n\nADOPTED_USER_SKILL_SENTINEL";

    let temp = tempfile::tempdir().expect("temporary adoption fixture");
    let seed_root = temp.path().join("seed-installation");
    let reborn_home = temp.path().join("reborn-home");
    let legacy_root = reborn_home.join("local-dev");
    let seed_paths = RebornStoragePaths::from_installation_root(&seed_root);
    fs::create_dir_all(seed_paths.state_root()).expect("create seed state root");
    fs::create_dir_all(seed_paths.system_root()).expect("create seed system root");
    for namespace in ["extensions", "prompts", "skills"] {
        fs::create_dir_all(seed_paths.system_root().join(namespace))
            .expect("create seed system namespace");
    }
    fs::create_dir_all(seed_paths.workspace_root()).expect("create seed workspace root");
    fs::create_dir_all(seed_paths.runtime_root()).expect("create seed runtime root");
    fs::write(
        seed_paths.state_root().join(MASTER_KEY_FILE),
        ironclaw_secrets::keychain::generate_master_key_hex(),
    )
    .expect("seed cached secrets master key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(
            seed_paths.state_root().join(MASTER_KEY_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restrict cached secrets master key");
    }

    let tenant = TenantId::new("adoption-tenant").expect("valid tenant");
    let owner = UserId::new("adoption-owner").expect("valid owner");
    let rejected_owner = UserId::new("adoption-other-user").expect("valid other user");
    let thread_scope = ThreadScope {
        tenant_id: tenant.clone(),
        agent_id: AgentId::new("adoption-agent").expect("valid agent"),
        project_id: None,
        owner_user_id: Some(owner.clone()),
        mission_id: None,
    };
    let thread_id = ThreadId::new("adoption-thread").expect("valid thread");
    let resource_scope = ResourceScope {
        tenant_id: tenant.clone(),
        user_id: owner.clone(),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: Default::default(),
    };
    let secret_handle = SecretHandle::new("adoption-secret").expect("valid secret handle");
    let capability_id = CapabilityId::new("builtin.shell").expect("valid capability");
    let setting_key = CapabilityPermissionOverrideKey::new(&resource_scope, capability_id.clone());

    let threads = open_standalone_thread_service_for_test(&seed_root)
        .await
        .expect("open production thread service");
    threads
        .ensure_thread(EnsureThreadRequest {
            scope: thread_scope.clone(),
            thread_id: Some(thread_id.clone()),
            created_by_actor_id: owner.as_str().to_string(),
            title: Some("adoption preservation thread".to_string()),
            metadata_json: None,
        })
        .await
        .expect("seed durable thread");
    threads
        .append_finalized_assistant_message(AppendFinalizedAssistantMessageRequest {
            scope: thread_scope.clone(),
            thread_id: thread_id.clone(),
            turn_run_id: "adoption-run".to_string(),
            content: MessageContent::text(THREAD_MESSAGE),
        })
        .await
        .expect("seed durable message");

    let secrets = open_standalone_secret_store(seed_paths.state_root())
        .await
        .expect("open production encrypted secret store");
    secrets
        .put(
            resource_scope.clone(),
            secret_handle.clone(),
            SecretMaterial::from(HOST_SECRET.to_string()),
            None,
        )
        .await
        .expect("seed encrypted secret");

    let extension_id = ExtensionId::new("adopted-extension").expect("valid extension id");
    let installation_id =
        ExtensionInstallationId::new(extension_id.as_str()).expect("valid installation id");
    let extensions = open_standalone_extension_installation_store_for_test(&seed_root)
        .await
        .expect("open production extension installation store");
    let manifest = ExtensionManifestRecord::from_toml(
        format!(
            r#"
schema_version = "reborn.extension_manifest.v2"
id = "{extension_id}"
name = "Adopted Extension"
version = "0.1.0"
description = "adoption preservation fixture"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/adopted-extension.wasm"

[[host_api]]
id = "ironclaw.capability_provider/v1"
section = "capability_provider.tools"

[capability_provider.tools]

[[capability_provider.tools.capabilities]]
id = "adopted-extension.read"
description = "read"
effects = ["network"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/read.input.json"
output_schema_ref = "schemas/read.output.json"
"#,
            extension_id = extension_id.as_str(),
        ),
        ManifestSource::HostBundled,
        &ironclaw_host_api::host_port::default_host_port_catalog()
            .expect("default host-port catalog"),
        None,
        &ironclaw_extension_host::product_extension_host_api_contract_registry()
            .expect("product host-api contracts"),
        None,
    )
    .expect("valid extension manifest record");
    extensions
        .upsert_manifest_and_installation(
            manifest,
            ExtensionInstallation::new(
                installation_id.clone(),
                extension_id.clone(),
                ExtensionManifestRef::new(extension_id.clone(), None),
                Vec::new(),
                chrono::Utc::now(),
                InstallationOwner::users(BTreeSet::from([owner.clone()]))
                    .expect("singleton installation owner"),
            )
            .expect("valid installation"),
        )
        .await
        .expect("seed durable extension installation");

    let (settings, _, _) =
        open_standalone_approval_settings_stores_for_test(seed_paths.state_root())
            .await
            .expect("open production approval settings store");
    settings
        .set(CapabilityPermissionOverrideInput {
            scope: resource_scope.clone(),
            capability_id,
            state: CapabilityPermissionOverride::AskEachTime,
            updated_by: Principal::User(owner.clone()),
        })
        .await
        .expect("seed durable approval setting");

    let prompt_path = seed_paths.system_root().join("prompts/default-system.md");
    fs::create_dir_all(prompt_path.parent().expect("prompt parent"))
        .expect("create prompt directory");
    fs::write(&prompt_path, "ADOPTED_SYSTEM_PROMPT_SENTINEL").expect("seed system prompt");
    let system_skill_path = seed_paths
        .system_root()
        .join("skills/adopted-system-skill/SKILL.md");
    fs::create_dir_all(system_skill_path.parent().expect("system skill parent"))
        .expect("create system skill directory");
    fs::write(&system_skill_path, "ADOPTED_SYSTEM_SKILL_SENTINEL").expect("seed system skill");

    drop(settings);
    drop(extensions);
    drop(secrets);
    drop(threads);

    move_children(seed_paths.state_root(), &legacy_root);
    fs::rename(seed_paths.system_root(), legacy_root.join("system"))
        .expect("move seeded system namespace into released legacy root");
    let legacy_user_skill = legacy_root
        .join("tenants")
        .join(tenant.as_str())
        .join("users")
        .join(owner.as_str())
        .join("skills")
        .join(USER_SKILL)
        .join("SKILL.md");
    fs::create_dir_all(legacy_user_skill.parent().expect("legacy skill parent"))
        .expect("create released tenant/user skill tree");
    fs::write(&legacy_user_skill, USER_SKILL_CONTENT).expect("seed released user skill");

    let output = Command::new(reborn_bin())
        .args([
            "storage",
            "adopt",
            "--confirm-processes-stopped",
            "--confirm-backup-snapshot",
        ])
        .env("IRONCLAW_REBORN_HOME", &reborn_home)
        .env("IRONCLAW_REBORN_PROFILE", "local-dev")
        .output()
        .expect("run the production storage adoption command");
    assert!(
        output.status.success(),
        "storage adoption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let adopted_paths = RebornStoragePaths::from_installation_root(&reborn_home);
    // A normal composition boot establishes the non-migrated empty namespaces
    // before mounting them. The focused reopen helpers intentionally assume
    // that bootstrap precondition and only exercise durable store wiring.
    fs::create_dir_all(adopted_paths.workspace_root()).expect("bootstrap workspaces namespace");
    fs::create_dir_all(adopted_paths.runtime_root()).expect("bootstrap runtime namespace");
    let reopened_threads = open_standalone_thread_service_for_test(&reborn_home)
        .await
        .expect("fresh thread-service reopen after adoption");
    let history = reopened_threads
        .list_thread_history(ThreadHistoryRequest {
            scope: thread_scope.clone(),
            thread_id: thread_id.clone(),
        })
        .await
        .expect("read adopted conversation history");
    assert_eq!(history.thread.scope, thread_scope);
    assert_eq!(history.messages[0].content.as_deref(), Some(THREAD_MESSAGE));

    let reopened_secrets = open_standalone_secret_store(adopted_paths.state_root())
        .await
        .expect("fresh encrypted-secret reopen after adoption");
    let rejected_scope = ResourceScope {
        user_id: rejected_owner.clone(),
        ..resource_scope.clone()
    };
    assert!(
        reopened_secrets
            .lease_once(&rejected_scope, &secret_handle)
            .await
            .is_err(),
        "a sibling user must not lease the adopted secret"
    );
    let lease = reopened_secrets
        .lease_once(&resource_scope, &secret_handle)
        .await
        .expect("owner leases adopted secret");
    let secret = reopened_secrets
        .consume(&resource_scope, lease.id)
        .await
        .expect("owner consumes adopted secret");
    assert_eq!(secret.expose_secret(), HOST_SECRET);

    let reopened_extensions = open_standalone_extension_installation_store_for_test(&reborn_home)
        .await
        .expect("fresh extension-store reopen after adoption");
    let installation = reopened_extensions
        .get_installation(&installation_id)
        .await
        .expect("read adopted installation")
        .expect("adopted installation remains present");
    assert_eq!(
        installation.owner().members(),
        Some(&BTreeSet::from([owner.clone()]))
    );
    assert!(!installation.owner().visible_to(&rejected_owner));

    let (reopened_settings, _, _) =
        open_standalone_approval_settings_stores_for_test(adopted_paths.state_root())
            .await
            .expect("fresh settings-store reopen after adoption");
    let setting = reopened_settings
        .get(&setting_key)
        .await
        .expect("read adopted setting")
        .expect("adopted setting remains present");
    assert_eq!(setting.state, CapabilityPermissionOverride::AskEachTime);

    assert_eq!(
        fs::read_to_string(
            adopted_paths
                .system_root()
                .join("prompts/default-system.md")
        )
        .expect("read adopted prompt"),
        "ADOPTED_SYSTEM_PROMPT_SENTINEL"
    );
    assert_eq!(
        fs::read_to_string(
            adopted_paths
                .system_root()
                .join("skills/adopted-system-skill/SKILL.md"),
        )
        .expect("read adopted system skill"),
        "ADOPTED_SYSTEM_SKILL_SENTINEL"
    );

    let reopened_skills = open_standalone_skill_management_after_adoption_for_test(
        &reborn_home,
        owner,
        LegacySkillSnapshotSource::LocalDev,
    )
    .await
    .expect("run the production boot importer and reopen skills");
    let user_skill = reopened_skills
        .read_content_for_scope(resource_scope, USER_SKILL)
        .await
        .expect("owner reads adopted user skill");
    assert_eq!(user_skill.content, USER_SKILL_CONTENT);
    assert!(
        reopened_skills
            .read_content_for_scope(rejected_scope, USER_SKILL)
            .await
            .is_err(),
        "a sibling user must not read the adopted tenant/user skill"
    );
}
