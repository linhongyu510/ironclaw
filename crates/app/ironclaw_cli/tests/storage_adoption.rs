use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};

use ironclaw_approvals::{
    CapabilityPermissionOverride, CapabilityPermissionOverrideInput,
    CapabilityPermissionOverrideKey,
};
use ironclaw_composition::test_support::{
    open_standalone_approval_settings_stores_for_test,
    open_standalone_extension_installation_store_for_test,
    open_standalone_skill_management_for_test, open_standalone_thread_service_for_test,
};
use ironclaw_composition::{STANDALONE_SECRETS_MASTER_KEY_PATH, open_standalone_secret_store};
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

const MASTER_KEY_FILE: &str = STANDALONE_SECRETS_MASTER_KEY_PATH;

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

fn wait_for_serve_banner(child: &mut std::process::Child) {
    let stderr = child.stderr.take().expect("serve stderr is piped");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut captured = String::new();
    loop {
        if let Some(status) = child.try_wait().expect("serve child status") {
            panic!("serve exited before binding with {status}; stderr: {captured}");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve did not bind after adoption; stderr: {captured}");
        }
        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(Ok(line)) => {
                captured.push_str(&line);
                captured.push('\n');
                if captured.contains("ironclaw: WebChat v2 listener") {
                    return;
                }
            }
            Ok(Err(error)) => panic!("read serve stderr: {error}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("serve stderr closed before binding: {captured}");
            }
        }
    }
}

fn adoption_serve_command(
    reborn_home: &std::path::Path,
    isolated_home: &std::path::Path,
    owner: &UserId,
    port: u16,
) -> Command {
    let mut command = Command::new(reborn_bin());
    command
        .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()])
        .env_clear()
        .env("HOME", isolated_home)
        .env("IRONCLAW_DISABLE_OS_KEYCHAIN", "1")
        .env("IRONCLAW_REBORN_HOME", reborn_home)
        .env("IRONCLAW_REBORN_PROFILE", "local-dev")
        .env("IRONCLAW_REBORN_WEBUI_USER_ID", owner.as_str())
        .env(
            "IRONCLAW_REBORN_WEBUI_TOKEN",
            "adoption-test-token-0123456789abcdef",
        )
        .env("LLM_USE_CODEX_AUTH", "false")
        .env("LLM_BACKEND", "")
        .env("LLM_MODEL", "")
        .env("OPENAI_API_KEY", "")
        .stderr(Stdio::piped())
        .stdout(Stdio::null());
    command
}

fn snapshot_tree(root: &std::path::Path) -> Vec<(std::path::PathBuf, bool, Vec<u8>)> {
    fn visit(
        root: &std::path::Path,
        current: &std::path::Path,
        snapshot: &mut Vec<(std::path::PathBuf, bool, Vec<u8>)>,
    ) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read snapshot entries");
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("snapshot relative path");
            let file_type = entry.file_type().expect("snapshot entry type");
            if file_type.is_dir() {
                snapshot.push((relative.to_path_buf(), true, Vec::new()));
                visit(root, &path, snapshot);
            } else {
                assert!(file_type.is_file(), "snapshot fixture contains no symlinks");
                snapshot.push((
                    relative.to_path_buf(),
                    false,
                    fs::read(&path).expect("snapshot file bytes"),
                ));
            }
        }
    }

    let mut snapshot = Vec::new();
    visit(root, root, &mut snapshot);
    snapshot
}

#[tokio::test]
async fn released_local_dev_adoption_preserves_durable_state_and_user_isolation() {
    const THREAD_MESSAGE: &str = "ADOPTED_THREAD_MESSAGE_SENTINEL";
    const HOST_SECRET: &str = "ADOPTED_HOST_SECRET_SENTINEL";
    const USER_SKILL: &str = "adopted-user-skill";
    const USER_SKILL_CONTENT: &str = "---\nname: adopted-user-skill\ndescription: adopted user skill\n---\n\nADOPTED_USER_SKILL_SENTINEL";
    const UNSCOPED_SKILL: &str = "adopted-unscoped-skill";
    const UNSCOPED_SKILL_CONTENT: &str = "---\nname: adopted-unscoped-skill\ndescription: adopted unscoped skill\n---\n\nADOPTED_UNSCOPED_SKILL_SENTINEL";

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
        open_standalone_approval_settings_stores_for_test(seed_paths.installation_root())
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
    fs::write(
        &system_skill_path,
        "---\nname: adopted-system-skill\ndescription: adopted system skill\n---\n\nADOPTED_SYSTEM_SKILL_SENTINEL",
    )
    .expect("seed system skill");

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
    let legacy_unscoped_skill = legacy_root
        .join("skills")
        .join(UNSCOPED_SKILL)
        .join("SKILL.md");
    fs::create_dir_all(
        legacy_unscoped_skill
            .parent()
            .expect("legacy unscoped skill parent"),
    )
    .expect("create released unscoped skill tree");
    fs::write(&legacy_unscoped_skill, UNSCOPED_SKILL_CONTENT)
        .expect("seed released unscoped skill");

    let adopted_paths = RebornStoragePaths::from_installation_root(&reborn_home);
    assert!(
        !reborn_home.join("layout.toml").exists(),
        "fixture must enter normal startup with only the released legacy layout"
    );
    let isolated_home = temp.path().join("isolated-home");
    let home_before_denied_start = snapshot_tree(&reborn_home);
    let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port that startup must not try to bind");
    let occupied_port = occupied_listener
        .local_addr()
        .expect("occupied listener address")
        .port();
    let denied = adoption_serve_command(&reborn_home, &isolated_home, &owner, occupied_port)
        .output()
        .expect("start without deployment cutover authority");
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr)
            .contains("IRONCLAW_REBORN_STORAGE_CUTOVER=legacy-layout-v1")
    );
    assert!(legacy_root.join("reborn-local-dev.db").is_file());
    assert!(!reborn_home.join("layout.toml").exists());
    assert!(
        !reborn_home
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
    assert_eq!(snapshot_tree(&reborn_home), home_before_denied_start);
    drop(occupied_listener);

    let mut serve = adoption_serve_command(&reborn_home, &isolated_home, &owner, 0)
        .env("IRONCLAW_REBORN_STORAGE_CUTOVER", "legacy-layout-v1")
        .spawn()
        .expect("start production serve process that automatically adopts legacy storage");
    wait_for_serve_banner(&mut serve);
    serve.kill().expect("stop fresh serve process");
    serve.wait().expect("reap fresh serve process");
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
        open_standalone_approval_settings_stores_for_test(adopted_paths.installation_root())
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
    assert!(
        fs::read_to_string(
            adopted_paths
                .system_root()
                .join("skills/adopted-system-skill/SKILL.md"),
        )
        .expect("read adopted system skill")
        .contains("ADOPTED_SYSTEM_SKILL_SENTINEL")
    );

    let reopened_skills = open_standalone_skill_management_for_test(&reborn_home, owner.clone())
        .await
        .expect("reopen skills after the production boot importer ran");
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
    let default_scope = ResourceScope {
        tenant_id: TenantId::new("default").expect("released default tenant"),
        user_id: owner,
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: Default::default(),
    };
    let unscoped_skill = reopened_skills
        .read_content_for_scope(default_scope, UNSCOPED_SKILL)
        .await
        .expect("released unscoped skill keeps its production owner mapping");
    assert_eq!(unscoped_skill.content, UNSCOPED_SKILL_CONTENT);
}
