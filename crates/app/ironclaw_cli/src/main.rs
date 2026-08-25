mod cli;
mod commands;
mod context;
mod dto;
mod file_write;
mod first_party;
mod operator_env;
mod render;
mod runtime;
mod serve_invocation;
mod webui_token;

fn main() -> anyhow::Result<()> {
    // Mirror the v1 binary's behavior so dev workflows can keep LLM
    // keys / base URLs in `.env`. Silent on missing file — production
    // hosts use shell-exported env or systemd unit env, not `.env` —
    // but any other error (parse failure, permission denied) is
    // surfaced to stderr so a malformed file does not boot the host
    // with stale env. The boot itself still proceeds because
    // operators may have already exported the same keys in their
    // shell.
    if let Err(error) = dotenvy::dotenv()
        && !error.not_found()
    {
        eprintln!("warning: failed to load .env: {error}");
    }
    load_home_env();
    cli::run()
}

/// Loads `$IRONCLAW_REBORN_HOME/.env` after the working-directory one, so a
/// workstation configures endpoints and credentials once instead of per shell.
/// Never overwrites an already-set variable: shell exports win, then the
/// project file, then this one.
fn load_home_env() {
    let Ok(home) = ironclaw_config::RebornHome::resolve_from_env() else {
        return;
    };
    if let Err(error) = dotenvy::from_path(home.path().join(".env"))
        && !error.not_found()
    {
        eprintln!("warning: failed to load home .env: {error}");
    }
}
