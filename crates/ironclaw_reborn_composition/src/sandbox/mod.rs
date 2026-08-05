//! Composition facade for the complete user-sandbox subsystem.
//!
//! Generic composition code enters through this module only. Provider
//! selection and compatible runtime-component construction live in
//! [`UserSandboxFactory`]; provider-specific lifecycle services remain in
//! private submodules.

mod factory;
mod lifecycle;
mod quota;
mod reaper;

pub use factory::{UserSandboxFactory, UserSandboxRuntimeBundle};

pub(crate) use factory::UserSandboxLifecycle;
pub(crate) use lifecycle::{SandboxProfileBindingInputs, SandboxRuntimeBindings};
pub(crate) use quota::{
    SANDBOX_PER_USER_MAX_CONCURRENT, apply_sandbox_user_ceiling, resolve_local_runtime_tenant_id,
    sandbox_max_concurrent_from_env,
};
pub(crate) use reaper::{
    SANDBOX_REAPER_SHUTDOWN_TIMEOUT, SandboxReaperRuntimeHandle, spawn_sandbox_reaper,
};
