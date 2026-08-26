//! Canonical planned-loop placement inside the persistent user sandbox.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::{
    ids::InvocationId,
    process::{SandboxLoopWorkerStartRequest, SandboxLoopWorkerTransport},
};
use ironclaw_loop_contracts::{
    AgentLoopDriver, AgentLoopDriverDescriptor, AgentLoopDriverError, AgentLoopDriverHost,
    AgentLoopDriverResumeRequest, AgentLoopDriverRunRequest, LoopExit,
};
use ironclaw_loop_host::{
    LoopWorkerFailure, LoopWorkerInvocation, LoopWorkerOutcome, read_worker_bootstrap,
    remote_host_from_stdio, serve_loop_worker,
};

use crate::{
    app_loop_family::build_loop_family_registry,
    driver_registry::{DriverKind, DriverRegistry, LoopDriverRegistryKey},
    planned_driver::PlannedDriver,
    planned_driver_factory::{
        DefaultPlannedDriverRegistrationError, planned_driver_descriptor,
        planned_driver_requirements,
    },
};

pub const LOOP_WORKER_EXECUTABLE: &str = "/usr/local/bin/ironclaw-loop-worker";

pub struct SandboxedPlannedDriver {
    descriptor: AgentLoopDriverDescriptor,
    transport: Arc<dyn SandboxLoopWorkerTransport>,
}

impl SandboxedPlannedDriver {
    pub fn new(
        transport: Arc<dyn SandboxLoopWorkerTransport>,
    ) -> Result<Self, AgentLoopDriverError> {
        let descriptor = planned_driver_descriptor()
            .map_err(|reason| AgentLoopDriverError::InvalidRequest { reason })?;
        Ok(Self {
            descriptor,
            transport,
        })
    }

    async fn invoke(
        &self,
        invocation: LoopWorkerInvocation,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        let context = host.run_context();
        let mut scope = context.scope.to_resource_scope();
        if let Some(actor) = context.actor() {
            scope.user_id = actor.user_id.clone();
        }
        scope.thread_id = Some(context.thread_id.clone());
        scope.invocation_id = InvocationId::from_uuid(context.run_id.as_uuid());

        let mut session = self
            .transport
            .start_loop_worker(SandboxLoopWorkerStartRequest {
                scope,
                executable: LOOP_WORKER_EXECUTABLE.to_string(),
                args: Vec::new(),
                workdir: Some("/workspace".to_string()),
            })
            .await
            .map_err(worker_transport_error)?;
        let outcome = serve_loop_worker(session.as_mut(), host, invocation).await;
        let cleanup = session.terminate().await;
        if let Err(error) = cleanup {
            return Err(worker_transport_error(error));
        }
        match outcome.map_err(worker_transport_error)? {
            LoopWorkerOutcome::Exit(exit) => Ok(exit),
            LoopWorkerOutcome::Failed(failure) => Err(AgentLoopDriverError::Failed {
                reason_kind: failure.kind,
                detail: failure.detail,
            }),
        }
    }
}
fn worker_transport_error(error: impl std::fmt::Display) -> AgentLoopDriverError {
    AgentLoopDriverError::Failed {
        reason_kind: "sandbox_loop_worker_unavailable".to_string(),
        detail: Some(error.to_string()),
    }
}

pub fn register_sandboxed_default_planned_driver(
    registry: &mut DriverRegistry,
    transport: Arc<dyn SandboxLoopWorkerTransport>,
) -> Result<LoopDriverRegistryKey, DefaultPlannedDriverRegistrationError> {
    let driver = Arc::new(SandboxedPlannedDriver::new(transport)?);
    registry
        .register_driver(
            driver,
            planned_driver_requirements(),
            DriverKind::Production,
        )
        .map_err(Into::into)
}

#[async_trait]
impl AgentLoopDriver for SandboxedPlannedDriver {
    fn descriptor(&self) -> AgentLoopDriverDescriptor {
        self.descriptor.clone()
    }

    async fn run(
        &self,
        request: AgentLoopDriverRunRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        self.invoke(LoopWorkerInvocation::Run(request), host).await
    }

    async fn resume(
        &self,
        request: AgentLoopDriverResumeRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        self.invoke(LoopWorkerInvocation::Resume(request), host)
            .await
    }
}

/// Canonical loop-worker entrypoint used by the sandbox worker image.
pub async fn run_loop_worker_stdio() -> Result<(), String> {
    let mut stdin = tokio::io::stdin();
    let bootstrap = read_worker_bootstrap(&mut stdin)
        .await
        .map_err(|error| error.to_string())?;
    let remote_host = remote_host_from_stdio(&bootstrap).map_err(|error| error.to_string())?;
    let registry = build_loop_family_registry().map_err(|error| error.to_string())?;
    let driver =
        PlannedDriver::default_from_registry(&registry).map_err(|error| error.to_string())?;
    let outcome = match bootstrap.invocation {
        LoopWorkerInvocation::Run(request) => driver.run(request, &remote_host).await,
        LoopWorkerInvocation::Resume(request) => driver.resume(request, &remote_host).await,
    };
    let outcome = match outcome {
        Ok(exit) => LoopWorkerOutcome::Exit(exit),
        Err(error) => LoopWorkerOutcome::Failed(LoopWorkerFailure {
            kind: worker_failure_kind(&error).to_string(),
            detail: Some(error.to_string()),
        }),
    };
    remote_host
        .write_outcome(outcome)
        .await
        .map_err(|error| error.to_string())
}

fn worker_failure_kind(error: &AgentLoopDriverError) -> &'static str {
    match error {
        AgentLoopDriverError::InvalidRequest { .. } => "driver_invalid_request",
        AgentLoopDriverError::Unavailable { .. } => "driver_unavailable",
        AgentLoopDriverError::Failed { .. } => "driver_failed",
    }
}
