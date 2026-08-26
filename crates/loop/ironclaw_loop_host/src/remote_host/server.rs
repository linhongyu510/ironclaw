use ironclaw_host_api::process::{RuntimeProcessError, SandboxLoopWorkerSession};
use ironclaw_loop_contracts::*;

use super::protocol::*;

fn process_error(error: RuntimeProcessError) -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::Unavailable,
        format!("sandbox loop worker transport failed: {error}"),
    )
}
pub(super) fn wire_error_to_host_error(error: WireError) -> AgentLoopHostError {
    match error {
        WireError::Host(error) => error,
        WireError::Compaction(error) => {
            AgentLoopHostError::new(AgentLoopHostErrorKind::Unavailable, error.to_string())
        }
        WireError::Protocol(detail) => {
            AgentLoopHostError::new(AgentLoopHostErrorKind::Internal, detail)
        }
    }
}

async fn dispatch_host_call(
    host: &(dyn AgentLoopDriverHost + Send + Sync),
    call: HostCall,
) -> Result<serde_json::Value, WireError> {
    macro_rules! host_call {
        ($future:expr) => {{
            let value = $future.await.map_err(WireError::Host)?;
            serde_json::to_value(value).map_err(|error| {
                WireError::Protocol(format!("host response serialization failed: {error}"))
            })
        }};
    }

    match call {
        HostCall::LoadContext(request) => {
            let bundle = host
                .load_loop_context(request)
                .await
                .map_err(WireError::Host)?;
            serde_json::to_value(WireLoopContextBundle::from(bundle)).map_err(|error| {
                WireError::Protocol(format!(
                    "loop context response serialization failed: {error}"
                ))
            })
        }
        HostCall::BuildPrompt(request) => host_call!(host.build_prompt_bundle(request)),
        HostCall::PollInputs { after, limit } => host_call!(host.poll_inputs(after, limit)),
        HostCall::AckInputs(tokens) => host_call!(host.ack_inputs(tokens)),
        HostCall::StreamModel(request) => host_call!(host.stream_model(request)),
        HostCall::RegisterProviderToolCall(request) => {
            host_call!(host.register_provider_tool_call(request))
        }
        HostCall::VisibleCapabilities(request) => {
            let surface = host
                .visible_capabilities(request)
                .await
                .map_err(WireError::Host)?;
            serde_json::to_value(WireVisibleCapabilitySurface::from(surface)).map_err(|error| {
                WireError::Protocol(format!(
                    "visible capability surface serialization failed: {error}"
                ))
            })
        }
        HostCall::InvokeCapability(request) => host_call!(host.invoke_capability(request)),
        HostCall::InvokeCapabilityBatch(request) => {
            host_call!(host.invoke_capability_batch(request))
        }
        HostCall::BeginAssistantDraft(request) => host_call!(host.begin_assistant_draft(request)),
        HostCall::UpdateAssistantDraft(request) => host_call!(host.update_assistant_draft(request)),
        HostCall::FinalizeAssistantMessage(request) => {
            host_call!(host.finalize_assistant_message(request))
        }
        HostCall::AppendCapabilityResultRef(request) => {
            host_call!(host.append_capability_result_ref(*request))
        }
        HostCall::Checkpoint(request) => host_call!(host.checkpoint(request)),
        HostCall::StageCheckpointPayload(request) => {
            host_call!(host.stage_checkpoint_payload(request))
        }
        HostCall::LoadCheckpointPayload(request) => {
            let payload = host
                .load_checkpoint_payload(request)
                .await
                .map_err(WireError::Host)?;
            serde_json::to_value(WireLoadedCheckpointPayload::from(payload)).map_err(|error| {
                WireError::Protocol(format!("checkpoint payload serialization failed: {error}"))
            })
        }
        HostCall::EmitProgress(event) => host_call!(host.emit_loop_progress(event)),
        HostCall::Compact(request) => {
            let value = host
                .compact_loop_context(request)
                .await
                .map_err(WireError::Compaction)?;
            serde_json::to_value(value).map_err(|error| {
                WireError::Protocol(format!("compaction response serialization failed: {error}"))
            })
        }
    }
}

/// Drive one loop worker against the already-scoped production host.
pub async fn serve_loop_worker(
    session: &mut dyn SandboxLoopWorkerSession,
    host: &(dyn AgentLoopDriverHost + Send + Sync),
    invocation: LoopWorkerInvocation,
) -> Result<LoopWorkerOutcome, AgentLoopHostError> {
    let bootstrap = LoopWorkerBootstrap {
        wire_version: LOOP_WORKER_WIRE_VERSION,
        run_context: host.run_context().clone(),
        invocation,
        tool_definitions: host.tool_definitions()?,
        current_visible_capabilities: host
            .current_visible_capabilities()?
            .map(WireVisibleCapabilitySurface::from)
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                AgentLoopHostError::new(
                    AgentLoopHostErrorKind::Internal,
                    format!("visible capability bootstrap serialization failed: {error}"),
                )
            })?,
    };
    session
        .send(encode(&HostFrame::Bootstrap(Box::new(bootstrap)))?)
        .await
        .map_err(process_error)?;

    let mut cancellation_sent = false;
    loop {
        let bytes = tokio::select! {
            frame = session.receive() => frame
                .map_err(process_error)?
                .ok_or_else(|| {
                    AgentLoopHostError::new(
                        AgentLoopHostErrorKind::Unavailable,
                        "sandbox loop worker exited before returning a loop outcome",
                    )
                })?,
            signal = host.cancellation_requested(), if !cancellation_sent => {
                session
                    .send(encode(&HostFrame::Cancel(signal))?)
                    .await
                    .map_err(process_error)?;
                cancellation_sent = true;
                continue;
            }
        };
        match decode::<WorkerFrame>(&bytes)? {
            WorkerFrame::Outcome(outcome) => {
                session
                    .send(encode(&HostFrame::OutcomeAck)?)
                    .await
                    .map_err(process_error)?;
                return Ok(outcome);
            }
            WorkerFrame::HostRequest(request) => {
                let result = dispatch_host_call(host, request.call).await;
                session
                    .send(encode(&HostFrame::HostResponse(HostResponseFrame {
                        id: request.id,
                        result,
                    }))?)
                    .await
                    .map_err(process_error)?;
            }
        }
    }
}
