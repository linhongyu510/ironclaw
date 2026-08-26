//! Synchronous recorder port for best-effort telemetry capture.

use crate::observation::TelemetryObservation;

/// The result of attempting to enqueue one typed observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    Accepted,
    DroppedQueueFull,
    DroppedClosed,
    DroppedInvalid,
}

/// A producer-facing, nonblocking telemetry sink.
pub trait TelemetryRecorder: Send + Sync {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome;
}
