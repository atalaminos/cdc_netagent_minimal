//! Netagent wire protocol & trust core.
//!
//! This crate is platform-free and runtime-free: it defines the signed-command
//! protocol between NetEdge and the agent, the per-agent signed-report messages
//! in the other direction, the shared inventory/telemetry types, and the
//! Ed25519 crypto primitives. The signing conventions (sign over `bincode`,
//! tuple-serialized 64-byte signatures) are intentionally identical to
//! NetEdge's `src/license.rs` so the two systems share one trust model.

pub mod command;
pub mod crypto;
pub mod error;
pub mod inventory;
pub mod messages;
pub(crate) mod sig;

pub use error::ProtoError;

/// Current wall-clock time as Unix seconds. Convenience for callers that build
/// or validate time-bounded envelopes.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
