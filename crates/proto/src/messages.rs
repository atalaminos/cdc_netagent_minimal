//! Agent ↔ NetEdge messages.
//!
//! Two directions, two trust mechanisms:
//!  * **NetEdge → agent** commands are [`crate::command::SignedCommand`], signed
//!    by NetEdge's command key and verified against the pinned copy.
//!  * **agent → NetEdge** reports are wrapped in [`SignedReport`], signed by the
//!    *agent's own* per-device key. NetEdge stores each agent's public key at
//!    enrollment and can revoke a single agent without touching the rest. This
//!    replaces the shared static `control_token` used by netdd's control server.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::command::{RejectReason, SignedCommand};
use crate::crypto::{self, SIG_LEN};
use crate::error::ProtoError;
use crate::inventory::{
    DriverInfo, HardwareInfo, InstallReport, MissingDriverDevice, NetApplyReport, SmartInfo,
    SoftwareInfo,
};

/// One-time enrollment request. The `enrollment_token` is a short-lived secret
/// minted by a NetEdge admin and bound to a specific node; it bootstraps the
/// agent's per-device identity and is never reused for command auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    /// Hex of the agent's freshly generated Ed25519 public key.
    pub agent_pubkey: String,
    pub hostname: String,
    pub mac: String,
    /// Stable machine fingerprint (e.g. hash of machine-id + primary MAC).
    pub machine_fingerprint: String,
    pub agent_version: String,
    pub os: String,
}

/// Enrollment response: the agent's assigned id and the keys/pins it must pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    /// Hex of NetEdge's command public key — the agent pins this for command verification.
    pub server_command_pubkey: String,
    /// Expected TLS SPKI pin (sha256 hex) confirming the server identity.
    pub server_spki_pin: Option<String>,
    pub heartbeat_interval_secs: u64,
    pub poll_interval_secs: u64,
}

/// Periodic liveness + light health beat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub agent_version: String,
    pub uptime_secs: u64,
    pub boot_time: i64,
    pub healthy: bool,
    pub timestamp: i64,
}

/// Agent acknowledges receipt of a command (before running it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAck {
    pub command_id: Uuid,
    pub at: i64,
}

/// Result of running a command. `data` carries inventory payloads when relevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: Uuid,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub message: String,
    pub finished_at: i64,
    pub data: Option<ResultData>,
}

/// Structured payloads attached to a [`CommandResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResultData {
    Drivers(Vec<DriverInfo>),
    MissingDrivers(Vec<MissingDriverDevice>),
    Software(Vec<SoftwareInfo>),
    Hardware(HardwareInfo),
    Smart(Vec<SmartInfo>),
    Network(NetApplyReport),
    Install(InstallReport),
}

/// Reported when a command was refused — audited as an attempt server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedCommandReport {
    pub command_id: Option<Uuid>,
    pub reason: RejectReason,
    pub detail: String,
    pub at: i64,
}

/// Messages the server pushes to the agent over the WebSocket (or returns from
/// an HTTP poll). JSON-encoded text frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Boxed: a `SignedCommand` is far larger than the other variants, and
    /// boxing keeps the enum compact. Serializes transparently as the inner
    /// command, so the JSON wire format is unchanged.
    Command(Box<SignedCommand>),
    /// Bytes for an open remote-shell session (base64).
    ShellInput {
        session_id: String,
        data_b64: String,
    },
    ShellClose {
        session_id: String,
    },
    Pong,
}

/// Messages the agent sends to the server over the WebSocket. JSON text frames.
/// Reports are individually signed via [`SignedReport`] before sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    Hello {
        agent_id: String,
    },
    Ack(SignedReport<CommandAck>),
    Result(SignedReport<CommandResult>),
    Rejected(SignedReport<RejectedCommandReport>),
    Heartbeat(SignedReport<Heartbeat>),
    /// Shell output produced by the agent's PTY (base64).
    ShellOutput {
        session_id: String,
        data_b64: String,
    },
    ShellClosed {
        session_id: String,
    },
    Ping,
}

/// Inner, signed body of an agent report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBody<T> {
    pub agent_id: String,
    pub issued_at: i64,
    pub nonce: [u8; 16],
    pub inner: T,
}

/// An agent report plus its detached Ed25519 signature (agent's own key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReport<T> {
    pub body: ReportBody<T>,
    #[serde(with = "crate::sig")]
    pub signature: [u8; SIG_LEN],
}

/// Sign an agent report body with the agent's own signing key.
pub fn sign_report<T: Serialize>(
    agent_id: &str,
    inner: T,
    issued_at: i64,
    key: &SigningKey,
) -> Result<SignedReport<T>, ProtoError> {
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let body = ReportBody {
        agent_id: agent_id.to_string(),
        issued_at,
        nonce,
        inner,
    };
    let bytes = bincode::serialize(&body).map_err(|e| ProtoError::Serialize(e.to_string()))?;
    let signature = crypto::sign_bytes(key, &bytes);
    Ok(SignedReport { body, signature })
}

/// Verify an agent report against the agent's stored public key, returning the
/// inner payload. Used by NetEdge / the test mock server.
pub fn verify_report<'a, T: Serialize + DeserializeOwned>(
    signed: &'a SignedReport<T>,
    agent_key: &VerifyingKey,
) -> Result<&'a T, ProtoError> {
    let bytes =
        bincode::serialize(&signed.body).map_err(|e| ProtoError::Serialize(e.to_string()))?;
    crypto::verify_bytes(agent_key, &bytes, &signed.signature)?;
    Ok(&signed.body.inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signing_key;

    #[test]
    fn signed_report_roundtrip_and_verify() {
        let k = generate_signing_key();
        let vk = k.verifying_key();
        let hb = Heartbeat {
            agent_version: "1.0.0".into(),
            uptime_secs: 42,
            boot_time: 1000,
            healthy: true,
            timestamp: 1042,
        };
        let signed = sign_report("agent-1", hb.clone(), 1042, &k).unwrap();
        let inner = verify_report(&signed, &vk).unwrap();
        assert_eq!(inner.uptime_secs, 42);
    }

    #[test]
    fn signed_report_tamper_rejected() {
        let k = generate_signing_key();
        let vk = k.verifying_key();
        let ack = CommandAck {
            command_id: Uuid::new_v4(),
            at: 10,
        };
        let mut signed = sign_report("agent-1", ack, 10, &k).unwrap();
        signed.body.agent_id = "agent-evil".into();
        assert!(verify_report(&signed, &vk).is_err());
    }

    #[test]
    fn signed_report_wrong_key_rejected() {
        let k = generate_signing_key();
        let other = generate_signing_key();
        let ack = CommandAck {
            command_id: Uuid::new_v4(),
            at: 10,
        };
        let signed = sign_report("agent-1", ack, 10, &k).unwrap();
        assert!(verify_report(&signed, &other.verifying_key()).is_err());
    }
}
