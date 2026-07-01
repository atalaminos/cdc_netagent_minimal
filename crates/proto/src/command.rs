//! Signed command protocol: NetEdge → Netagent.
//!
//! Every command NetEdge sends is wrapped in a [`CommandEnvelope`] and signed
//! with NetEdge's *command* Ed25519 key. The agent verifies the signature
//! against a **pinned** copy of that public key (configured at enrollment),
//! exactly mirroring how netdd verifies sub-licenses against an embedded
//! `NETEDGE_PUBLIC_KEY_BYTES`. On top of the signature we enforce a short
//! validity window (timestamp + nonce) and a replay cache, so a captured,
//! validly-signed command cannot be replayed later or against another agent.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::crypto::{self, SIG_LEN};
use crate::error::ProtoError;

/// Bump only with a coordinated change on both NetEdge and the agent.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed `expires_at - issued_at`. Commands must be short-lived so a
/// captured command is only briefly replayable even before the replay cache.
pub const MAX_COMMAND_WINDOW_SECS: i64 = 60;

/// Allowed clock skew between server and agent when checking `issued_at`.
pub const CLOCK_SKEW_SECS: i64 = 30;

/// Whether a hostname change (or similar) should trigger a reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebootPolicy {
    /// Do not reboot; change applies on next manual reboot.
    None,
    /// Reboot immediately after applying.
    Immediate,
    /// Reboot after a delay (seconds).
    Deferred(u32),
}

/// IP assignment method for a network reconfiguration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpMethod {
    Dhcp,
    Static {
        /// e.g. "192.168.10.50"
        address: String,
        /// CIDR prefix length, e.g. 24
        prefix: u8,
        gateway: Option<String>,
    },
}

/// Desired network configuration for an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Interface name (Linux: "eth0"/"enp3s0"; Windows: alias e.g. "Ethernet").
    pub iface: String,
    pub method: IpMethod,
    /// DNS servers (applied for both static and DHCP-override scenarios).
    pub dns: Vec<String>,
    /// Optional 802.1Q VLAN id.
    pub vlan: Option<u16>,
}

/// Kind of installable package for the snapin runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageKind {
    Msi,
    ExeSilent,
    Deb,
    Rpm,
    Script,
}

/// A software package to install silently (FOG-style snapin, cross-platform).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSpec {
    /// HTTPS URL to download the artifact from (server is SPKI-pinned).
    pub url: String,
    pub kind: PackageKind,
    /// Extra silent-install arguments (e.g. "/qn" for msi, "-s" for exe).
    pub args: Vec<String>,
    /// Expected SHA-256 (hex) of the downloaded artifact; verified before run.
    pub sha256: String,
    /// Number of retries on failure.
    pub retries: u8,
}

/// Power action for scheduled maintenance windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerAction {
    Reboot,
    Shutdown,
}

/// Schedule a power action inside a maintenance window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerSchedule {
    pub action: PowerAction,
    /// Unix timestamp at which to perform the action.
    pub at: i64,
    /// If true, skip the action when an interactive user session is active.
    pub cancel_if_active: bool,
}

/// The set of operations NetEdge can ask a Netagent to perform.
///
/// `SelfUpdate` carries a 64-byte signature + strings, making it much larger
/// than e.g. `Ping`; boxing would only save stack on a short-lived, immediately
/// matched value, so we accept the size spread.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Liveness probe; agent replies with a `CommandResult` (exit_code 0).
    Ping,
    /// Ordered reboot after `delay_secs`.
    Reboot { delay_secs: u32 },
    /// Ordered shutdown after `delay_secs`.
    Shutdown { delay_secs: u32 },
    /// Run an arbitrary command (subject to the agent's exec policy).
    Exec {
        program: String,
        args: Vec<String>,
        /// Kill the process if it exceeds this many seconds.
        timeout_secs: u32,
        cwd: Option<String>,
        env: Vec<(String, String)>,
    },
    /// Change the network hostname (NetBIOS/hostname), optionally rebooting.
    SetHostname { name: String, reboot: RebootPolicy },
    /// Reconfigure an interface (static/DHCP, mask, gateway, DNS, VLAN).
    SetNetwork(NetworkConfig),
    /// Windows: full installed-driver inventory (WMI Win32_PnPSignedDriver).
    GetDrivers,
    /// Windows: devices with no/failed driver (ConfigManagerErrorCode != 0).
    GetMissingDrivers,
    /// Installed software inventory.
    GetSoftwareInventory,
    /// Hardware + SMART inventory snapshot.
    GetHardware,
    /// Install a software package silently.
    InstallPackage(PackageSpec),
    /// Schedule a power action in a maintenance window.
    SchedulePower(PowerSchedule),
    /// Cancel any pending scheduled power action.
    CancelScheduledPower,
    /// Open an interactive remote shell session (PTY) identified by `session_id`.
    OpenShell { session_id: String },
    /// Replace the agent binary with a newer, signed one.
    SelfUpdate {
        url: String,
        version: String,
        /// SHA-256 (hex) of the new binary.
        sha256: String,
        /// Ed25519 signature (raw 64 bytes) over the new binary, verified
        /// against the pinned NetEdge command key before swapping.
        #[serde(with = "crate::sig")]
        binary_sig: [u8; SIG_LEN],
    },
    /// Authorized self-uninstall (the ONLY way to remove the agent remotely).
    Uninstall,
}

/// Signed, time-bounded wrapper around a [`Command`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub version: u8,
    pub command_id: Uuid,
    /// The agent this command is destined for. Prevents replay against peers.
    pub agent_id: String,
    pub command: Command,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: [u8; 16],
}

/// A [`CommandEnvelope`] plus the detached Ed25519 signature over its bincode
/// serialization. Same shape and signing convention as NetEdge `SignedLicense`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommand {
    pub payload: CommandEnvelope,
    #[serde(with = "crate::sig")]
    pub signature: [u8; SIG_LEN],
}

/// Why a command was refused. Each variant is auditable as an *attempt* — the
/// agent never silently drops a rejected command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    BadSignature,
    WrongAgent,
    UnsupportedVersion,
    Expired,
    NotYetValid,
    WindowTooLong,
    Replay,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RejectReason::BadSignature => "invalid signature",
            RejectReason::WrongAgent => "command addressed to a different agent",
            RejectReason::UnsupportedVersion => "unsupported protocol version",
            RejectReason::Expired => "command expired",
            RejectReason::NotYetValid => "command issued in the future (clock skew)",
            RejectReason::WindowTooLong => "validity window too long",
            RejectReason::Replay => "command already seen (replay)",
        };
        f.write_str(s)
    }
}

/// Sign a command envelope with NetEdge's command signing key.
/// Used by NetEdge (and the test mock server) — mirrors `sign_license`.
pub fn sign_command(
    payload: CommandEnvelope,
    key: &SigningKey,
) -> Result<SignedCommand, ProtoError> {
    let bytes = bincode::serialize(&payload).map_err(|e| ProtoError::Serialize(e.to_string()))?;
    let signature = crypto::sign_bytes(key, &bytes);
    Ok(SignedCommand { payload, signature })
}

/// Serialize a signed command to bincode for the wire.
pub fn serialize(signed: &SignedCommand) -> Result<Vec<u8>, ProtoError> {
    bincode::serialize(signed).map_err(|e| ProtoError::Serialize(e.to_string()))
}

/// Deserialize a signed command from bincode bytes.
pub fn deserialize(bytes: &[u8]) -> Result<SignedCommand, ProtoError> {
    bincode::deserialize(bytes).map_err(|e| ProtoError::Deserialize(e.to_string()))
}

/// Verify a signed command and admit it for execution, or return why not.
///
/// Order of checks (all must pass): protocol version → signature (against the
/// pinned key) → destined for this agent → timestamp within skew → not expired
/// → window not abused → not a replay. Only on full success is the command_id
/// recorded in the replay cache.
pub fn verify_and_admit(
    signed: &SignedCommand,
    pinned_key: &VerifyingKey,
    expected_agent_id: &str,
    now: i64,
    replay: &mut ReplayCache,
) -> Result<Command, RejectReason> {
    let p = &signed.payload;

    if p.version != PROTOCOL_VERSION {
        return Err(RejectReason::UnsupportedVersion);
    }

    // Signature is checked over the exact bincode bytes of the payload.
    let bytes = bincode::serialize(p).map_err(|_| RejectReason::BadSignature)?;
    crypto::verify_bytes(pinned_key, &bytes, &signed.signature)
        .map_err(|_| RejectReason::BadSignature)?;

    if p.agent_id != expected_agent_id {
        return Err(RejectReason::WrongAgent);
    }
    if p.issued_at - now > CLOCK_SKEW_SECS {
        return Err(RejectReason::NotYetValid);
    }
    if now >= p.expires_at {
        return Err(RejectReason::Expired);
    }
    if p.expires_at - p.issued_at > MAX_COMMAND_WINDOW_SECS {
        return Err(RejectReason::WindowTooLong);
    }
    if !replay.admit(p.command_id, p.expires_at) {
        return Err(RejectReason::Replay);
    }

    Ok(p.command.clone())
}

/// In-memory replay guard keyed by `command_id`, pruned by expiry.
///
/// A command is only ever admitted once. Entries are dropped once their
/// `expires_at` passes (a command past expiry is rejected earlier anyway), so
/// the cache stays bounded by the validity window, not by total traffic.
#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashMap<Uuid, i64>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Record `command_id` if unseen; returns false if it was already present.
    pub fn admit(&mut self, command_id: Uuid, expires_at: i64) -> bool {
        if self.seen.contains_key(&command_id) {
            return false;
        }
        self.seen.insert(command_id, expires_at);
        true
    }

    /// Drop entries whose expiry is at or before `now`. Call periodically.
    pub fn prune(&mut self, now: i64) {
        self.seen.retain(|_, &mut exp| exp > now);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signing_key;

    fn envelope(agent_id: &str, issued_at: i64, ttl: i64) -> CommandEnvelope {
        CommandEnvelope {
            version: PROTOCOL_VERSION,
            command_id: Uuid::new_v4(),
            agent_id: agent_id.to_string(),
            command: Command::Ping,
            issued_at,
            expires_at: issued_at + ttl,
            nonce: [9u8; 16],
        }
    }

    #[test]
    fn valid_command_admitted() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        let cmd = verify_and_admit(&signed, &vk, "agent-1", 1005, &mut rc).unwrap();
        assert_eq!(cmd, Command::Ping);
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let mut signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        signed.payload.command = Command::Reboot { delay_secs: 0 };
        let mut rc = ReplayCache::new();
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-1", 1005, &mut rc).unwrap_err(),
            RejectReason::BadSignature
        );
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let key = generate_signing_key();
        let other = generate_signing_key();
        let signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        assert_eq!(
            verify_and_admit(&signed, &other.verifying_key(), "agent-1", 1005, &mut rc)
                .unwrap_err(),
            RejectReason::BadSignature
        );
    }

    #[test]
    fn wrong_agent_rejected() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-2", 1005, &mut rc).unwrap_err(),
            RejectReason::WrongAgent
        );
    }

    #[test]
    fn expired_rejected() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-1", 1031, &mut rc).unwrap_err(),
            RejectReason::Expired
        );
    }

    #[test]
    fn future_command_rejected() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed = sign_command(envelope("agent-1", 5000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        // now is well before issued_at, beyond allowed skew
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-1", 1000, &mut rc).unwrap_err(),
            RejectReason::NotYetValid
        );
    }

    #[test]
    fn overlong_window_rejected() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed =
            sign_command(envelope("agent-1", 1000, MAX_COMMAND_WINDOW_SECS + 1), &key).unwrap();
        let mut rc = ReplayCache::new();
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-1", 1005, &mut rc).unwrap_err(),
            RejectReason::WindowTooLong
        );
    }

    #[test]
    fn replay_rejected_second_time() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let signed = sign_command(envelope("agent-1", 1000, 30), &key).unwrap();
        let mut rc = ReplayCache::new();
        assert!(verify_and_admit(&signed, &vk, "agent-1", 1005, &mut rc).is_ok());
        assert_eq!(
            verify_and_admit(&signed, &vk, "agent-1", 1006, &mut rc).unwrap_err(),
            RejectReason::Replay
        );
    }

    #[test]
    fn replay_cache_prunes_expired() {
        let mut rc = ReplayCache::new();
        rc.admit(Uuid::new_v4(), 100);
        rc.admit(Uuid::new_v4(), 200);
        assert_eq!(rc.len(), 2);
        rc.prune(150);
        assert_eq!(rc.len(), 1);
    }

    #[test]
    fn bincode_roundtrip_stable() {
        let key = generate_signing_key();
        let signed = sign_command(envelope("agent-x", 1000, 30), &key).unwrap();
        let bytes = serialize(&signed).unwrap();
        let back = deserialize(&bytes).unwrap();
        assert_eq!(back.signature, signed.signature);
        assert_eq!(back.payload.agent_id, "agent-x");
    }

    #[test]
    fn selfupdate_command_roundtrips() {
        let key = generate_signing_key();
        let mut env = envelope("agent-1", 1000, 30);
        env.command = Command::SelfUpdate {
            url: "https://srv/netagent".into(),
            version: "1.0.1".into(),
            sha256: "ab".repeat(32),
            binary_sig: [7u8; SIG_LEN],
        };
        let signed = sign_command(env, &key).unwrap();
        let bytes = serialize(&signed).unwrap();
        let back = deserialize(&bytes).unwrap();
        match back.payload.command {
            Command::SelfUpdate { binary_sig, .. } => assert_eq!(binary_sig, [7u8; SIG_LEN]),
            _ => panic!("wrong variant"),
        }
    }
}
