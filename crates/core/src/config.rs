//! Agent configuration + persisted enrollment state.
//!
//! `Config` is operator-provided (TOML + env), set at deploy time. `EnrollState`
//! is written by the agent after a successful enrollment and holds the assigned
//! `agent_id` and the **pinned** NetEdge command public key the agent verifies
//! every command against. The two are kept in separate files so the operator's
//! config is never rewritten by the agent.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

/// Exec authorization policy. The secure default — `Default::default()` —
/// is `allow_arbitrary = false` with an empty allow-list, i.e. no exec at all
/// until NetEdge grants specific programs per group, or marks the group
/// administrative. (The derived defaults coincide with that secure baseline.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecPolicy {
    /// Allow arbitrary commands (only for groups explicitly marked administrative).
    #[serde(default)]
    pub allow_arbitrary: bool,
    /// Program basenames permitted when `allow_arbitrary` is false.
    #[serde(default)]
    pub allow_list: Vec<String>,
}

impl ExecPolicy {
    /// Whether a given program is permitted by this policy.
    pub fn permits(&self, program: &str) -> bool {
        if self.allow_arbitrary {
            return true;
        }
        let base = program_basename(program);
        self.allow_list.iter().any(|p| program_basename(p) == base)
    }
}

fn program_basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(p)
        .to_ascii_lowercase()
}

fn default_heartbeat() -> u64 {
    45
}
fn default_poll() -> u64 {
    10
}
fn default_log() -> String {
    "info".to_string()
}

/// Operator-provided configuration (TOML file + `NETAGENT_*` env overrides).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Base URL of NetEdge, e.g. "https://netedge.local:8080".
    pub server_url: String,
    /// Directory holding the agent key + enrollment state. Default: alongside config.
    pub data_dir: PathBuf,
    /// One-time enrollment token minted by a NetEdge admin (only needed to enroll).
    #[serde(default)]
    pub enrollment_token: Option<String>,
    /// Expected TLS SPKI pin (sha256 hex) of the NetEdge server certificate.
    /// Required for https/wss; supports self-signed server certs without
    /// disabling verification.
    #[serde(default)]
    pub server_spki_pin: Option<String>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub exec_policy: ExecPolicy,
    #[serde(default = "default_log")]
    pub log_level: String,
}

impl Config {
    /// Load from a TOML file, then apply `NETAGENT_*` environment overrides.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CoreError::Config(format!("reading {}: {e}", path.display())))?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| CoreError::Config(format!("parsing {}: {e}", path.display())))?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("NETAGENT_SERVER_URL") {
            self.server_url = v;
        }
        if let Ok(v) = std::env::var("NETAGENT_ENROLLMENT_TOKEN") {
            self.enrollment_token = Some(v);
        }
        if let Ok(v) = std::env::var("NETAGENT_SPKI_PIN") {
            self.server_spki_pin = Some(v);
        }
        if let Ok(v) = std::env::var("NETAGENT_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("NETAGENT_LOG") {
            self.log_level = v;
        }
    }

    fn validate(&self) -> Result<()> {
        if self.server_url.is_empty() {
            return Err(CoreError::Config("server_url is required".into()));
        }
        let is_tls =
            self.server_url.starts_with("https://") || self.server_url.starts_with("wss://");
        if is_tls && self.server_spki_pin.is_none() {
            return Err(CoreError::Config(
                "server_spki_pin is required for https/wss server_url (we pin, never disable verification)".into(),
            ));
        }
        Ok(())
    }

    /// Path of the agent's private signing key.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join("agent.key")
    }

    /// Path of the persisted enrollment state.
    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }
}

/// Persisted after a successful enrollment. `server_command_pubkey` is the pin
/// the agent uses to verify every inbound command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollState {
    pub agent_id: String,
    /// Hex of NetEdge's command public key (pinned).
    pub server_command_pubkey: String,
    pub server_spki_pin: Option<String>,
    pub heartbeat_interval_secs: u64,
    pub poll_interval_secs: u64,
}

impl EnrollState {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|_| CoreError::NotEnrolled)?;
        serde_json::from_str(&text).map_err(|e| CoreError::Config(format!("parsing state: {e}")))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text =
            serde_json::to_string_pretty(self).map_err(|e| CoreError::Serde(e.to_string()))?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_policy_deny_by_default() {
        let p = ExecPolicy::default();
        assert!(!p.permits("/bin/ls"));
        assert!(!p.allow_arbitrary);
    }

    #[test]
    fn exec_policy_allow_list_matches_basename() {
        let p = ExecPolicy {
            allow_arbitrary: false,
            allow_list: vec!["uptime".into(), "ipconfig.exe".into()],
        };
        // basename match, with or without a directory prefix
        assert!(p.permits("uptime"));
        assert!(p.permits("/usr/bin/uptime"));
        // allow-list entries match exactly including extension
        assert!(p.permits("C:/Windows/System32/ipconfig.exe"));
        assert!(!p.permits("ipconfig")); // "ipconfig" != "ipconfig.exe"
        assert!(!p.permits("rm"));
    }

    #[test]
    fn exec_policy_arbitrary_allows_all() {
        let p = ExecPolicy {
            allow_arbitrary: true,
            allow_list: vec![],
        };
        assert!(p.permits("anything"));
    }

    #[test]
    fn tls_url_requires_pin() {
        let cfg = Config {
            server_url: "https://x".into(),
            data_dir: PathBuf::from("/tmp"),
            enrollment_token: None,
            server_spki_pin: None,
            heartbeat_interval_secs: 45,
            poll_interval_secs: 10,
            exec_policy: ExecPolicy::default(),
            log_level: "info".into(),
        };
        assert!(cfg.validate().is_err());
    }
}
