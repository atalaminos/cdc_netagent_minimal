//! Enrollment: establish the agent's per-device identity with NetEdge.
//!
//! The agent generates its own Ed25519 keypair (once), then presents its public
//! key plus a one-time `enrollment_token` to NetEdge. NetEdge returns the agent
//! id and the command public key the agent must pin. The token is never reused
//! for command auth — it only bootstraps identity. NetEdge can revoke a single
//! agent's public key without affecting any other agent.

use ed25519_dalek::SigningKey;
use std::path::Path;

use netagent_proto::crypto::{
    generate_signing_key, load_signing_key, save_signing_key, verifying_key_to_hex,
};
use netagent_proto::messages::EnrollRequest;

use crate::config::{Config, EnrollState};
use crate::error::{CoreError, Result};
use crate::transport::Transport;

/// Identity facts the platform layer supplies for enrollment + heartbeats.
#[derive(Debug, Clone)]
pub struct Identity {
    pub hostname: String,
    pub mac: String,
    pub machine_fingerprint: String,
    pub os: String,
    pub agent_version: String,
}

/// Load the agent signing key, creating + persisting it (0600) if absent.
pub fn load_or_create_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        Ok(load_signing_key(path)?)
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = generate_signing_key();
        save_signing_key(path, &key)?;
        Ok(key)
    }
}

/// Run the full enrollment flow and persist the resulting state.
pub async fn enroll(config: &Config, id: &Identity) -> Result<EnrollState> {
    std::fs::create_dir_all(&config.data_dir)?;
    let key = load_or_create_key(&config.key_path())?;
    let agent_pubkey = verifying_key_to_hex(&key.verifying_key());

    let token = config
        .enrollment_token
        .clone()
        .ok_or_else(|| CoreError::Enroll("enrollment_token not configured".into()))?;

    let req = EnrollRequest {
        enrollment_token: token,
        agent_pubkey,
        hostname: id.hostname.clone(),
        mac: id.mac.clone(),
        machine_fingerprint: id.machine_fingerprint.clone(),
        agent_version: id.agent_version.clone(),
        os: id.os.clone(),
    };

    let resp =
        Transport::enroll(&config.server_url, config.server_spki_pin.as_deref(), &req).await?;

    // Sanity-check the returned command key parses before we persist it.
    netagent_proto::crypto::verifying_key_from_hex(&resp.server_command_pubkey).map_err(|e| {
        CoreError::Enroll(format!("server returned an invalid command pubkey: {e}"))
    })?;

    let state = EnrollState {
        agent_id: resp.agent_id,
        server_command_pubkey: resp.server_command_pubkey,
        server_spki_pin: resp
            .server_spki_pin
            .or_else(|| config.server_spki_pin.clone()),
        heartbeat_interval_secs: if resp.heartbeat_interval_secs > 0 {
            resp.heartbeat_interval_secs
        } else {
            config.heartbeat_interval_secs
        },
        poll_interval_secs: if resp.poll_interval_secs > 0 {
            resp.poll_interval_secs
        } else {
            config.poll_interval_secs
        },
    };
    state.save(&config.state_path())?;
    Ok(state)
}
