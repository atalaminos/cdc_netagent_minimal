//! The agent runtime: connect, receive commands, dispatch, report, heartbeat.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use netagent_proto::crypto::verifying_key_from_hex;

use crate::config::{Config, EnrollState};
use crate::dispatcher::Dispatcher;
use crate::enroll::load_or_create_key;
use crate::error::{CoreError, Result};
use crate::heartbeat;
use crate::platform::DynPlatform;
use crate::transport::{build_http_client, Transport};

/// Runtime tunables (mostly for tests).
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Try WebSocket first (true) or go straight to HTTP polling (false).
    pub prefer_ws: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self { prefer_ws: true }
    }
}

/// The agent. `run` blocks until the inbound stream ends (shutdown).
pub struct Agent;

impl Agent {
    /// Load enrollment state + key and run the full agent loop.
    pub async fn run(
        config: Config,
        platform: DynPlatform,
        agent_version: &str,
        opts: RuntimeOptions,
    ) -> Result<()> {
        let state = EnrollState::load(&config.state_path())?;
        Self::run_with_state(config, state, platform, agent_version, opts).await
    }

    /// Like [`run`], with the enrollment state already in hand.
    pub async fn run_with_state(
        config: Config,
        state: EnrollState,
        platform: DynPlatform,
        agent_version: &str,
        opts: RuntimeOptions,
    ) -> Result<()> {
        let key = load_or_create_key(&config.key_path())?;
        let server_cmd_key = verifying_key_from_hex(&state.server_command_pubkey)
            .map_err(|e| CoreError::Config(format!("stored command pubkey invalid: {e}")))?;
        let pin = state
            .server_spki_pin
            .clone()
            .or_else(|| config.server_spki_pin.clone());
        let http = build_http_client(&config.server_url, pin.as_deref())?;

        let (in_tx, mut in_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();

        let dispatcher = Arc::new(Dispatcher::new(
            state.agent_id.clone(),
            key.clone(),
            server_cmd_key,
            config.exec_policy.clone(),
            platform.clone(),
            out_tx.clone(),
            http,
        ));

        let transport = Transport::new(&config.server_url, &state.agent_id, pin.as_deref())?
            .with_prefer_ws(opts.prefer_ws);

        let hb = heartbeat::spawn(
            platform.clone(),
            out_tx.clone(),
            state.agent_id.clone(),
            key,
            agent_version.to_string(),
            state.heartbeat_interval_secs,
        );

        let poll = Duration::from_secs(state.poll_interval_secs.max(1));
        let transport_task = tokio::spawn(transport.run(in_tx, out_rx, poll));

        tracing::info!(agent_id = %state.agent_id, "agent running");

        while let Some(msg) = in_rx.recv().await {
            let d = dispatcher.clone();
            tokio::spawn(async move {
                d.handle(msg).await;
            });
        }

        hb.abort();
        let _ = transport_task.await;
        Ok(())
    }
}
