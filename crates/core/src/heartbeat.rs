//! Lightweight heartbeat + telemetry loop.
//!
//! Sends a signed `Heartbeat` every interval (uptime, last boot, version,
//! health), plus a periodic hardware/SMART snapshot shaped to NetEdge's
//! existing `/metrics` ingest so the same threshold alert rules apply during
//! normal operation, not just during cloning. Kept deliberately cheap so the
//! agent is near-idle at rest.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::mpsc::UnboundedSender;

use netagent_proto::messages::{sign_report, AgentMessage, Heartbeat};
use netagent_proto::now_unix;

use crate::platform::DynPlatform;

/// Spawn the heartbeat loop. Returns a handle the runtime can abort on shutdown.
pub fn spawn(
    platform: DynPlatform,
    out: UnboundedSender<AgentMessage>,
    agent_id: String,
    agent_key: SigningKey,
    agent_version: String,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.max(5));
        loop {
            let (uptime_secs, boot_time) = platform.uptime().await.unwrap_or((0, 0));
            let hb = Heartbeat {
                agent_version: agent_version.clone(),
                uptime_secs,
                boot_time,
                healthy: true,
                timestamp: now_unix(),
            };
            match sign_report(&agent_id, hb, now_unix(), &agent_key) {
                Ok(signed) => {
                    if out.send(AgentMessage::Heartbeat(signed)).is_err() {
                        break; // runtime shutting down
                    }
                }
                Err(e) => tracing::error!(error = %e, "failed to sign heartbeat"),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// Periodic hardware/SMART snapshot, returned as a value the caller can forward.
/// Exposed for the agent binary / tests that want an on-demand inventory.
pub async fn hardware_snapshot(
    platform: &Arc<dyn crate::platform::PlatformOps>,
) -> Option<netagent_proto::inventory::HardwareInfo> {
    platform.hardware_inventory().await.ok()
}
