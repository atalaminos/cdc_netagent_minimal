//! Power scheduling: deferred reboot/shutdown in a maintenance window, with an
//! optional "skip if a user session is active" policy. Only one schedule is
//! pending at a time; a new schedule replaces the old.

use parking_lot::Mutex;
use std::sync::Arc;
use tokio::task::JoinHandle;

use netagent_proto::command::{PowerAction, PowerSchedule};

use crate::platform::DynPlatform;

#[derive(Clone)]
pub struct PowerScheduler {
    platform: DynPlatform,
    pending: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PowerScheduler {
    pub fn new(platform: DynPlatform) -> Self {
        Self {
            platform,
            pending: Arc::new(Mutex::new(None)),
        }
    }

    /// Schedule (or replace) a pending power action.
    pub fn schedule(&self, sched: PowerSchedule) {
        self.cancel();
        let platform = self.platform.clone();
        let handle = tokio::spawn(async move {
            let now = netagent_proto::now_unix();
            let wait = (sched.at - now).max(0) as u64;
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

            if sched.cancel_if_active {
                match platform.active_sessions().await {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!(
                            sessions = n,
                            "scheduled power action skipped: user session active"
                        );
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "could not check active sessions; proceeding")
                    }
                }
            }

            let res = match sched.action {
                PowerAction::Reboot => platform.reboot(0).await,
                PowerAction::Shutdown => platform.shutdown(0).await,
            };
            if let Err(e) = res {
                tracing::error!(error = %e, "scheduled power action failed");
            }
        });
        *self.pending.lock() = Some(handle);
    }

    /// Cancel any pending power action.
    pub fn cancel(&self) {
        if let Some(h) = self.pending.lock().take() {
            h.abort();
        }
    }
}
