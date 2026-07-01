//! Command dispatch: the security gate + executor.
//!
//! Every inbound `ServerMessage::Command` is run through
//! `proto::verify_and_admit` (signature against the pinned key, agent match,
//! timestamp window, replay cache). Admitted commands are executed via the
//! platform layer / feature modules and reported back with a signed
//! `CommandResult`; refused commands are reported as a `RejectedCommandReport`
//! and audited — never silently dropped.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::Mutex;
use tokio::sync::mpsc::UnboundedSender;

use netagent_proto::command::{Command, ReplayCache, SignedCommand};
use netagent_proto::messages::{
    sign_report, AgentMessage, CommandAck, CommandResult, RejectedCommandReport, ResultData,
    ServerMessage,
};
use netagent_proto::now_unix;

use crate::config::ExecPolicy;
use crate::platform::{DynPlatform, ExecSpec};
use crate::scheduler::PowerScheduler;
use crate::shell::ShellManager;
use crate::{snapin, updater};

/// Shared dispatcher state. Cheap to clone-wrap in an `Arc`.
pub struct Dispatcher {
    agent_id: String,
    agent_key: SigningKey,
    server_cmd_key: VerifyingKey,
    exec_policy: ExecPolicy,
    platform: DynPlatform,
    out: UnboundedSender<AgentMessage>,
    replay: Mutex<ReplayCache>,
    scheduler: PowerScheduler,
    shells: ShellManager,
    http: reqwest::Client,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: String,
        agent_key: SigningKey,
        server_cmd_key: VerifyingKey,
        exec_policy: ExecPolicy,
        platform: DynPlatform,
        out: UnboundedSender<AgentMessage>,
        http: reqwest::Client,
    ) -> Self {
        let scheduler = PowerScheduler::new(platform.clone());
        let shells = ShellManager::new(out.clone());
        Self {
            agent_id,
            agent_key,
            server_cmd_key,
            exec_policy,
            platform,
            out,
            replay: Mutex::new(ReplayCache::new()),
            scheduler,
            shells,
            http,
        }
    }

    /// Handle one server message.
    pub async fn handle(self: &Arc<Self>, msg: ServerMessage) {
        match msg {
            ServerMessage::Command(signed) => self.handle_command(*signed).await,
            ServerMessage::ShellInput {
                session_id,
                data_b64,
            } => self.shells.feed(&session_id, &data_b64),
            ServerMessage::ShellClose { session_id } => self.shells.close(&session_id),
            ServerMessage::Pong => {}
        }
    }

    async fn handle_command(self: &Arc<Self>, signed: SignedCommand) {
        let claimed_id = signed.payload.command_id;
        let now = now_unix();

        let admitted = {
            let mut rc = self.replay.lock();
            netagent_proto::command::verify_and_admit(
                &signed,
                &self.server_cmd_key,
                &self.agent_id,
                now,
                &mut rc,
            )
        };

        let cmd = match admitted {
            Ok(cmd) => cmd,
            Err(reason) => {
                tracing::warn!(command_id = %claimed_id, %reason, "command rejected");
                self.send(AgentMessage::Rejected(self.sign(RejectedCommandReport {
                    command_id: Some(claimed_id),
                    reason,
                    detail: reason.to_string(),
                    at: now,
                })));
                return;
            }
        };

        // Acknowledge receipt before executing.
        self.send(AgentMessage::Ack(self.sign(CommandAck {
            command_id: claimed_id,
            at: now,
        })));

        let result = self.execute(claimed_id, cmd).await;
        self.send(AgentMessage::Result(self.sign(result)));
    }

    async fn execute(self: &Arc<Self>, command_id: uuid::Uuid, cmd: Command) -> CommandResult {
        match cmd {
            Command::Ping => ok(command_id, "pong", None),

            Command::Reboot { delay_secs } => {
                self.spawn_power(true, delay_secs);
                ok(
                    command_id,
                    &format!("reboot scheduled in {delay_secs}s"),
                    None,
                )
            }
            Command::Shutdown { delay_secs } => {
                self.spawn_power(false, delay_secs);
                ok(
                    command_id,
                    &format!("shutdown scheduled in {delay_secs}s"),
                    None,
                )
            }

            Command::Exec {
                program,
                args,
                timeout_secs,
                cwd,
                env,
            } => {
                if !self.exec_policy.permits(&program) {
                    return fail(command_id, &format!("exec denied by policy: {program}"));
                }
                match self
                    .platform
                    .exec(ExecSpec {
                        program,
                        args,
                        timeout_secs,
                        cwd,
                        env,
                    })
                    .await
                {
                    Ok(o) => CommandResult {
                        command_id,
                        ok: o.exit_code == Some(0) && !o.timed_out,
                        exit_code: o.exit_code,
                        stdout: o.stdout,
                        stderr: o.stderr,
                        message: if o.timed_out {
                            "timed out".into()
                        } else {
                            "executed".into()
                        },
                        finished_at: now_unix(),
                        data: None,
                    },
                    Err(e) => fail(command_id, &format!("exec failed: {e}")),
                }
            }

            Command::SetHostname { name, reboot } => {
                match self.platform.set_hostname(&name, reboot).await {
                    Ok(()) => ok(command_id, &format!("hostname set to {name}"), None),
                    Err(e) => fail(command_id, &format!("set_hostname failed: {e}")),
                }
            }

            Command::SetNetwork(cfg) => match self.platform.set_network(&cfg).await {
                Ok(report) => ok(
                    command_id,
                    "network applied",
                    Some(ResultData::Network(report)),
                ),
                Err(e) => fail(command_id, &format!("set_network failed: {e}")),
            },

            Command::GetDrivers => match self.platform.driver_inventory().await {
                Ok(d) => ok(command_id, "drivers", Some(ResultData::Drivers(d))),
                Err(e) => fail(command_id, &format!("driver_inventory failed: {e}")),
            },
            Command::GetMissingDrivers => match self.platform.missing_drivers().await {
                Ok(d) => ok(
                    command_id,
                    "missing drivers",
                    Some(ResultData::MissingDrivers(d)),
                ),
                Err(e) => fail(command_id, &format!("missing_drivers failed: {e}")),
            },
            Command::GetSoftwareInventory => match self.platform.software_inventory().await {
                Ok(s) => ok(command_id, "software", Some(ResultData::Software(s))),
                Err(e) => fail(command_id, &format!("software_inventory failed: {e}")),
            },
            Command::GetHardware => match self.platform.hardware_inventory().await {
                Ok(h) => ok(command_id, "hardware", Some(ResultData::Hardware(h))),
                Err(e) => fail(command_id, &format!("hardware_inventory failed: {e}")),
            },

            Command::InstallPackage(spec) => {
                let report = snapin::run(&spec, &self.http, &self.platform).await;
                let okk = report.ok;
                let detail = report.detail.clone();
                let res = ok(command_id, "install", Some(ResultData::Install(report)));
                if okk {
                    res
                } else {
                    CommandResult {
                        ok: false,
                        message: detail,
                        ..res
                    }
                }
            }

            Command::SchedulePower(sched) => {
                self.scheduler.schedule(sched);
                ok(command_id, "power action scheduled", None)
            }
            Command::CancelScheduledPower => {
                self.scheduler.cancel();
                ok(command_id, "scheduled power action cancelled", None)
            }

            Command::OpenShell { session_id } => match self.shells.open(&session_id) {
                Ok(()) => ok(command_id, &format!("shell {session_id} opened"), None),
                Err(e) => fail(command_id, &format!("open shell failed: {e}")),
            },

            Command::SelfUpdate {
                url,
                version,
                sha256,
                binary_sig,
            } => {
                match updater::apply(
                    &self.http,
                    &url,
                    &version,
                    &sha256,
                    &binary_sig,
                    &self.server_cmd_key,
                )
                .await
                {
                    Ok(()) => {
                        self.spawn_exit("self-update applied, restarting");
                        ok(
                            command_id,
                            &format!("updated to {version}; restarting"),
                            None,
                        )
                    }
                    Err(e) => fail(command_id, &format!("self-update failed: {e}")),
                }
            }

            Command::Uninstall => match self.platform.uninstall().await {
                Ok(()) => {
                    self.spawn_exit("authorized uninstall");
                    ok(command_id, "uninstalled", None)
                }
                Err(e) => fail(command_id, &format!("uninstall failed: {e}")),
            },
        }
    }

    /// Trigger reboot/shutdown after a short grace so the result can flush.
    fn spawn_power(self: &Arc<Self>, reboot: bool, delay_secs: u32) {
        let platform = self.platform.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let r = if reboot {
                platform.reboot(delay_secs).await
            } else {
                platform.shutdown(delay_secs).await
            };
            if let Err(e) = r {
                tracing::error!(error = %e, "power action failed");
            }
        });
    }

    /// Exit the process after a short grace (service manager restarts us, or
    /// for uninstall the service is already being removed).
    fn spawn_exit(self: &Arc<Self>, why: &str) {
        let why = why.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            tracing::info!("exiting: {why}");
            std::process::exit(0);
        });
    }

    fn sign<T: serde::Serialize>(&self, inner: T) -> netagent_proto::messages::SignedReport<T> {
        // Signing only fails on a serialization bug; impossible for our internal
        // types, so we surface it loudly via expect.
        sign_report(&self.agent_id, inner, now_unix(), &self.agent_key)
            .expect("signing agent report")
    }

    fn send(&self, msg: AgentMessage) {
        if self.out.send(msg).is_err() {
            tracing::warn!("outbound channel closed; dropping message");
        }
    }
}

fn ok(command_id: uuid::Uuid, message: &str, data: Option<ResultData>) -> CommandResult {
    CommandResult {
        command_id,
        ok: true,
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        message: message.to_string(),
        finished_at: now_unix(),
        data,
    }
}

fn fail(command_id: uuid::Uuid, message: &str) -> CommandResult {
    CommandResult {
        command_id,
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        message: message.to_string(),
        finished_at: now_unix(),
        data: None,
    }
}
