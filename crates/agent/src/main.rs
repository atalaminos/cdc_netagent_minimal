//! Netagent — the NetEdge management agent binary.
//!
//! A single cross-platform binary that runs as a service (systemd unit on Linux,
//! SCM service on Windows). It enrolls once to obtain a per-device identity, then
//! connects to NetEdge to receive Ed25519-signed commands and report telemetry.

mod service;

#[cfg(windows)]
mod windows_service_glue;

use std::path::PathBuf;

use anyhow::{bail, Context};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use netagent_core::{Agent, Config, EnrollState, RuntimeOptions};
use netagent_proto::command::{deserialize, verify_and_admit, Command, ReplayCache};
use netagent_proto::crypto::verifying_key_from_hex;
use netagent_proto::now_unix;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "netagent", version = VERSION, about = "NetEdge management agent")]
struct Cli {
    /// Path to the agent config TOML.
    #[arg(short, long, env = "NETAGENT_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent (default). Auto-enrolls if a token is configured and we are not yet enrolled.
    Run,
    /// Enroll with NetEdge and persist the per-device identity.
    Enroll,
    /// Install the OS service (systemd unit / Windows SCM).
    InstallService,
    /// Remove the OS service.
    UninstallService,
    /// Self-uninstall — requires a NetEdge-signed Uninstall authorization (base64).
    Uninstall {
        /// base64(bincode(SignedCommand)) carrying a Command::Uninstall for this agent.
        #[arg(long)]
        authorized_by: String,
    },
    /// Print version.
    Version,
}

pub(crate) fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Netagent\agent.toml")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/netagent/agent.toml")
    }
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

/// A fresh multi-threaded tokio runtime. We build it explicitly (rather than
/// `#[tokio::main]`) so the Windows SCM dispatcher — which runs the service body
/// on its own thread — can stand up its own runtime without nesting.
fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Runtime::new()?)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Cmd::Run);

    if let Cmd::Version = cmd {
        println!("netagent {VERSION}");
        return Ok(());
    }

    let config_path = cli.config.unwrap_or_else(default_config_path);

    match cmd {
        Cmd::Run => run(config_path),
        Cmd::Enroll => runtime()?.block_on(cmd_enroll(config_path)),
        Cmd::InstallService => service::install(&config_path),
        Cmd::UninstallService => service::uninstall(),
        Cmd::Uninstall { authorized_by } => {
            runtime()?.block_on(cmd_uninstall(config_path, authorized_by))
        }
        Cmd::Version => unreachable!(),
    }
}

/// Load config; if not yet enrolled but a token is set, enroll automatically.
async fn load_or_enroll(config: &Config) -> anyhow::Result<EnrollState> {
    match EnrollState::load(&config.state_path()) {
        Ok(state) => Ok(state),
        Err(_) => {
            if config.enrollment_token.is_some() {
                tracing::info!("not yet enrolled; enrolling with configured token");
                let id = netagent_platform::identity(VERSION);
                netagent_core::enroll(config, &id)
                    .await
                    .context("auto-enrollment failed")
            } else {
                bail!(
                    "not enrolled and no enrollment_token configured; run `netagent enroll` first"
                )
            }
        }
    }
}

fn run(config_path: PathBuf) -> anyhow::Result<()> {
    let config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    init_logging(&config.log_level);

    // On Windows, if we were launched by the Service Control Manager, hand off to
    // the SCM dispatcher (it stands up its own runtime). Otherwise fall through
    // to a console/foreground run (also how it runs under systemd on Linux).
    #[cfg(windows)]
    {
        if windows_service_glue::dispatch_if_service(&config_path)? {
            return Ok(());
        }
    }

    runtime()?.block_on(async {
        let state = load_or_enroll(&config).await?;
        let platform = netagent_platform::current();
        Agent::run_with_state(config, state, platform, VERSION, RuntimeOptions::default())
            .await
            .context("agent runtime error")
    })
}

/// Shared console/service entry point used on Windows by the SCM dispatcher.
#[cfg(windows)]
pub(crate) fn run_agent_blocking(config: Config) -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let state = load_or_enroll(&config).await?;
        let platform = netagent_platform::current();
        Agent::run_with_state(config, state, platform, VERSION, RuntimeOptions::default())
            .await
            .context("agent runtime error")
    })
}

async fn cmd_enroll(config_path: PathBuf) -> anyhow::Result<()> {
    let config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    init_logging(&config.log_level);
    let id = netagent_platform::identity(VERSION);
    let state = netagent_core::enroll(&config, &id)
        .await
        .context("enrollment failed")?;
    println!(
        "enrolled: agent_id={} (pinned command key {})",
        state.agent_id,
        &state.server_command_pubkey[..16]
    );
    Ok(())
}

/// Self-uninstall, gated on a valid NetEdge-signed `Uninstall` command. A local
/// stop/kill cannot remove the agent — only a server-authorized command can.
async fn cmd_uninstall(config_path: PathBuf, authorized_by: String) -> anyhow::Result<()> {
    let config = Config::load(&config_path)?;
    init_logging(&config.log_level);
    let state = EnrollState::load(&config.state_path()).context("agent is not enrolled")?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(authorized_by.trim())
        .context("authorization is not valid base64")?;
    let signed = deserialize(&bytes).context("authorization is not a valid SignedCommand")?;
    let key = verifying_key_from_hex(&state.server_command_pubkey)?;

    let mut replay = ReplayCache::new();
    let cmd = verify_and_admit(&signed, &key, &state.agent_id, now_unix(), &mut replay)
        .map_err(|r| anyhow::anyhow!("authorization rejected: {r}"))?;
    if !matches!(cmd, Command::Uninstall) {
        bail!("authorization is valid but is not an Uninstall command");
    }

    let platform = netagent_platform::current();
    platform
        .uninstall()
        .await
        .context("platform uninstall failed")?;
    let _ = std::fs::remove_file(config.state_path());
    let _ = std::fs::remove_file(config.key_path());
    println!("netagent uninstalled (authorized by NetEdge)");
    Ok(())
}
