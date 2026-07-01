//! Windows Service Control Manager integration.
//!
//! `install`/`uninstall` register the service via `sc.exe`, including auto-restart
//! recovery actions (the watchdog: the SCM restarts the agent if it dies).
//! `dispatch_if_service` hands control to the SCM dispatcher when launched as a
//! service, and reports `false` when run from a console so the caller can run in
//! the foreground instead.
//!
//! Compiles only on Windows (gated at the `mod` declaration in `main.rs`);
//! build-checked via the windows-gnu target, validated on a real Windows host.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use netagent_core::Config;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "netagent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Config path stashed for the SCM service entry point (which takes no args).
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT — returned when not launched by SCM.
const NOT_A_SERVICE: i32 = 1063;

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Try to run as a service. Returns Ok(true) if we ran as a service (dispatcher
/// returned), Ok(false) if we are not running under the SCM (run in console).
pub fn dispatch_if_service(config_path: &Path) -> anyhow::Result<bool> {
    let _ = CONFIG_PATH.set(config_path.to_path_buf());
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
            Ok(false)
        }
        Err(e) => Err(anyhow::anyhow!("service dispatcher failed: {e}")),
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service exited with error");
    }
}

fn run_service() -> anyhow::Result<()> {
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // The agent has no graceful in-loop cancellation hook yet; the SCM
            // recovery action will restart us if needed. Exit promptly.
            std::process::exit(0);
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    let running = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running)?;

    let config_path = CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(crate::default_config_path);
    let config = Config::load(&config_path)?;
    let result = crate::run_agent_blocking(config);

    let stopped = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(stopped)?;
    result
}

/// Register the service via sc.exe with auto-restart recovery (the watchdog).
pub fn install(config_path: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let bin_path = format!(
        "\"{}\" --config \"{}\" run",
        exe.display(),
        config_path.display()
    );

    sc(&[
        "create",
        SERVICE_NAME,
        &format!("binPath= {bin_path}"),
        "start=",
        "auto",
        "DisplayName=",
        "Netagent",
    ])?;
    // Restart on each of the first three failures, 5s apart; reset count daily.
    sc(&[
        "failure",
        SERVICE_NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/5000/restart/5000",
    ])?;
    sc(&["start", SERVICE_NAME])?;
    println!("installed and started Windows service: {SERVICE_NAME}");
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let _ = sc(&["stop", SERVICE_NAME]);
    sc(&["delete", SERVICE_NAME])?;
    println!("removed Windows service: {SERVICE_NAME}");
    Ok(())
}

fn sc(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("sc.exe").args(args).status()?;
    if !status.success() {
        anyhow::bail!("sc.exe {args:?} exited with {status}");
    }
    Ok(())
}
