//! Service install/uninstall helpers.
//!
//! On Linux this writes a systemd unit with `Restart=always` (the watchdog —
//! systemd restarts the daemon if it dies unexpectedly). On Windows it registers
//! a Service Control Manager service with auto-restart recovery (see the
//! `windows` module for the runtime side). A non-systemd Linux fallback is
//! documented in README.md (run under your init of choice; the agent
//! is a well-behaved foreground process).

use std::path::Path;

#[cfg(target_os = "linux")]
const UNIT_TEMPLATE: &str = "\
[Unit]
Description=Netagent (NetEdge management agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} --config {config} run
Restart=always
RestartSec=5
# Least privilege: the agent needs root only for reboot/network/hostname ops.
# Tighten further per deployment as appropriate.

[Install]
WantedBy=multi-user.target
";

#[cfg(target_os = "linux")]
pub fn install(config_path: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let unit = UNIT_TEMPLATE
        .replace("{exe}", &exe.display().to_string())
        .replace("{config}", &config_path.display().to_string());
    std::fs::write("/etc/systemd/system/netagent.service", unit)?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "netagent"])?;
    println!("installed and started systemd service: netagent");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> anyhow::Result<()> {
    let _ = run("systemctl", &["disable", "--now", "netagent"]);
    let _ = std::fs::remove_file("/etc/systemd/system/netagent.service");
    let _ = run("systemctl", &["daemon-reload"]);
    println!("removed systemd service: netagent");
    Ok(())
}

#[cfg(target_os = "linux")]
fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{program} {args:?} exited with {status}");
    }
    Ok(())
}

#[cfg(windows)]
pub fn install(config_path: &Path) -> anyhow::Result<()> {
    crate::windows_service_glue::install(config_path)
}

#[cfg(windows)]
pub fn uninstall() -> anyhow::Result<()> {
    crate::windows_service_glue::uninstall()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn install(_config_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "service install is not supported on this OS; run `netagent run` under your init system"
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn uninstall() -> anyhow::Result<()> {
    anyhow::bail!("service uninstall is not supported on this OS")
}
