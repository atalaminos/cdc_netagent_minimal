//! Cross-platform helpers shared by the per-OS implementations: process
//! execution with a timeout, hardware inventory via `sysinfo`, and identity
//! gathering for enrollment.

use std::time::Duration;

use sha2::{Digest, Sha256};
use sysinfo::{Disks, Networks, System};
use tokio::io::AsyncReadExt;

use netagent_core::{ExecOutput, ExecSpec, Identity};
use netagent_proto::inventory::{DiskInfo, HardwareInfo, NicInfo};

/// Run a program capturing stdout/stderr, killing it if it exceeds the timeout.
pub async fn run_with_timeout(spec: ExecSpec) -> ExecOutput {
    use std::process::Stdio;
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ExecOutput {
                exit_code: None,
                stdout: String::new(),
                stderr: format!("spawn failed: {e}"),
                timed_out: false,
            }
        }
    };

    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let read_out = tokio::spawn(async move {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b).await;
        }
        b
    });
    let read_err = tokio::spawn(async move {
        let mut b = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.read_to_end(&mut b).await;
        }
        b
    });

    let dur = Duration::from_secs(spec.timeout_secs.max(1) as u64);
    let (exit_code, timed_out) = match tokio::time::timeout(dur, child.wait()).await {
        Ok(Ok(status)) => (status.code(), false),
        Ok(Err(_)) => (None, false),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            (None, true)
        }
    };

    let stdout = String::from_utf8_lossy(&read_out.await.unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&read_err.await.unwrap_or_default()).into_owned();
    ExecOutput {
        exit_code,
        stdout,
        stderr,
        timed_out,
    }
}

/// Blocking convenience used by sync code paths: run + collect once.
pub fn run_blocking(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(program).args(args).output()
}

/// Collect a hardware snapshot via `sysinfo`. SMART is filled in per-OS.
pub fn hardware_inventory() -> HardwareInfo {
    let sys = System::new_all();
    let cpu_model = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .unwrap_or_default();
    let cpu_cores = sys.cpus().len();

    let disks = Disks::new_with_refreshed_list()
        .iter()
        .map(|d| DiskInfo {
            name: d.name().to_string_lossy().into_owned(),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
            kind: format!("{:?}", d.kind()),
        })
        .collect();

    let nics = Networks::new_with_refreshed_list()
        .iter()
        .map(|(name, data)| NicInfo {
            name: name.clone(),
            mac: data.mac_address().to_string(),
            ips: data
                .ip_networks()
                .iter()
                .map(|n| n.addr.to_string())
                .collect(),
        })
        .collect();

    HardwareInfo {
        cpu_model,
        cpu_cores,
        ram_total_bytes: sys.total_memory(),
        ram_used_bytes: sys.used_memory(),
        disks,
        nics,
        smart: Vec::new(),
    }
}

/// `(uptime_secs, boot_time_unix)`.
pub fn uptime() -> (u64, i64) {
    (System::uptime(), System::boot_time() as i64)
}

/// First non-loopback interface MAC (best-effort), as "aa:bb:cc:dd:ee:ff".
pub fn primary_mac() -> String {
    let nets = Networks::new_with_refreshed_list();
    for (name, data) in &nets {
        let mac = data.mac_address().to_string();
        if name != "lo" && mac != "00:00:00:00:00:00" {
            return mac;
        }
    }
    "00:00:00:00:00:00".to_string()
}

/// Gather the identity facts NetEdge needs to enroll this machine. The
/// fingerprint is a stable hash of hostname + primary MAC + machine-id.
pub fn identity(version: &str, machine_id: &str) -> Identity {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let mac = primary_mac();
    let mut h = Sha256::new();
    h.update(format!("{hostname}|{mac}|{machine_id}").as_bytes());
    let machine_fingerprint = hex::encode(h.finalize());
    let os = format!(
        "{} {}",
        std::env::consts::OS,
        System::long_os_version().unwrap_or_default()
    )
    .trim()
    .to_string();
    Identity {
        hostname,
        mac,
        machine_fingerprint,
        os,
        agent_version: version.to_string(),
    }
}
