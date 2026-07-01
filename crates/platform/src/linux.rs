//! Linux implementation of [`PlatformOps`].
//!
//! Uses systemd where present (with direct syscall fallback for reboot/shutdown
//! and hostname), detects the active network manager before touching the
//! network — failing explicitly if none is recognized — and shells out to the
//! usual tools (lspci, dpkg/rpm, smartctl, who) for inventory.

use std::path::Path;

use async_trait::async_trait;

use netagent_core::platform::{
    Capabilities, ExecOutput, ExecSpec, PlatformError, PlatformOps, PlatformResult,
};
use netagent_proto::command::{IpMethod, NetworkConfig, PackageKind, PackageSpec, RebootPolicy};
use netagent_proto::inventory::{
    DriverInfo, HardwareInfo, InstallReport, MissingDriverDevice, NetApplyReport, SmartInfo,
    SoftwareInfo,
};

use crate::common;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

fn spawn_detached(cmdline: &str) {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmdline)
        .spawn();
}

async fn sh(program: &str, args: &[&str], timeout_secs: u32) -> ExecOutput {
    common::run_with_timeout(ExecSpec {
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        timeout_secs,
        cwd: None,
        env: vec![],
    })
    .await
}

#[async_trait]
impl PlatformOps for LinuxPlatform {
    async fn reboot(&self, delay_secs: u32) -> PlatformResult<()> {
        let base = if has_systemd() {
            "systemctl reboot"
        } else {
            "reboot"
        };
        if delay_secs == 0 {
            spawn_detached(base);
        } else {
            spawn_detached(&format!("sleep {delay_secs}; {base}"));
        }
        Ok(())
    }

    async fn shutdown(&self, delay_secs: u32) -> PlatformResult<()> {
        let base = if has_systemd() {
            "systemctl poweroff"
        } else {
            "poweroff"
        };
        if delay_secs == 0 {
            spawn_detached(base);
        } else {
            spawn_detached(&format!("sleep {delay_secs}; {base}"));
        }
        Ok(())
    }

    async fn exec(&self, spec: ExecSpec) -> PlatformResult<ExecOutput> {
        Ok(common::run_with_timeout(spec).await)
    }

    async fn set_hostname(&self, name: &str, reboot: RebootPolicy) -> PlatformResult<()> {
        let out = if has_systemd() {
            sh("hostnamectl", &["set-hostname", name], 15).await
        } else {
            // Fallback: live sethostname + persist to /etc/hostname.
            nix::unistd::sethostname(name)
                .map_err(|e| PlatformError::Failed(format!("sethostname: {e}")))?;
            let _ = std::fs::write("/etc/hostname", format!("{name}\n"));
            ExecOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
            }
        };
        if out.exit_code != Some(0) {
            return Err(PlatformError::Failed(format!(
                "set hostname failed: {}",
                out.stderr
            )));
        }
        match reboot {
            RebootPolicy::None => {}
            RebootPolicy::Immediate => self.reboot(0).await?,
            RebootPolicy::Deferred(secs) => self.reboot(secs).await?,
        }
        Ok(())
    }

    async fn set_network(&self, cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
        match detect_manager() {
            Some(NetManager::NetworkManager) => apply_networkmanager(cfg).await,
            Some(NetManager::Netplan) => apply_netplan(cfg).await,
            Some(NetManager::SystemdNetworkd) => apply_systemd_networkd(cfg).await,
            Some(NetManager::Ifupdown) => apply_ifupdown(cfg).await,
            None => Err(PlatformError::NoNetworkManager),
        }
    }

    async fn driver_inventory(&self) -> PlatformResult<Vec<DriverInfo>> {
        let out = sh("lspci", &["-k"], 20).await;
        Ok(parse_lspci(&out.stdout).0)
    }

    async fn missing_drivers(&self) -> PlatformResult<Vec<MissingDriverDevice>> {
        let out = sh("lspci", &["-k"], 20).await;
        Ok(parse_lspci(&out.stdout).1)
    }

    async fn software_inventory(&self) -> PlatformResult<Vec<SoftwareInfo>> {
        // Prefer dpkg, fall back to rpm.
        let dpkg = sh("dpkg-query", &["-W", "-f=${Package}\t${Version}\n"], 30).await;
        if dpkg.exit_code == Some(0) && !dpkg.stdout.is_empty() {
            return Ok(parse_pkg_list(&dpkg.stdout, "dpkg"));
        }
        let rpm = sh("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}\n"], 30).await;
        if rpm.exit_code == Some(0) {
            return Ok(parse_pkg_list(&rpm.stdout, "rpm"));
        }
        Ok(vec![])
    }

    async fn hardware_inventory(&self) -> PlatformResult<HardwareInfo> {
        let mut hw = common::hardware_inventory();
        hw.smart = self.smart().await.unwrap_or_default();
        Ok(hw)
    }

    async fn smart(&self) -> PlatformResult<Vec<SmartInfo>> {
        let scan = sh("smartctl", &["--scan"], 15).await;
        if scan.exit_code != Some(0) {
            return Ok(vec![]); // smartctl absent or unprivileged — best-effort
        }
        let mut out = Vec::new();
        for line in scan.stdout.lines() {
            // lines look like: "/dev/sda -d sat # ..."
            let Some(dev) = line.split_whitespace().next() else {
                continue;
            };
            if !dev.starts_with("/dev/") {
                continue;
            }
            let info = sh("smartctl", &["-H", "-A", dev], 20).await;
            out.push(parse_smart(dev, &info.stdout));
        }
        Ok(out)
    }

    async fn install_package(
        &self,
        spec: &PackageSpec,
        artifact: &Path,
    ) -> PlatformResult<InstallReport> {
        let p = artifact.to_string_lossy().to_string();
        let out = match spec.kind {
            PackageKind::Deb => {
                let r = sh("dpkg", &["-i", &p], 600).await;
                if r.exit_code != Some(0) {
                    // resolve deps
                    let _ = sh("apt-get", &["-f", "install", "-y"], 600).await;
                }
                r
            }
            PackageKind::Rpm => sh("rpm", &["-Uvh", "--replacepkgs", &p], 600).await,
            PackageKind::Script => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(artifact) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o755);
                        let _ = std::fs::set_permissions(artifact, perms);
                    }
                }
                let args: Vec<&str> = spec.args.iter().map(|s| s.as_str()).collect();
                sh(&p, &args, 600).await
            }
            PackageKind::Msi | PackageKind::ExeSilent => {
                return Err(PlatformError::Unsupported(
                    "Windows installers on Linux".into(),
                ))
            }
        };
        Ok(InstallReport {
            ok: out.exit_code == Some(0) && !out.timed_out,
            attempts: 1,
            exit_code: out.exit_code,
            detail: if out.exit_code == Some(0) {
                "installed".into()
            } else {
                format!("{}\n{}", out.stdout, out.stderr).trim().to_string()
            },
        })
    }

    async fn active_sessions(&self) -> PlatformResult<u32> {
        let out = sh("who", &[], 5).await;
        Ok(out.stdout.lines().filter(|l| !l.trim().is_empty()).count() as u32)
    }

    async fn uptime(&self) -> PlatformResult<(u64, i64)> {
        Ok(common::uptime())
    }

    async fn uninstall(&self) -> PlatformResult<()> {
        // Stop + disable the unit and remove it; data/binary removal is left to
        // the packaging script. Best-effort: failures are logged, not fatal.
        if has_systemd() {
            let _ = sh("systemctl", &["disable", "--now", "netagent"], 30).await;
            let _ = std::fs::remove_file("/etc/systemd/system/netagent.service");
            let _ = sh("systemctl", &["daemon-reload"], 15).await;
        }
        Ok(())
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            os: "linux".into(),
            arch: std::env::consts::ARCH.into(),
            has_driver_inventory: false, // best-effort via lspci, not authoritative
            can_set_network: true,
        }
    }
}

// ---- network manager detection + apply ----

#[derive(Debug, Clone, Copy)]
enum NetManager {
    NetworkManager,
    Netplan,
    SystemdNetworkd,
    Ifupdown,
}

fn detect_manager() -> Option<NetManager> {
    let active = |unit: &str| {
        std::process::Command::new("systemctl")
            .args(["is-active", unit])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false)
    };
    if active("NetworkManager") {
        return Some(NetManager::NetworkManager);
    }
    if active("systemd-networkd") {
        return Some(NetManager::SystemdNetworkd);
    }
    if Path::new("/etc/netplan").is_dir()
        && std::fs::read_dir("/etc/netplan")
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    {
        return Some(NetManager::Netplan);
    }
    if Path::new("/etc/network/interfaces").exists() {
        return Some(NetManager::Ifupdown);
    }
    None
}

async fn apply_networkmanager(cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
    let mut detail = String::new();
    if cfg.vlan.is_some() {
        detail.push_str("note: VLAN not applied via nmcli device modify; ");
    }
    let result = match &cfg.method {
        IpMethod::Dhcp => {
            sh(
                "nmcli",
                &["device", "modify", &cfg.iface, "ipv4.method", "auto"],
                30,
            )
            .await
        }
        IpMethod::Static {
            address,
            prefix,
            gateway,
        } => {
            let addr = format!("{address}/{prefix}");
            let dns = cfg.dns.join(" ");
            let mut args = vec![
                "device".to_string(),
                "modify".to_string(),
                cfg.iface.clone(),
                "ipv4.method".to_string(),
                "manual".to_string(),
                "ipv4.addresses".to_string(),
                addr,
            ];
            if let Some(gw) = gateway {
                args.push("ipv4.gateway".to_string());
                args.push(gw.clone());
            }
            if !dns.is_empty() {
                args.push("ipv4.dns".to_string());
                args.push(dns);
            }
            let argrefs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            sh("nmcli", &argrefs, 45).await
        }
    };
    let ok = result.exit_code == Some(0) && !result.timed_out;
    detail.push_str(if ok {
        "applied via nmcli"
    } else {
        &result.stderr
    });
    Ok(NetApplyReport {
        manager: "NetworkManager".into(),
        applied: ok,
        detail,
    })
}

async fn apply_netplan(cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
    let yaml = render_netplan(cfg);
    std::fs::write("/etc/netplan/99-netagent.yaml", yaml)
        .map_err(|e| PlatformError::Failed(format!("write netplan: {e}")))?;
    let out = sh("netplan", &["apply"], 60).await;
    let ok = out.exit_code == Some(0) && !out.timed_out;
    Ok(NetApplyReport {
        manager: "netplan".into(),
        applied: ok,
        detail: if ok {
            "applied via netplan".into()
        } else {
            out.stderr
        },
    })
}

async fn apply_systemd_networkd(cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
    let conf = render_networkd(cfg);
    std::fs::write("/etc/systemd/network/99-netagent.network", conf)
        .map_err(|e| PlatformError::Failed(format!("write networkd: {e}")))?;
    let out = sh("systemctl", &["restart", "systemd-networkd"], 60).await;
    let ok = out.exit_code == Some(0) && !out.timed_out;
    Ok(NetApplyReport {
        manager: "systemd-networkd".into(),
        applied: ok,
        detail: if ok {
            "applied via systemd-networkd".into()
        } else {
            out.stderr
        },
    })
}

async fn apply_ifupdown(cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
    let stanza = render_ifupdown(cfg);
    std::fs::create_dir_all("/etc/network/interfaces.d").ok();
    std::fs::write("/etc/network/interfaces.d/netagent", stanza)
        .map_err(|e| PlatformError::Failed(format!("write interfaces.d: {e}")))?;
    let _ = sh("ifdown", &[&cfg.iface], 30).await;
    let out = sh("ifup", &[&cfg.iface], 30).await;
    let ok = out.exit_code == Some(0) && !out.timed_out;
    Ok(NetApplyReport {
        manager: "ifupdown".into(),
        applied: ok,
        detail: if ok {
            "applied via ifupdown".into()
        } else {
            out.stderr
        },
    })
}

fn render_netplan(cfg: &NetworkConfig) -> String {
    let mut s = String::from("network:\n  version: 2\n  ethernets:\n");
    s.push_str(&format!("    {}:\n", cfg.iface));
    match &cfg.method {
        IpMethod::Dhcp => s.push_str("      dhcp4: true\n"),
        IpMethod::Static {
            address,
            prefix,
            gateway,
        } => {
            s.push_str("      dhcp4: false\n");
            s.push_str(&format!("      addresses: [{address}/{prefix}]\n"));
            if let Some(gw) = gateway {
                s.push_str(&format!(
                    "      routes:\n        - to: default\n          via: {gw}\n"
                ));
            }
            if !cfg.dns.is_empty() {
                s.push_str(&format!(
                    "      nameservers:\n        addresses: [{}]\n",
                    cfg.dns.join(", ")
                ));
            }
        }
    }
    s
}

fn render_networkd(cfg: &NetworkConfig) -> String {
    let mut s = format!("[Match]\nName={}\n\n[Network]\n", cfg.iface);
    match &cfg.method {
        IpMethod::Dhcp => s.push_str("DHCP=ipv4\n"),
        IpMethod::Static {
            address,
            prefix,
            gateway,
        } => {
            s.push_str(&format!("Address={address}/{prefix}\n"));
            if let Some(gw) = gateway {
                s.push_str(&format!("Gateway={gw}\n"));
            }
            for d in &cfg.dns {
                s.push_str(&format!("DNS={d}\n"));
            }
        }
    }
    s
}

fn render_ifupdown(cfg: &NetworkConfig) -> String {
    match &cfg.method {
        IpMethod::Dhcp => format!("auto {0}\niface {0} inet dhcp\n", cfg.iface),
        IpMethod::Static {
            address,
            prefix,
            gateway,
        } => {
            let netmask = prefix_to_netmask(*prefix);
            let mut s = format!(
                "auto {0}\niface {0} inet static\n    address {address}\n    netmask {netmask}\n",
                cfg.iface
            );
            if let Some(gw) = gateway {
                s.push_str(&format!("    gateway {gw}\n"));
            }
            if !cfg.dns.is_empty() {
                s.push_str(&format!("    dns-nameservers {}\n", cfg.dns.join(" ")));
            }
            s
        }
    }
}

fn prefix_to_netmask(prefix: u8) -> String {
    let bits: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        !(u32::MAX >> prefix)
    };
    format!(
        "{}.{}.{}.{}",
        bits >> 24 & 0xff,
        bits >> 16 & 0xff,
        bits >> 8 & 0xff,
        bits & 0xff
    )
}

// ---- parsers ----

fn parse_lspci(text: &str) -> (Vec<DriverInfo>, Vec<MissingDriverDevice>) {
    let mut drivers = Vec::new();
    let mut missing = Vec::new();
    let mut cur_dev: Option<(String, String)> = None; // (device_id, name)
    let mut cur_driver: Option<String> = None;

    let flush = |dev: &Option<(String, String)>,
                 driver: &Option<String>,
                 drivers: &mut Vec<DriverInfo>,
                 missing: &mut Vec<MissingDriverDevice>| {
        if let Some((id, name)) = dev {
            match driver {
                Some(drv) => drivers.push(DriverInfo {
                    device_name: name.clone(),
                    provider: String::new(),
                    version: String::new(),
                    date: String::new(),
                    signed: true,
                    inf_name: drv.clone(),
                }),
                None => missing.push(MissingDriverDevice {
                    name: name.clone(),
                    device_id: id.clone(),
                    config_manager_error_code: 28, // mimic "no driver installed"
                    status: "no kernel driver in use".into(),
                }),
            }
        }
    };

    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
            // new device line: "00:1f.6 Ethernet controller: Intel ..."
            flush(&cur_dev, &cur_driver, &mut drivers, &mut missing);
            cur_driver = None;
            let (id, rest) = line.split_once(' ').unwrap_or((line, ""));
            let name = rest
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or(rest)
                .trim()
                .to_string();
            cur_dev = Some((
                id.to_string(),
                if name.is_empty() {
                    rest.trim().to_string()
                } else {
                    name
                },
            ));
        } else if let Some(d) = line.trim().strip_prefix("Kernel driver in use:") {
            cur_driver = Some(d.trim().to_string());
        }
    }
    flush(&cur_dev, &cur_driver, &mut drivers, &mut missing);
    (drivers, missing)
}

fn parse_pkg_list(text: &str, provider: &str) -> Vec<SoftwareInfo> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let name = parts.next()?.trim();
            if name.is_empty() {
                return None;
            }
            let version = parts.next().unwrap_or("").trim().to_string();
            Some(SoftwareInfo {
                name: name.to_string(),
                version,
                vendor: provider.to_string(),
            })
        })
        .collect()
}

fn parse_smart(dev: &str, text: &str) -> SmartInfo {
    let healthy = if text.contains("PASSED") {
        Some(true)
    } else if text.contains("FAILED") {
        Some(false)
    } else {
        None
    };
    let attr = |name: &str| -> Option<u64> {
        text.lines()
            .find(|l| l.contains(name))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
    };
    SmartInfo {
        device: dev.to_string(),
        model: String::new(),
        healthy,
        temperature_c: attr("Temperature_Celsius").map(|v| v as i32),
        reallocated_sectors: attr("Reallocated_Sector_Ct"),
        pending_sectors: attr("Current_Pending_Sector"),
        power_on_hours: attr("Power_On_Hours"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_conversion() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
    }

    #[test]
    fn lspci_parses_driver_and_missing() {
        let sample = "\
00:1f.6 Ethernet controller: Intel Corporation Ethernet Connection
\tSubsystem: Dell Device
\tKernel driver in use: e1000e
\tKernel modules: e1000e
03:00.0 Network controller: Realtek Unknown Device
\tSubsystem: Foo
";
        let (drivers, missing) = parse_lspci(sample);
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].inf_name, "e1000e");
        assert_eq!(missing.len(), 1);
        assert!(missing[0].name.contains("Realtek"));
    }

    #[test]
    fn pkg_list_parses_tab_separated() {
        let s = "bash\t5.1-6\ncoreutils\t8.32\n\n";
        let v = parse_pkg_list(s, "dpkg");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "bash");
        assert_eq!(v[1].version, "8.32");
    }

    #[test]
    fn smart_parses_health_and_temp() {
        let s = "SMART overall-health self-assessment test result: PASSED\n194 Temperature_Celsius 0x0022 100 100 000 Old_age Always - 41\n";
        let info = parse_smart("/dev/sda", s);
        assert_eq!(info.healthy, Some(true));
        assert_eq!(info.temperature_c, Some(41));
    }
}
