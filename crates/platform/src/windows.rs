//! Windows implementation of [`PlatformOps`].
//!
//! WMI is queried via PowerShell `Get-CimInstance ... | ConvertTo-Json` (the
//! same WMI classes the spec calls for — `Win32_PnPSignedDriver`,
//! `Win32_PnPEntity`), network reconfiguration uses the NetTCPIP cmdlets with a
//! `netsh` fallback, and installed software is read from the uninstall registry.
//! Reboot/shutdown go through `shutdown.exe`, which wraps the same
//! `InitiateSystemShutdownEx` mechanism while handling the shutdown privilege.
//!
//! NOTE: this module compiles only on Windows and is build-checked via
//! `cargo check --target x86_64-pc-windows-gnu`; it is not run on the Linux dev
//! host. Behaviour must be validated on a real Windows machine.

use std::path::Path;

use async_trait::async_trait;
use serde_json::Value;

use netagent_core::platform::{
    Capabilities, ExecOutput, ExecSpec, PlatformError, PlatformOps, PlatformResult,
};
use netagent_proto::command::{IpMethod, NetworkConfig, PackageKind, PackageSpec, RebootPolicy};
use netagent_proto::inventory::{
    DriverInfo, HardwareInfo, InstallReport, MissingDriverDevice, NetApplyReport, SmartInfo,
    SoftwareInfo,
};

use crate::common;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        WindowsPlatform
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a program with a timeout.
async fn run(program: &str, args: &[&str], timeout_secs: u32) -> ExecOutput {
    common::run_with_timeout(ExecSpec {
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        timeout_secs,
        cwd: None,
        env: vec![],
    })
    .await
}

/// Run a PowerShell snippet, returning its output.
async fn ps(script: &str, timeout_secs: u32) -> ExecOutput {
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
        timeout_secs,
    )
    .await
}

/// Normalize ConvertTo-Json output (object for one item, array for many) to a Vec.
fn json_rows(text: &str) -> Vec<Value> {
    let t = text.trim();
    if t.is_empty() {
        return vec![];
    }
    match serde_json::from_str::<Value>(t) {
        Ok(Value::Array(a)) => a,
        Ok(v) => vec![v],
        Err(_) => vec![],
    }
}

fn jstr(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(|v| {
            if v.is_string() {
                v.as_str().map(|s| s.to_string())
            } else if v.is_null() {
                None
            } else {
                Some(v.to_string())
            }
        })
        .unwrap_or_default()
}

#[async_trait]
impl PlatformOps for WindowsPlatform {
    async fn reboot(&self, delay_secs: u32) -> PlatformResult<()> {
        let t = delay_secs.to_string();
        let out = run("shutdown.exe", &["/r", "/t", &t, "/f"], 15).await;
        if out.exit_code == Some(0) {
            Ok(())
        } else {
            Err(PlatformError::Failed(format!(
                "shutdown /r failed: {}",
                out.stderr
            )))
        }
    }

    async fn shutdown(&self, delay_secs: u32) -> PlatformResult<()> {
        let t = delay_secs.to_string();
        let out = run("shutdown.exe", &["/s", "/t", &t, "/f"], 15).await;
        if out.exit_code == Some(0) {
            Ok(())
        } else {
            Err(PlatformError::Failed(format!(
                "shutdown /s failed: {}",
                out.stderr
            )))
        }
    }

    async fn exec(&self, spec: ExecSpec) -> PlatformResult<ExecOutput> {
        Ok(common::run_with_timeout(spec).await)
    }

    async fn set_hostname(&self, name: &str, reboot: RebootPolicy) -> PlatformResult<()> {
        let script = format!("Rename-Computer -NewName '{}' -Force", ps_escape(name));
        let out = ps(&script, 30).await;
        if out.exit_code != Some(0) {
            return Err(PlatformError::Failed(format!(
                "Rename-Computer failed: {}",
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
        let iface = ps_escape(&cfg.iface);
        let script = match &cfg.method {
            IpMethod::Dhcp => format!(
                "Set-NetIPInterface -InterfaceAlias '{iface}' -Dhcp Enabled; \
                 Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ResetServerAddresses"
            ),
            IpMethod::Static {
                address,
                prefix,
                gateway,
            } => {
                let gw = gateway
                    .as_ref()
                    .map(|g| format!(" -DefaultGateway '{}'", ps_escape(g)))
                    .unwrap_or_default();
                let dns = if cfg.dns.is_empty() {
                    String::new()
                } else {
                    let list = cfg
                        .dns
                        .iter()
                        .map(|d| format!("'{}'", ps_escape(d)))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ServerAddresses ({list}); ")
                };
                format!(
                    "Remove-NetIPAddress -InterfaceAlias '{iface}' -Confirm:$false -ErrorAction SilentlyContinue; \
                     Set-NetIPInterface -InterfaceAlias '{iface}' -Dhcp Disabled; \
                     New-NetIPAddress -InterfaceAlias '{iface}' -IPAddress '{address}' -PrefixLength {prefix}{gw}; \
                     {dns}"
                )
            }
        };
        let out = ps(&script, 60).await;
        if out.exit_code == Some(0) {
            let mut detail = "applied via NetTCPIP".to_string();
            if cfg.vlan.is_some() {
                detail.push_str("; note: VLAN not configured by this path");
            }
            return Ok(NetApplyReport {
                manager: "NetTCPIP".into(),
                applied: true,
                detail,
            });
        }

        // Fallback: netsh (static only; DHCP handled above on failure too).
        if let IpMethod::Static {
            address,
            prefix,
            gateway,
        } = &cfg.method
        {
            let mask = prefix_to_netmask(*prefix);
            let gw = gateway.clone().unwrap_or_default();
            let netsh = run(
                "netsh",
                &[
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &format!("name={}", cfg.iface),
                    "static",
                    address,
                    &mask,
                    &gw,
                ],
                30,
            )
            .await;
            let ok = netsh.exit_code == Some(0);
            return Ok(NetApplyReport {
                manager: "netsh".into(),
                applied: ok,
                detail: if ok {
                    "applied via netsh fallback".into()
                } else {
                    netsh.stderr
                },
            });
        }

        Ok(NetApplyReport {
            manager: "NetTCPIP".into(),
            applied: false,
            detail: out.stderr,
        })
    }

    async fn driver_inventory(&self) -> PlatformResult<Vec<DriverInfo>> {
        let out = ps(
            "Get-CimInstance Win32_PnPSignedDriver | \
             Select-Object DeviceName,DriverProviderName,DriverVersion,DriverDate,IsSigned,InfName | \
             ConvertTo-Json -Depth 2",
            90,
        )
        .await;
        Ok(json_rows(&out.stdout)
            .iter()
            .map(|r| DriverInfo {
                device_name: jstr(r, "DeviceName"),
                provider: jstr(r, "DriverProviderName"),
                version: jstr(r, "DriverVersion"),
                date: jstr(r, "DriverDate"),
                signed: r.get("IsSigned").and_then(|v| v.as_bool()).unwrap_or(false),
                inf_name: jstr(r, "InfName"),
            })
            .collect())
    }

    async fn missing_drivers(&self) -> PlatformResult<Vec<MissingDriverDevice>> {
        let out = ps(
            "Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | \
             Select-Object Name,DeviceID,ConfigManagerErrorCode,Status | ConvertTo-Json -Depth 2",
            90,
        )
        .await;
        Ok(json_rows(&out.stdout)
            .iter()
            .map(|r| MissingDriverDevice {
                name: jstr(r, "Name"),
                device_id: jstr(r, "DeviceID"),
                config_manager_error_code: r
                    .get("ConfigManagerErrorCode")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                status: jstr(r, "Status"),
            })
            .collect())
    }

    async fn software_inventory(&self) -> PlatformResult<Vec<SoftwareInfo>> {
        Ok(read_uninstall_registry())
    }

    async fn hardware_inventory(&self) -> PlatformResult<HardwareInfo> {
        let mut hw = common::hardware_inventory();
        hw.smart = self.smart().await.unwrap_or_default();
        Ok(hw)
    }

    async fn smart(&self) -> PlatformResult<Vec<SmartInfo>> {
        // Best-effort: model + overall status from Win32_DiskDrive; detailed
        // attributes need vendor tooling and are left empty.
        let out = ps(
            "Get-CimInstance Win32_DiskDrive | Select-Object Model,Status,DeviceID | ConvertTo-Json -Depth 2",
            30,
        )
        .await;
        Ok(json_rows(&out.stdout)
            .iter()
            .map(|r| SmartInfo {
                device: jstr(r, "DeviceID"),
                model: jstr(r, "Model"),
                healthy: Some(jstr(r, "Status").eq_ignore_ascii_case("OK")),
                temperature_c: None,
                reallocated_sectors: None,
                pending_sectors: None,
                power_on_hours: None,
            })
            .collect())
    }

    async fn install_package(
        &self,
        spec: &PackageSpec,
        artifact: &Path,
    ) -> PlatformResult<InstallReport> {
        let p = artifact.to_string_lossy().to_string();
        let out = match spec.kind {
            PackageKind::Msi => {
                let mut args = vec!["/i".to_string(), p.clone(), "/qn".to_string()];
                args.extend(spec.args.iter().cloned());
                let argrefs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                run("msiexec.exe", &argrefs, 1200).await
            }
            PackageKind::ExeSilent => {
                let argrefs: Vec<&str> = spec.args.iter().map(|s| s.as_str()).collect();
                run(&p, &argrefs, 1200).await
            }
            PackageKind::Deb | PackageKind::Rpm | PackageKind::Script => {
                return Err(PlatformError::Unsupported(
                    "Linux package on Windows".into(),
                ))
            }
        };
        // msiexec returns 0 (ok) or 3010 (ok, reboot required).
        let ok = matches!(out.exit_code, Some(0) | Some(3010)) && !out.timed_out;
        Ok(InstallReport {
            ok,
            attempts: 1,
            exit_code: out.exit_code,
            detail: if ok {
                "installed".into()
            } else {
                format!("{}\n{}", out.stdout, out.stderr).trim().to_string()
            },
        })
    }

    async fn active_sessions(&self) -> PlatformResult<u32> {
        // Count interactive sessions reported by `query user`. Best-effort.
        let out = run("query", &["user"], 10).await;
        let n = out
            .stdout
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .count() as u32;
        Ok(n)
    }

    async fn uptime(&self) -> PlatformResult<(u64, i64)> {
        Ok(common::uptime())
    }

    async fn uninstall(&self) -> PlatformResult<()> {
        let _ = run("sc.exe", &["stop", "netagent"], 30).await;
        let _ = run("sc.exe", &["delete", "netagent"], 30).await;
        Ok(())
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            os: "windows".into(),
            arch: std::env::consts::ARCH.into(),
            has_driver_inventory: true,
            can_set_network: true,
        }
    }
}

/// Escape single quotes for embedding in a PowerShell single-quoted string.
fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
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

/// Read installed software from the Windows uninstall registry (HKLM 64-bit +
/// 32-bit views and HKCU), skipping entries without a display name.
fn read_uninstall_registry() -> Vec<SoftwareInfo> {
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };
    use winreg::RegKey;

    const PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let mut out = Vec::new();

    let roots = [
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_32KEY),
        (HKEY_CURRENT_USER, KEY_READ),
    ];

    for (hive, flags) in roots {
        let root = RegKey::predef(hive);
        let Ok(uninstall) = root.open_subkey_with_flags(PATH, flags) else {
            continue;
        };
        for sub in uninstall.enum_keys().flatten() {
            let Ok(k) = uninstall.open_subkey_with_flags(&sub, flags) else {
                continue;
            };
            let name: String = k.get_value("DisplayName").unwrap_or_default();
            if name.trim().is_empty() {
                continue;
            }
            out.push(SoftwareInfo {
                name,
                version: k.get_value("DisplayVersion").unwrap_or_default(),
                vendor: k.get_value("Publisher").unwrap_or_default(),
            });
        }
    }
    out
}
