//! The platform abstraction.
//!
//! `core` is OS-agnostic: it speaks the protocol and orchestrates, but every
//! action that actually touches the machine goes through [`PlatformOps`]. The
//! real implementations live in the `netagent-platform` crate (cfg-gated for
//! Linux/Windows) and are injected into the runtime as `Arc<dyn PlatformOps>`,
//! so `core` never depends on platform code and tests can inject [`MockPlatform`].

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use netagent_proto::command::{NetworkConfig, PackageSpec, RebootPolicy};
use netagent_proto::inventory::{
    DriverInfo, HardwareInfo, InstallReport, MissingDriverDevice, NetApplyReport, SmartInfo,
    SoftwareInfo,
};

/// Errors from platform operations. `NoNetworkManager`/`Unsupported` are
/// surfaced verbatim to NetEdge rather than guessing a fallback.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("operation not supported on this platform: {0}")]
    Unsupported(String),
    #[error(
        "no recognized network manager found (NetworkManager/netplan/systemd-networkd/ifupdown)"
    )]
    NoNetworkManager,
    #[error("{0}")]
    Failed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type PlatformResult<T> = std::result::Result<T, PlatformError>;

/// Inputs for a single command execution.
#[derive(Debug, Clone)]
pub struct ExecSpec {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_secs: u32,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
}

/// Captured output of an executed command.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Static capabilities the agent advertises and the runtime can branch on.
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub os: String,
    pub arch: String,
    pub has_driver_inventory: bool,
    pub can_set_network: bool,
}

/// Everything the agent can do to the host machine. One trait, two cfg-gated
/// implementations, plus a mock. Destructive ops (reboot/shutdown) honor a
/// delay so callers can ack first.
#[async_trait]
pub trait PlatformOps: Send + Sync {
    async fn reboot(&self, delay_secs: u32) -> PlatformResult<()>;
    async fn shutdown(&self, delay_secs: u32) -> PlatformResult<()>;
    async fn exec(&self, spec: ExecSpec) -> PlatformResult<ExecOutput>;
    async fn set_hostname(&self, name: &str, reboot: RebootPolicy) -> PlatformResult<()>;
    async fn set_network(&self, cfg: &NetworkConfig) -> PlatformResult<NetApplyReport>;
    async fn driver_inventory(&self) -> PlatformResult<Vec<DriverInfo>>;
    async fn missing_drivers(&self) -> PlatformResult<Vec<MissingDriverDevice>>;
    async fn software_inventory(&self) -> PlatformResult<Vec<SoftwareInfo>>;
    async fn hardware_inventory(&self) -> PlatformResult<HardwareInfo>;
    async fn smart(&self) -> PlatformResult<Vec<SmartInfo>>;
    /// Install a package already downloaded + hash-verified by the core snapin
    /// runner; `artifact` is the local path to the verified file.
    async fn install_package(
        &self,
        spec: &PackageSpec,
        artifact: &Path,
    ) -> PlatformResult<InstallReport>;
    /// Number of active interactive user sessions (for `cancel_if_active`).
    async fn active_sessions(&self) -> PlatformResult<u32>;
    /// `(uptime_secs, boot_time_unix)`.
    async fn uptime(&self) -> PlatformResult<(u64, i64)>;
    /// Self-uninstall (remove service + files). Only called for an authorized,
    /// signed `Uninstall` command.
    async fn uninstall(&self) -> PlatformResult<()>;
    fn capabilities(&self) -> Capabilities;
}

/// A boxed platform handle.
pub type DynPlatform = Arc<dyn PlatformOps>;

/// Test double that records calls instead of touching the machine.
#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    pub struct MockPlatform {
        pub calls: Mutex<Vec<String>>,
    }

    impl MockPlatform {
        pub fn new() -> Self {
            Self::default()
        }
        fn record(&self, what: impl Into<String>) {
            self.calls.lock().push(what.into());
        }
        pub fn recorded(&self) -> Vec<String> {
            self.calls.lock().clone()
        }
    }

    #[async_trait]
    impl PlatformOps for MockPlatform {
        async fn reboot(&self, delay_secs: u32) -> PlatformResult<()> {
            self.record(format!("reboot:{delay_secs}"));
            Ok(())
        }
        async fn shutdown(&self, delay_secs: u32) -> PlatformResult<()> {
            self.record(format!("shutdown:{delay_secs}"));
            Ok(())
        }
        async fn exec(&self, spec: ExecSpec) -> PlatformResult<ExecOutput> {
            self.record(format!("exec:{} {}", spec.program, spec.args.join(" ")));
            Ok(ExecOutput {
                exit_code: Some(0),
                stdout: format!("ran {}", spec.program),
                stderr: String::new(),
                timed_out: false,
            })
        }
        async fn set_hostname(&self, name: &str, _reboot: RebootPolicy) -> PlatformResult<()> {
            self.record(format!("set_hostname:{name}"));
            Ok(())
        }
        async fn set_network(&self, cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
            self.record(format!("set_network:{}", cfg.iface));
            Ok(NetApplyReport {
                manager: "mock".into(),
                applied: true,
                detail: "ok".into(),
            })
        }
        async fn driver_inventory(&self) -> PlatformResult<Vec<DriverInfo>> {
            self.record("driver_inventory");
            Ok(vec![])
        }
        async fn missing_drivers(&self) -> PlatformResult<Vec<MissingDriverDevice>> {
            self.record("missing_drivers");
            Ok(vec![])
        }
        async fn software_inventory(&self) -> PlatformResult<Vec<SoftwareInfo>> {
            self.record("software_inventory");
            Ok(vec![])
        }
        async fn hardware_inventory(&self) -> PlatformResult<HardwareInfo> {
            self.record("hardware_inventory");
            Ok(HardwareInfo {
                cpu_model: "MockCPU".into(),
                cpu_cores: 1,
                ram_total_bytes: 0,
                ram_used_bytes: 0,
                disks: vec![],
                nics: vec![],
                smart: vec![],
            })
        }
        async fn smart(&self) -> PlatformResult<Vec<SmartInfo>> {
            self.record("smart");
            Ok(vec![])
        }
        async fn install_package(
            &self,
            _spec: &PackageSpec,
            artifact: &Path,
        ) -> PlatformResult<InstallReport> {
            self.record(format!("install_package:{}", artifact.display()));
            Ok(InstallReport {
                ok: true,
                attempts: 1,
                exit_code: Some(0),
                detail: "installed".into(),
            })
        }
        async fn active_sessions(&self) -> PlatformResult<u32> {
            Ok(0)
        }
        async fn uptime(&self) -> PlatformResult<(u64, i64)> {
            Ok((123, 1000))
        }
        async fn uninstall(&self) -> PlatformResult<()> {
            self.record("uninstall");
            Ok(())
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                os: "mock".into(),
                arch: "test".into(),
                has_driver_inventory: false,
                can_set_network: true,
            }
        }
    }
}
