//! Fallback for OSes we don't target: every operation returns `Unsupported`.

use std::path::Path;

use async_trait::async_trait;

use netagent_core::platform::{
    Capabilities, ExecOutput, ExecSpec, PlatformError, PlatformOps, PlatformResult,
};
use netagent_proto::command::{NetworkConfig, PackageSpec, RebootPolicy};
use netagent_proto::inventory::{
    DriverInfo, HardwareInfo, InstallReport, MissingDriverDevice, NetApplyReport, SmartInfo,
    SoftwareInfo,
};

use crate::common;

pub struct UnsupportedPlatform;

fn unsupported<T>(op: &str) -> PlatformResult<T> {
    Err(PlatformError::Unsupported(op.into()))
}

#[async_trait]
impl PlatformOps for UnsupportedPlatform {
    async fn reboot(&self, _delay_secs: u32) -> PlatformResult<()> {
        unsupported("reboot")
    }
    async fn shutdown(&self, _delay_secs: u32) -> PlatformResult<()> {
        unsupported("shutdown")
    }
    async fn exec(&self, spec: ExecSpec) -> PlatformResult<ExecOutput> {
        Ok(common::run_with_timeout(spec).await)
    }
    async fn set_hostname(&self, _name: &str, _reboot: RebootPolicy) -> PlatformResult<()> {
        unsupported("set_hostname")
    }
    async fn set_network(&self, _cfg: &NetworkConfig) -> PlatformResult<NetApplyReport> {
        unsupported("set_network")
    }
    async fn driver_inventory(&self) -> PlatformResult<Vec<DriverInfo>> {
        Ok(vec![])
    }
    async fn missing_drivers(&self) -> PlatformResult<Vec<MissingDriverDevice>> {
        Ok(vec![])
    }
    async fn software_inventory(&self) -> PlatformResult<Vec<SoftwareInfo>> {
        Ok(vec![])
    }
    async fn hardware_inventory(&self) -> PlatformResult<HardwareInfo> {
        Ok(common::hardware_inventory())
    }
    async fn smart(&self) -> PlatformResult<Vec<SmartInfo>> {
        Ok(vec![])
    }
    async fn install_package(
        &self,
        _spec: &PackageSpec,
        _artifact: &Path,
    ) -> PlatformResult<InstallReport> {
        unsupported("install_package")
    }
    async fn active_sessions(&self) -> PlatformResult<u32> {
        Ok(0)
    }
    async fn uptime(&self) -> PlatformResult<(u64, i64)> {
        Ok(common::uptime())
    }
    async fn uninstall(&self) -> PlatformResult<()> {
        unsupported("uninstall")
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            has_driver_inventory: false,
            can_set_network: false,
        }
    }
}
