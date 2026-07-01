//! Inventory / telemetry data types shared by the platform layer (producer),
//! the agent core (forwarder) and the test mock server (consumer).

use serde::{Deserialize, Serialize};

/// One installed driver (Windows: a row of WMI `Win32_PnPSignedDriver`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverInfo {
    pub device_name: String,
    pub provider: String,
    pub version: String,
    /// Driver date, free-form (WMI format or ISO); empty if unknown.
    pub date: String,
    pub signed: bool,
    pub inf_name: String,
}

/// A device whose driver is missing or failed
/// (Windows: `Win32_PnPEntity` with `ConfigManagerErrorCode != 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingDriverDevice {
    pub name: String,
    pub device_id: String,
    pub config_manager_error_code: u32,
    pub status: String,
}

/// One installed software package/program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: String,
    pub vendor: String,
}

/// A physical disk and its SMART health (best-effort; fields may be absent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartInfo {
    pub device: String,
    pub model: String,
    pub healthy: Option<bool>,
    pub temperature_c: Option<i32>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub power_on_hours: Option<u64>,
}

/// Hardware snapshot. Field names mirror NetEdge's `/api/v1/metrics` `system`
/// block so telemetry slots into existing dashboards/alerts unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub ram_total_bytes: u64,
    pub ram_used_bytes: u64,
    pub disks: Vec<DiskInfo>,
    pub nics: Vec<NicInfo>,
    pub smart: Vec<SmartInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicInfo {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
}

/// Result of applying a [`crate::command::NetworkConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetApplyReport {
    /// Which network manager actually applied the change.
    pub manager: String,
    pub applied: bool,
    pub detail: String,
}

/// Result of a silent package install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub ok: bool,
    pub attempts: u8,
    pub exit_code: Option<i32>,
    pub detail: String,
}
