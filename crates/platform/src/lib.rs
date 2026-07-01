//! Platform layer: the OS-specific implementations of `netagent_core::PlatformOps`.
//!
//! The agent binary calls [`current()`] to obtain the right implementation for
//! the host (selected by `cfg(target_os)`) and injects it into the core
//! runtime. [`identity()`] gathers the facts NetEdge needs at enrollment.

use std::sync::Arc;

use netagent_core::{DynPlatform, Identity};

pub mod common;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

/// The platform implementation for the current OS.
pub fn current() -> DynPlatform {
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::LinuxPlatform::new())
    }
    #[cfg(windows)]
    {
        Arc::new(windows::WindowsPlatform::new())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Arc::new(unsupported::UnsupportedPlatform)
    }
}

/// Identity facts (hostname, MAC, fingerprint, OS) for enrollment + heartbeats.
pub fn identity(version: &str) -> Identity {
    common::identity(version, &read_machine_id())
}

fn read_machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/machine-id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(windows)]
    {
        // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .and_then(|k| k.get_value::<String, _>("MachineGuid"))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        String::new()
    }
}
