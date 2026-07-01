//! Cross-platform silent software deployment (FOG-style "snapins").
//!
//! Core downloads + hash-verifies the artifact, then hands the local file to
//! the platform layer which performs the OS-specific silent install. Retries
//! are honored per the package spec.

use netagent_proto::command::PackageSpec;
use netagent_proto::inventory::InstallReport;

use crate::platform::DynPlatform;
use crate::util::download_verified;

/// Download, verify, and install a package, retrying up to `spec.retries` times.
pub async fn run(
    spec: &PackageSpec,
    client: &reqwest::Client,
    platform: &DynPlatform,
) -> InstallReport {
    let max_attempts = spec.retries.saturating_add(1);
    let mut last = String::new();
    for attempt in 1..=max_attempts {
        match download_verified(client, &spec.url, &spec.sha256).await {
            Ok((path, _bytes)) => match platform.install_package(spec, path.as_ref()).await {
                Ok(mut report) => {
                    report.attempts = attempt;
                    if report.ok {
                        return report;
                    }
                    last = report.detail;
                }
                Err(e) => last = format!("install error: {e}"),
            },
            Err(e) => last = format!("download error: {e}"),
        }
        tracing::warn!(attempt, max_attempts, detail = %last, "snapin attempt failed");
    }
    InstallReport {
        ok: false,
        attempts: max_attempts,
        exit_code: None,
        detail: last,
    }
}
