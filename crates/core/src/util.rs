//! Small shared helpers: timestamped download with SHA-256 verification.

use std::io::Write;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Download `url` to a temp file and verify its SHA-256 equals `expected_hex`.
/// Returns the temp file path (kept alive by the returned handle).
pub async fn download_verified(
    client: &reqwest::Client,
    url: &str,
    expected_hex: &str,
) -> Result<(tempfile::TempPath, Vec<u8>)> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CoreError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(CoreError::Http(format!(
            "download {url} returned {}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CoreError::Http(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got = hex::encode(hasher.finalize());
    if !got.eq_ignore_ascii_case(expected_hex) {
        return Err(CoreError::Update(format!(
            "sha256 mismatch for {url}: expected {expected_hex}, got {got}"
        )));
    }

    let mut tf = tempfile::NamedTempFile::new()?;
    tf.write_all(&bytes)?;
    tf.flush()?;
    Ok((tf.into_temp_path(), bytes.to_vec()))
}

/// Default per-agent data directory used when none is configured.
pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(|p| PathBuf::from(p).join("Netagent"))
            .unwrap_or_else(|| PathBuf::from("C:/ProgramData/Netagent"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/netagent")
    }
}
