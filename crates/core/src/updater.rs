//! Signed self-update.
//!
//! The new binary is downloaded, its SHA-256 checked, and — crucially — its
//! Ed25519 signature verified against the **pinned NetEdge command key** before
//! the running binary is atomically replaced. This reuses the same trust anchor
//! as command verification, so we never run an unverified binary.

use ed25519_dalek::VerifyingKey;

use netagent_proto::crypto::{verify_bytes, SIG_LEN};

use crate::error::{CoreError, Result};
use crate::util::download_verified;

/// Apply a self-update. On success the current binary on disk is the new one;
/// the caller is expected to exit so the service manager restarts it.
pub async fn apply(
    client: &reqwest::Client,
    url: &str,
    version: &str,
    sha256_hex: &str,
    binary_sig: &[u8; SIG_LEN],
    server_cmd_key: &VerifyingKey,
) -> Result<()> {
    let (path, bytes) = download_verified(client, url, sha256_hex).await?;

    // The signature is over the raw new-binary bytes, verified against the same
    // pinned key used for commands.
    verify_bytes(server_cmd_key, &bytes, binary_sig)
        .map_err(|_| CoreError::Update("new binary signature invalid (pinned key)".into()))?;

    // Make sure it is executable (no-op on Windows).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)?;
    }

    self_replace::self_replace(&path)
        .map_err(|e| CoreError::Update(format!("self_replace: {e}")))?;
    tracing::info!(version, "self-update applied; restart pending");
    Ok(())
}
