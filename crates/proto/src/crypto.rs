//! Ed25519 key handling + SPKI pinning.
//!
//! The signing/serialization conventions here are deliberately the SAME as
//! NetEdge's `src/license.rs`: payloads are signed over their `bincode`
//! serialization, and the 64-byte signature is (de)serialized as a fixed tuple
//! so the wire format stays byte-stable across versions and languages.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::ProtoError;

/// Length of an Ed25519 private/seed key, public key (bytes).
pub const KEY_LEN: usize = 32;
/// Length of an Ed25519 signature (bytes).
pub const SIG_LEN: usize = 64;

/// Generate a fresh Ed25519 signing key using the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Load a 32-byte Ed25519 signing key from a binary file (exactly 32 bytes).
/// Mirror of NetEdge `license::load_signing_key`. Recommended perms: 0600.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, ProtoError> {
    let bytes = std::fs::read(path)?;
    let arr = to_key_array(&bytes)?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Persist a signing key as raw 32 bytes. On Unix the file is created 0600.
pub fn save_signing_key(path: &Path, key: &SigningKey) -> Result<(), ProtoError> {
    write_private(path, &key.to_bytes())
}

/// Parse a 32-byte Ed25519 verifying (public) key from raw bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ProtoError> {
    let arr = to_key_array(bytes)?;
    VerifyingKey::from_bytes(&arr).map_err(|e| ProtoError::InvalidKey(e.to_string()))
}

/// Parse a verifying key from a hex string (64 hex chars).
pub fn verifying_key_from_hex(s: &str) -> Result<VerifyingKey, ProtoError> {
    let bytes = hex::decode(s.trim()).map_err(|e| ProtoError::InvalidKey(e.to_string()))?;
    verifying_key_from_bytes(&bytes)
}

/// Hex-encode a verifying key (64 hex chars) for config files / transport.
pub fn verifying_key_to_hex(vk: &VerifyingKey) -> String {
    hex::encode(vk.to_bytes())
}

/// Short fingerprint (first 8 bytes of the public key, hex) for logging.
/// NEVER logs the private key. Mirror of NetEdge `license::fingerprint`.
pub fn fingerprint(vk: &VerifyingKey) -> String {
    vk.to_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Sign arbitrary bytes with a signing key, returning the raw 64-byte signature.
pub fn sign_bytes(key: &SigningKey, msg: &[u8]) -> [u8; SIG_LEN] {
    let sig: Signature = key.sign(msg);
    sig.to_bytes()
}

/// Verify a raw 64-byte signature over `msg` against a verifying key.
pub fn verify_bytes(vk: &VerifyingKey, msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), ProtoError> {
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature)
        .map_err(|_| ProtoError::InvalidSignature)
}

/// Compute the SHA-256 SubjectPublicKeyInfo pin of a DER-encoded certificate.
///
/// We pin the SPKI (the public key inside the cert), not the whole cert, so the
/// server can rotate the cert validity period without breaking pins as long as
/// the key stays the same — the standard HPKP-style pin. Returns lowercase hex.
pub fn spki_pin_from_cert_der(cert_der: &[u8]) -> Result<String, ProtoError> {
    let spki = extract_spki_der(cert_der)?;
    let mut h = Sha256::new();
    h.update(spki);
    Ok(hex::encode(h.finalize()))
}

/// Extract the DER bytes of the SubjectPublicKeyInfo from a DER certificate.
///
/// A `Certificate` is `SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`
/// and `tbsCertificate` is `SEQUENCE { [0] version?, serial, sigAlg, issuer,
/// validity, subject, subjectPublicKeyInfo, ... }`. We walk those SEQUENCE
/// members until the 7th element of tbs (or 6th if version is absent) which is
/// the SPKI, itself a SEQUENCE — we return it verbatim including its own header.
fn extract_spki_der(cert: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let der_err = || ProtoError::InvalidKey("malformed certificate DER".into());

    // outer Certificate SEQUENCE → take its content
    let (cert_body, _) = der_take_seq(cert).ok_or_else(der_err)?;
    // first member of Certificate is tbsCertificate SEQUENCE → take its content
    let (tbs, _) = der_take_seq(cert_body).ok_or_else(der_err)?;
    let mut rest = tbs;

    // optional [0] EXPLICIT version
    if let Some((_, after)) = der_take_tag(rest, 0xA0) {
        rest = after;
    }
    // serialNumber INTEGER
    rest = der_skip(rest).ok_or_else(der_err)?;
    // signature AlgorithmIdentifier SEQUENCE
    rest = der_skip(rest).ok_or_else(der_err)?;
    // issuer Name SEQUENCE
    rest = der_skip(rest).ok_or_else(der_err)?;
    // validity SEQUENCE
    rest = der_skip(rest).ok_or_else(der_err)?;
    // subject Name SEQUENCE
    rest = der_skip(rest).ok_or_else(der_err)?;
    // subjectPublicKeyInfo SEQUENCE — return whole element (header + content)
    let spki = der_take_element(rest).ok_or_else(der_err)?;
    Ok(spki.to_vec())
}

/// Returns (content, remaining_after_element) for a SEQUENCE (tag 0x30).
fn der_take_seq(input: &[u8]) -> Option<(&[u8], &[u8])> {
    der_take_tag(input, 0x30)
}

/// Returns (content, remaining_after_element) for the given tag byte.
fn der_take_tag(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first()? != &tag {
        return None;
    }
    let (len, hdr) = der_len(&input[1..])?;
    let start = 1 + hdr;
    let end = start.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((&input[start..end], &input[end..]))
}

/// Returns the full element bytes (tag + length + content).
fn der_take_element(input: &[u8]) -> Option<&[u8]> {
    let _tag = *input.first()?;
    let (len, hdr) = der_len(&input[1..])?;
    let end = 1usize.checked_add(hdr)?.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some(&input[..end])
}

/// Skip one element, returning the bytes after it.
fn der_skip(input: &[u8]) -> Option<&[u8]> {
    let el = der_take_element(input)?;
    Some(&input[el.len()..])
}

/// Decode a DER length, returning (length, header_bytes_consumed).
fn der_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || input.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &input[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

fn to_key_array(bytes: &[u8]) -> Result<[u8; KEY_LEN], ProtoError> {
    if bytes.len() != KEY_LEN {
        return Err(ProtoError::InvalidKey(format!(
            "key must be exactly {KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ProtoError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ProtoError> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let k = generate_signing_key();
        let vk = k.verifying_key();
        let sig = sign_bytes(&k, b"hello");
        verify_bytes(&vk, b"hello", &sig).unwrap();
        assert!(verify_bytes(&vk, b"hellp", &sig).is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let k = generate_signing_key();
        let vk = k.verifying_key();
        let h = verifying_key_to_hex(&vk);
        assert_eq!(h.len(), 64);
        let vk2 = verifying_key_from_hex(&h).unwrap();
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn fingerprint_is_16_hex() {
        let k = generate_signing_key();
        let fp = fingerprint(&k.verifying_key());
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rejects_wrong_key_len() {
        assert!(verifying_key_from_bytes(&[0u8; 31]).is_err());
        assert!(verifying_key_from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn der_len_decodes_short_and_long_form() {
        assert_eq!(der_len(&[0x05]), Some((5, 1)));
        assert_eq!(der_len(&[0x00]), Some((0, 1))); // short-form zero length
        assert_eq!(der_len(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(der_len(&[0x82, 0x01, 0x2c]), Some((300, 3)));
        assert_eq!(der_len(&[0x80]), None); // indefinite form rejected
    }

    /// Walk the DER of a real self-signed cert and confirm our extracted SPKI
    /// pin equals an independently-computed hash of the key pair's SPKI DER.
    /// Exercised for both an ECDSA (long SPKI) and an Ed25519 (short SPKI) cert.
    fn spki_matches_for(alg: &'static rcgen::SignatureAlgorithm) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let params = rcgen::CertificateParams::new(vec!["netedge.local".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let expected = {
            let mut h = Sha256::new();
            h.update(key.public_key_der()); // this is the SPKI DER
            hex::encode(h.finalize())
        };
        let got = spki_pin_from_cert_der(cert.der()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn spki_pin_matches_independent_hash_ecdsa() {
        spki_matches_for(&rcgen::PKCS_ECDSA_P256_SHA256);
    }

    #[test]
    fn spki_pin_matches_independent_hash_ed25519() {
        spki_matches_for(&rcgen::PKCS_ED25519);
    }
}
