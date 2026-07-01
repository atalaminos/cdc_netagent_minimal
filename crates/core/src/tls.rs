//! TLS with **public-key pinning** instead of a CA trust store.
//!
//! NetEdge serves plain HTTP and is typically fronted by a self-signed or
//! internal cert. Rather than disabling verification (the netdd-era footgun),
//! the agent pins the server's SubjectPublicKeyInfo (SPKI) hash, configured at
//! deploy time. We still perform full TLS handshake-signature verification via
//! the ring provider — only the chain/name check is replaced by the pin.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// A `ServerCertVerifier` that accepts a cert iff its SPKI sha256 matches `pin`.
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pin_hex: String,
    provider: Arc<CryptoProvider>,
}

impl SpkiPinVerifier {
    pub fn new(pin_hex: String, provider: Arc<CryptoProvider>) -> Self {
        Self { pin_hex, provider }
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let got = netagent_proto::crypto::spki_pin_from_cert_der(end_entity.as_ref())
            .map_err(|e| TlsError::General(format!("spki extraction: {e}")))?;
        if got.eq_ignore_ascii_case(&self.pin_hex) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "server SPKI pin mismatch: expected {}, got {}",
                self.pin_hex, got
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls `ClientConfig` that pins the server SPKI to `pin_hex`.
pub fn pinned_client_config(pin_hex: &str) -> Result<rustls::ClientConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(SpkiPinVerifier::new(pin_hex.to_string(), provider.clone()));
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::General(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    fn make_cert() -> (Vec<u8>, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["netedge.local".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        let pin = netagent_proto::crypto::spki_pin_from_cert_der(&der).unwrap();
        (der, pin)
    }

    #[test]
    fn verifier_accepts_matching_pin() {
        let (der, pin) = make_cert();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = SpkiPinVerifier::new(pin, provider);
        let cert = CertificateDer::from(der);
        let name = ServerName::try_from("netedge.local").unwrap();
        let r = v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(r.is_ok());
    }

    #[test]
    fn verifier_rejects_wrong_pin() {
        let (der, _pin) = make_cert();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = SpkiPinVerifier::new("00".repeat(32), provider);
        let cert = CertificateDer::from(der);
        let name = ServerName::try_from("netedge.local").unwrap();
        let r = v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(r.is_err());
    }

    #[test]
    fn pinned_client_config_builds() {
        assert!(pinned_client_config(&"ab".repeat(32)).is_ok());
    }
}
