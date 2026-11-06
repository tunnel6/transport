//! Trust-on-first-use discovery for an explicit pairing operation only.
//! Business connections and certificate enrollment still verify the discovered CA.
use crate::error::{Result, TransportError};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct PairingDiscoveryVerifier;
impl ServerCertVerifier for PairingDiscoveryVerifier {
  fn verify_server_cert(
    &self,
    _: &CertificateDer<'_>,
    _: &[CertificateDer<'_>],
    _: &ServerName<'_>,
    _: &[u8],
    _: UnixTime,
  ) -> std::result::Result<ServerCertVerified, rustls::Error> {
    Ok(ServerCertVerified::assertion())
  }
  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    signature: &DigitallySignedStruct,
  ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls12_signature(
      message,
      cert,
      signature,
      &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
  }
  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    signature: &DigitallySignedStruct,
  ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(
      message,
      cert,
      signature,
      &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
  }
  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
      .signature_verification_algorithms
      .supported_schemes()
  }
}

/// Fetch a server certificate chain for a user-initiated pairing operation.
/// Never use this to authorize a business connection.
pub async fn discover_pairing_certificates(host: &str, port: u16) -> Result<Vec<Vec<u8>>> {
  let operation = async {
    let mut config = ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(PairingDiscoveryVerifier))
      .with_no_client_auth();
    config.enable_sni = false;
    config.alpn_protocols = vec![b"edge-health/1".to_vec()];
    let stream = tokio::net::TcpStream::connect((host, port))
      .await
      .map_err(|error| TransportError::Connection(error.to_string()))?;
    let name = ServerName::try_from(host.to_owned())
      .map_err(|error| TransportError::Tls(error.to_string()))?;
    let connection = tokio_rustls::TlsConnector::from(Arc::new(config))
      .connect(name, stream)
      .await
      .map_err(|error| TransportError::Tls(error.to_string()))?;
    let chain = connection
      .get_ref()
      .1
      .peer_certificates()
      .ok_or_else(|| TransportError::Tls("Edge certificate chain is missing".into()))?;
    Ok(chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
  };
  tokio::time::timeout(Duration::from_secs(5), operation)
    .await
    .map_err(|_| TransportError::Connection("Pairing discovery timed out".into()))?
}
