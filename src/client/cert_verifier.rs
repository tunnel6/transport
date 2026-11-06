//! 自定义证书验证器
//!
//! 只验证 CA 证书链，不验证服务器名称（SNI/SAN）。
//! 用于不发送 SNI 的 TLS 连接场景：客户端连接时使用对端 IP 作为 ServerName，
//! 服务器证书只有域名 SAN，名称验证必然失败，但 CA 链验证仍然有效。

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
  CertificateError, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use std::sync::Arc;

/// 只验证 CA 链，忽略名称不匹配错误
#[derive(Debug)]
pub(crate) struct CaOnlyVerifier {
  inner: Arc<WebPkiServerVerifier>,
  allow_invalid_purpose: bool,
}

impl CaOnlyVerifier {
  pub fn new(root_store: Arc<RootCertStore>) -> Result<Arc<Self>, TlsError> {
    Self::new_with_options(root_store, false)
  }

  pub fn new_allow_invalid_purpose(root_store: Arc<RootCertStore>) -> Result<Arc<Self>, TlsError> {
    Self::new_with_options(root_store, true)
  }

  fn new_with_options(
    root_store: Arc<RootCertStore>,
    allow_invalid_purpose: bool,
  ) -> Result<Arc<Self>, TlsError> {
    let inner = WebPkiServerVerifier::builder(root_store)
      .build()
      .map_err(|e| TlsError::General(e.to_string()))?;
    Ok(Arc::new(Self {
      inner,
      allow_invalid_purpose,
    }))
  }
}

impl ServerCertVerifier for CaOnlyVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, TlsError> {
    // 委托给 WebPkiServerVerifier：
    //   - CA 链验证失败 → 错误照常传播（安全性保留）
    //   - 名称不匹配 (NotValidForName) → 忽略（预期行为，因为不发 SNI）
    match self
      .inner
      .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    {
      Ok(v) => Ok(v),
      // rustls 0.23+: match both old and new error variants
      Err(TlsError::InvalidCertificate(CertificateError::NotValidForName)) => {
        Ok(ServerCertVerified::assertion())
      }
      Err(TlsError::InvalidCertificate(CertificateError::NotValidForNameContext { .. })) => {
        Ok(ServerCertVerified::assertion())
      }
      Err(TlsError::InvalidCertificate(CertificateError::InvalidPurpose))
        if self.allow_invalid_purpose =>
      {
        Ok(ServerCertVerified::assertion())
      }
      Err(TlsError::InvalidCertificate(CertificateError::InvalidPurposeContext { .. }))
        if self.allow_invalid_purpose =>
      {
        Ok(ServerCertVerified::assertion())
      }
      Err(e) => Err(e),
    }
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    self.inner.verify_tls12_signature(message, cert, dss)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    self.inner.verify_tls13_signature(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.inner.supported_verify_schemes()
  }
}
