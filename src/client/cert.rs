//! 证书和密钥对生成
//!
//! 负责生成密钥对和 CSR（证书签名请求）

use crate::error::{Result, TransportError};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

/// 证书申请结果
#[derive(Debug, Clone)]
pub struct CertRequestResult {
  /// 客户端证书 (PEM)
  pub certificate: Vec<u8>,
  /// 证书链 (PEM) - 包含叶子证书 + 中间 CA
  pub certificate_chain: Vec<u8>,
  /// 私钥 (PEM)
  pub private_key: Vec<u8>,
  /// CA 证书链 (PEM)
  pub ca_certificate: Vec<u8>,
  /// 过期时间戳（毫秒）
  pub expires_at: u64,
  /// 证书序列号
  pub serial_number: String,
}

/// 生成的密钥对
pub struct GeneratedKeyPair {
  /// 私钥 (PEM 格式)
  pub private_key_pem: String,
  /// 内部密钥对对象
  pub(crate) key_pair: KeyPair,
}

/// 生成密钥对
pub fn generate_key_pair() -> Result<GeneratedKeyPair> {
  // 使用 rcgen 生成密钥对
  let key_pair = KeyPair::generate()
    .map_err(|e| TransportError::Certificate(format!("Failed to generate key pair: {}", e)))?;

  let private_key_pem = key_pair.serialize_pem();

  Ok(GeneratedKeyPair {
    private_key_pem,
    key_pair,
  })
}

/// 生成 CSR（证书签名请求）
///
/// # Arguments
/// * `key_pair` - 密钥对
/// * `device_id` - 设备 ID
pub fn generate_csr(
  key_pair: &GeneratedKeyPair,
  device_id: &str,
) -> Result<Vec<u8>> {
  let mut params = CertificateParams::default();

  // CSR contains only the device identity; authorization comes from the enrollment token.
  let mut dn = DistinguishedName::new();
  dn.push(
    DnType::CommonName,
    format!("device_{}", device_id),
  );
  dn.push(DnType::OrganizationName, "YAT Client");
  params.distinguished_name = dn;

  // 生成 CSR
  let csr = params
    .serialize_request(&key_pair.key_pair)
    .map_err(|e| TransportError::Certificate(format!("Failed to generate CSR: {}", e)))?;

  let pem_str = csr
    .pem()
    .map_err(|e| TransportError::Certificate(format!("Failed to encode CSR: {}", e)))?;

  Ok(pem_str.into_bytes())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_generate_key_pair() {
    let key_pair = generate_key_pair().unwrap();
    assert!(key_pair.private_key_pem.contains("BEGIN PRIVATE KEY"));
  }

  #[test]
  fn test_generate_csr() {
    let key_pair = generate_key_pair().unwrap();
    let csr = generate_csr(&key_pair, "test-device").unwrap();
    let csr_str = String::from_utf8(csr).unwrap();
    assert!(csr_str.contains("BEGIN CERTIFICATE REQUEST"));
  }
}
