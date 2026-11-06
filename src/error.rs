//! 错误类型定义

use thiserror::Error;

/// A confirmed Auth rejection, distinct from credentials and feature negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityReason {
  ProtocolMismatch,
  EdgeVersionTooOld,
  EdgeVersionUnknown,
}

#[derive(Clone, Debug, Error)]
#[error("{message}")]
pub struct CompatibilityError {
  pub reason: CompatibilityReason,
  pub edge_version: String,
  pub minimum_edge_version: String,
  pub client_protocol: String,
  pub edge_protocol: String,
  pub message: String,
}

#[derive(Error, Debug)]
pub enum TransportError {
  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  #[error("TLS error: {0}")]
  Tls(String),

  #[error("Certificate error: {0}")]
  Certificate(String),

  #[error("Protocol error: {0}")]
  Protocol(String),

  #[error("Connection error: {0}")]
  Connection(String),

  #[error("Authentication failed: {0}")]
  AuthFailed(String),

  #[error("{0}")]
  Incompatible(#[from] Box<CompatibilityError>),

  #[error("Timeout")]
  Timeout,

  #[error("Not connected")]
  NotConnected,

  #[error("Already connected")]
  AlreadyConnected,
}

pub type Result<T> = std::result::Result<T, TransportError>;

// 实现 napi::Error 转换 (仅在 napi-bindings feature 开启时可用)
#[cfg(feature = "napi-bindings")]
impl From<TransportError> for napi::Error {
  fn from(err: TransportError) -> Self {
    napi::Error::from_reason(err.to_string())
  }
}
