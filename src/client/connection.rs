//! TCP/TLS 连接管理
//!
//! 支持单向 TLS（证书申请）和双向 mTLS（正常通信）

use crate::client::cert_verifier::CaOnlyVerifier;
use crate::error::{Result, TransportError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use socket2::{Socket, TcpKeepalive};
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

/// TCP keepalive parameters for fast dead-connection detection.
///
/// - `KEEPIDLE = 30s`: time before first probe (default OS: 2 hours)
/// - `KEEPINTVL = 10s`: interval between probes
/// - `KEEPCNT = 3`: number of probes before declaring dead
///
/// Total detection time: ~60s (30 + 10*3) instead of hours.
const TCP_KEEPALIVE_IDLE_SECS: u64 = 30;
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 10;
// TCP_KEEPCNT is not settable via socket2 on Windows (`with_retries` is
// unavailable there); Windows falls back to its OS-default probe count.
#[cfg(not(windows))]
const TCP_KEEPALIVE_COUNT: u32 = 3;

/// Connect to a TCP address with keepalive enabled and tuned for fast detection.
///
/// TCP keepalive detects dead connections when Edge crashes or TCP FIN is lost
/// (e.g., due to firewall/NAT). Without keepalive, the Agent's read_loop would
/// wait indefinitely for data that never comes.
///
/// Tuned parameters (vs OS defaults):
/// - `KEEPIDLE = 30s` (default: 2 hours) — first probe after 30s of idle
/// - `KEEPINTVL = 10s` (default: 75s) — probe every 10s
/// - `KEEPCNT = 3` (default: 9) — declare dead after 3 failed probes
///
/// Total detection time: ~60s instead of hours.
async fn connect_tcp_with_keepalive(addr: &str) -> Result<TcpStream> {
  // Use tokio's normal connect
  let tcp_stream = TcpStream::connect(addr)
    .await
    .map_err(|e| TransportError::Connection(format!("Failed to connect to {}: {}", addr, e)))?;

  // Enable TCP keepalive using socket2 on the underlying socket
  let std_socket = tcp_stream
    .into_std()
    .map_err(|e| TransportError::Connection(format!("Failed to convert to std socket: {}", e)))?;

  let socket = Socket::from(std_socket);

  // Configure keepalive parameters for fast dead-connection detection.
  // `with_retries` (TCP_KEEPCNT) is unavailable on Windows, so it is applied
  // only on platforms that support it; Windows uses the OS-default probe count.
  let keepalive = TcpKeepalive::new()
    .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS))
    .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS));

  #[cfg(not(windows))]
  let keepalive = keepalive.with_retries(TCP_KEEPALIVE_COUNT);

  socket
    .set_tcp_keepalive(&keepalive)
    .map_err(|e| TransportError::Connection(format!("Failed to set keepalive params: {}", e)))?;

  // Also enable SO_KEEPALIVE (required on some platforms)
  socket
    .set_keepalive(true)
    .map_err(|e| TransportError::Connection(format!("Failed to enable keepalive: {}", e)))?;

  // Convert back to tokio's TcpStream
  let std_stream: std::net::TcpStream = socket.into();
  let tcp_stream = TcpStream::from_std(std_stream).map_err(|e| {
    TransportError::Connection(format!("Failed to convert back to tokio stream: {}", e))
  })?;

  Ok(tcp_stream)
}

/// Canonical logical name, shared by every product and transport path.
pub fn default_edge_server_name(edge_id: &str) -> String {
  format!("{edge_id}.edge.myproxy.dev")
}

/// TLS 连接类型
pub enum TlsConnection {
  /// 单向 TLS（只验证服务器证书）
  OneWay(TlsStream<TcpStream>),
  /// 双向 mTLS（双向验证）
  Mutual(TlsStream<TcpStream>),
}

impl TlsConnection {
  /// 获取内部的读写流
  pub fn into_split(
    self,
  ) -> (
    tokio::io::ReadHalf<TlsStream<TcpStream>>,
    tokio::io::WriteHalf<TlsStream<TcpStream>>,
  ) {
    match self {
      TlsConnection::OneWay(stream) => tokio::io::split(stream),
      TlsConnection::Mutual(stream) => tokio::io::split(stream),
    }
  }
}

/// 建立单向 TLS 连接(用于证书申请)
///
/// 只验证服务器证书,不提供客户端证书
///
/// # Arguments
/// * `host` - Edge 服务器的实际地址(IP 或域名)
/// * `port` - Edge 服务器的端口
/// * `ca_cert_pem` - CA 证书(用于验证服务器证书)
/// * `server_name` - 显式指定的 SNI 域名（优先使用）
/// * `edge_id` - Edge ID(可选),用于构造逻辑域名 <edge_id>.edge.myproxy.dev 作为 SNI 回退
pub async fn connect_one_way_tls(
  host: &str,
  port: u16,
  ca_cert_pem: &[u8],
  server_name: Option<&str>,
  edge_id: Option<&str>,
) -> Result<TlsConnection> {
  // 解析 CA 证书
  let root_store = Arc::new(parse_ca_cert(ca_cert_pem)?);

  // 创建 TLS 配置(无客户端证书)，使用只验证 CA 链的自定义 verifier
  let verifier = CaOnlyVerifier::new(root_store)
    .map_err(|e| TransportError::Tls(format!("Failed to create verifier: {}", e)))?;
  let mut config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

  // 设置 ALPN 协议，与 Edge 服务器协商
  config.alpn_protocols = vec![b"tunnel/1".to_vec()];
  config.enable_sni = false;

  let connector = TlsConnector::from(Arc::new(config));

  // 建立 TCP 连接(使用实际的 host:port)，启用 keepalive 检测死连接
  let addr = edge_socket_address(host, port);
  let tcp_stream = connect_tcp_with_keepalive(&addr).await?;

  // 确定 SNI(Server Name Indication)
  // 优先使用显式指定的 server_name，其次从 edge_id 构造，最后回退到 host
  let sni = if let Some(sn) = server_name {
    ServerName::try_from(sn.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", sn)))?
  } else if let Some(eid) = edge_id {
    // 使用逻辑域名作为 SNI,用于证书校验
    let logical_host = default_edge_server_name(eid);
    ServerName::try_from(logical_host.clone())
      .map_err(|_| TransportError::Tls(format!("Invalid logical server name: {}", logical_host)))?
  } else if let Ok(ip_addr) = host.parse::<std::net::IpAddr>() {
    // 旧逻辑:IP 地址使用 IpAddr
    ServerName::IpAddress(ip_addr.into())
  } else {
    // 旧逻辑:域名使用 DnsName
    ServerName::try_from(host.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", host)))?
  };

  let tls_stream = connector
    .connect(sni, tcp_stream)
    .await
    .map_err(|e| TransportError::Tls(format!("TLS handshake failed: {}", e)))?;

  Ok(TlsConnection::OneWay(tls_stream))
}

/// 建立健康检查 TLS 连接(仅用于探活)
///
/// 特点:
/// - 只验证服务器证书,不提供客户端证书
/// - 使用 ALPN 协议标记为 "edge-health/1", 便于服务端区分连接语义
pub async fn connect_healthcheck(
  host: &str,
  port: u16,
  ca_cert_pem: &[u8],
  server_name: Option<&str>,
  edge_id: Option<&str>,
) -> Result<TlsConnection> {
  // 解析 CA 证书
  let root_store = Arc::new(parse_ca_cert(ca_cert_pem)?);

  // 创建 TLS 配置(无客户端证书),并设置健康检查用的 ALPN
  let verifier = CaOnlyVerifier::new(root_store)
    .map_err(|e| TransportError::Tls(format!("Failed to create verifier: {}", e)))?;
  let mut config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
  config.alpn_protocols = vec![b"edge-health/1".to_vec()];
  config.enable_sni = false;

  let connector = TlsConnector::from(Arc::new(config));

  // 建立 TCP 连接(使用实际的 host:port)，启用 keepalive 检测死连接
  let addr = edge_socket_address(host, port);
  let tcp_stream = connect_tcp_with_keepalive(&addr).await?;

  // 确定 SNI,逻辑与 connect_one_way_tls 保持一致
  let sni = if let Some(sn) = server_name {
    ServerName::try_from(sn.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", sn)))?
  } else if let Some(eid) = edge_id {
    let logical_host = default_edge_server_name(eid);
    ServerName::try_from(logical_host.clone())
      .map_err(|_| TransportError::Tls(format!("Invalid logical server name: {}", logical_host)))?
  } else if let Ok(ip_addr) = host.parse::<std::net::IpAddr>() {
    ServerName::IpAddress(ip_addr.into())
  } else {
    ServerName::try_from(host.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", host)))?
  };

  let tls_stream = connector
    .connect(sni, tcp_stream)
    .await
    .map_err(|e| TransportError::Tls(format!("TLS handshake failed: {}", e)))?;

  Ok(TlsConnection::OneWay(tls_stream))
}

/// 建立双向 mTLS 连接(用于正常通信)
///
/// 双向验证:验证服务器证书,并提供客户端证书
///
/// # Arguments
/// * `host` - Edge 服务器的实际地址(IP 或域名)
/// * `port` - Edge 服务器的端口
/// * `ca_cert_pem` - CA 证书(用于验证服务器证书)
/// * `client_cert_pem` - 客户端证书
/// * `client_key_pem` - 客户端私钥
/// * `server_name` - 显式指定的 SNI 域名（优先使用）
/// * `edge_id` - Edge ID(可选),用于构造逻辑域名 <edge_id>.edge.myproxy.dev 作为 SNI 回退
pub async fn connect_mtls(
  host: &str,
  port: u16,
  ca_cert_pem: &[u8],
  client_cert_pem: &[u8],
  client_key_pem: &[u8],
  server_name: Option<&str>,
  edge_id: Option<&str>,
) -> Result<TlsConnection> {
  // 解析 CA 证书
  let root_store = Arc::new(parse_ca_cert(ca_cert_pem)?);

  // 解析客户端证书
  let client_certs = parse_certs(client_cert_pem)?;

  // 解析客户端私钥
  let client_key = parse_private_key(client_key_pem)?;

  // 调试：记录证书数量
  log::debug!("[mTLS] Loaded {} client certificate(s)", client_certs.len());
  log::debug!(
    "[mTLS] Client key type: {:?}",
    std::any::type_name_of_val(&client_key)
  );

  // 创建 TLS 配置(带客户端证书)，使用只验证 CA 链的自定义 verifier
  let verifier = CaOnlyVerifier::new(root_store)
    .map_err(|e| TransportError::Tls(format!("Failed to create verifier: {}", e)))?;
  let mut config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(client_certs, client_key)
    .map_err(|e| TransportError::Certificate(format!("Invalid client certificate: {}", e)))?;

  // 设置 ALPN 协议，与 Edge 服务器协商
  config.alpn_protocols = vec![b"tunnel/1".to_vec()];
  config.enable_sni = false;

  let connector = TlsConnector::from(Arc::new(config));

  // 建立 TCP 连接(使用实际的 host:port)，启用 keepalive 检测死连接
  // 这是主 mTLS 连接，用于所有 Edge 通信
  let addr = edge_socket_address(host, port);
  let tcp_stream = connect_tcp_with_keepalive(&addr).await?;

  // 确定 SNI(Server Name Indication)
  // 优先使用显式指定的 server_name，其次从 edge_id 构造，最后回退到 host
  let server_name = if let Some(sn) = server_name {
    ServerName::try_from(sn.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", sn)))?
  } else if let Some(eid) = edge_id {
    // 使用逻辑域名作为 SNI,用于证书校验
    let logical_host = default_edge_server_name(eid);
    ServerName::try_from(logical_host.clone())
      .map_err(|_| TransportError::Tls(format!("Invalid logical server name: {}", logical_host)))?
  } else {
    // 旧逻辑:直接使用 host 作为 SNI
    ServerName::try_from(host.to_string())
      .map_err(|_| TransportError::Tls(format!("Invalid server name: {}", host)))?
  };

  let tls_stream = match connector.connect(server_name, tcp_stream).await {
    Ok(stream) => stream,
    Err(e) => {
      // Distinguish transient network/IO errors from actual certificate
      // failures so the caller (and ultimately the FE error classifier)
      // does not mis-classify a timeout or connection reset as a
      // certificate error.
      let kind = e.kind();
      let is_transient = matches!(
        kind,
        std::io::ErrorKind::TimedOut
          | std::io::ErrorKind::ConnectionReset
          | std::io::ErrorKind::ConnectionRefused
          | std::io::ErrorKind::ConnectionAborted
          | std::io::ErrorKind::BrokenPipe
          | std::io::ErrorKind::UnexpectedEof
          | std::io::ErrorKind::WriteZero
          | std::io::ErrorKind::Interrupted
      );
      if is_transient {
        return Err(TransportError::Connection(format!(
          "mTLS handshake failed (transient: {}): {}",
          kind, e
        )));
      }
      return Err(TransportError::Tls(format!("mTLS handshake failed: {}", e)));
    }
  };

  // 调试：打印 TLS 连接信息
  let (_, conn_info) = tls_stream.get_ref();
  log::debug!("[mTLS] TLS handshake complete");
  log::debug!("[mTLS] ALPN negotiated: {:?}", conn_info.alpn_protocol());
  log::debug!(
    "[mTLS] Protocol version: {:?}",
    conn_info.protocol_version()
  );

  Ok(TlsConnection::Mutual(tls_stream))
}

/// 解析 CA 证书
fn parse_ca_cert(pem: &[u8]) -> Result<RootCertStore> {
  let mut reader = BufReader::new(pem);
  let certs = rustls_pemfile::certs(&mut reader)
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|e| TransportError::Certificate(format!("Failed to parse CA cert: {}", e)))?;

  let mut root_store = RootCertStore::empty();
  for cert in certs {
    root_store
      .add(cert)
      .map_err(|e| TransportError::Certificate(format!("Failed to add CA cert: {}", e)))?;
  }

  if root_store.is_empty() {
    return Err(TransportError::Certificate(
      "No CA certificates found".to_string(),
    ));
  }

  Ok(root_store)
}

/// 解析证书链
fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
  let mut reader = BufReader::new(pem);
  let certs = rustls_pemfile::certs(&mut reader)
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|e| TransportError::Certificate(format!("Failed to parse cert: {}", e)))?;

  if certs.is_empty() {
    return Err(TransportError::Certificate(
      "No certificates found".to_string(),
    ));
  }

  Ok(certs)
}

/// 解析私钥
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
  let mut reader = BufReader::new(pem);

  // 尝试读取各种格式的私钥
  loop {
    match rustls_pemfile::read_one(&mut reader) {
      Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
        return Ok(PrivateKeyDer::Pkcs1(key));
      }
      Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
        return Ok(PrivateKeyDer::Pkcs8(key));
      }
      Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
        return Ok(PrivateKeyDer::Sec1(key));
      }
      Ok(Some(_)) => continue, // 跳过其他类型
      Ok(None) => break,
      Err(e) => {
        return Err(TransportError::Certificate(format!(
          "Failed to parse private key: {}",
          e
        )))
      }
    }
  }

  Err(TransportError::Certificate(
    "No private key found".to_string(),
  ))
}

// IPv6 literals require brackets when joined with a port.
fn edge_socket_address(host: &str, port: u16) -> String {
  if host.contains(':') { format!("[{}]:{}", host, port) } else { format!("{}:{}", host, port) }
}

#[cfg(test)]
mod socket_address_tests {
  use super::edge_socket_address;
  #[test]
  fn edge_socket_addresses_preserve_dns_ipv4_and_ipv6() {
    assert_eq!(edge_socket_address("edge.example", 9443), "edge.example:9443");
    assert_eq!(edge_socket_address("192.0.2.1", 9443), "192.0.2.1:9443");
    assert_eq!(edge_socket_address("2001:db8::1", 9443), "[2001:db8::1]:9443");
    assert_eq!(edge_socket_address("::1", 443).parse::<std::net::SocketAddr>().unwrap().port(), 443);
  }
}

#[cfg(test)]
mod unified_tls_tests {
  #[test]
  fn canonical_edge_name_is_product_independent() {
    assert_eq!(super::default_edge_server_name("edge-a"), "edge-a.edge.myproxy.dev");
  }
}
