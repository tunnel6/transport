//! EdgeClient - 与 Edge 服务器通信的主客户端
//!
//! 功能：
//! - 证书申请（单向 TLS）
//! - mTLS 连接管理
//! - 消息收发
//! - 心跳维护
//! - 请求-响应匹配

mod data_packet;
mod edge_ops;
mod http;
mod ice;
mod read_loop;
mod subscriptions;
mod tcp_bridge;
mod tunnel_ops;
mod udp_assoc;
mod wg_network_ops;
mod wg_path;

pub use wg_path::{
  WGPathLifecycleFact, WGPathLifecycleObserver, WGPathSession, WGPathSubscription,
};

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tokio_rustls::client::TlsStream;

use crate::client::cert::{generate_csr, generate_key_pair, CertRequestResult};
use crate::client::connection::{connect_mtls, connect_one_way_tls};
use crate::client::framing::{read_frame, write_frame};
use crate::client::utils::normalize_link_type;
use crate::error::{Result, TransportError};
use crate::protocol::generated::message_generated::message;
use crate::protocol::message::{
  IcePunchData, IceQuicStartData, IceStartData, IceStateChangeData, TunnelEventPushData,
  WGNetworkEventPushData,
};
use crate::protocol::{MessageBuilder, MessageReader, MessageType, ParsedResponse};

type ResponseSender = oneshot::Sender<Vec<u8>>;
type PendingRequests = Arc<Mutex<HashMap<u32, ResponseSender>>>;
type PendingTypeRequests = Arc<Mutex<HashMap<u16, VecDeque<u32>>>>;

// Agent deadlines can drop send_request before its own response timeout.
// Keep registration cleanup tied to the future's lifetime, including write failures.
struct PendingRequestGuard<'a> {
  client: &'a EdgeClient,
  seq: u32,
  expect_type: MessageType,
  stage: &'static str,
  finished: bool,
}

impl PendingRequestGuard<'_> {
  async fn cleanup(&mut self) {
    EdgeClient::remove_pending_registration(
      self.seq,
      &self.client.pending_requests,
      &self.client.pending_type_requests,
    )
    .await;
    self.finished = true;
  }
}

impl Drop for PendingRequestGuard<'_> {
  fn drop(&mut self) {
    if self.finished {
      return;
    }
    log::warn!(
      "[ReqFlow] request dropped edge={}:{} seq={} expect_type={} stage={}",
      self.client.config.host,
      self.client.config.port,
      self.seq,
      self.expect_type.0,
      self.stage
    );
    let pending = self.client.pending_requests.clone();
    let pending_type = self.client.pending_type_requests.clone();
    let seq = self.seq;
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
      runtime.spawn(async move {
        EdgeClient::remove_pending_registration(seq, &pending, &pending_type).await;
      });
    }
  }
}

type LogHandler = Box<dyn Fn(Vec<String>) + Send>;
type TunnelEventHandler = Box<dyn Fn(TunnelEventPushData) + Send>;
type WGNetworkEventHandler = Box<dyn Fn(WGNetworkEventPushData) + Send>;
type ChannelConnectionEventHandler = Box<dyn Fn(ChannelConnectionEventData) + Send>;

/// WG P2P 事件（Gather/Punch 推送自 Edge）
#[derive(Debug, Clone)]
pub enum WGP2PEvent {
  Gather {
    session_id: String,
  },
  Punch {
    session_id: String,
    client_id: String,
    punch_addrs: Vec<String>,
  },
}
type WGP2PEventHandler = Box<dyn Fn(WGP2PEvent) + Send>;

#[derive(Debug, Clone)]
pub enum IceMessage {
  Start(IceStartData),
  Punch(IcePunchData),
  QuicStart(IceQuicStartData),
  StateChange(IceStateChangeData),
}

type IceHandler = Box<dyn Fn(IceMessage) + Send>;

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 16 * 1024;
const MIN_CHANNEL_BUFFER_SIZE: usize = 1024;
const MAX_CHANNEL_BUFFER_SIZE: usize = 1024 * 1024;
const DYNAMIC_WINDOW_FLOOR: usize = 4 * 1024;
const UDP_ASSOC_READ_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_ASSOC_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

static UDP_ASSOC_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Edge 客户端配置
#[derive(Clone)]
pub struct EdgeClientConfig {
  pub host: String,
  pub port: u16,
  pub ca_cert: Vec<u8>,
  pub client_cert: Option<Vec<u8>>,
  pub client_key: Option<Vec<u8>>,
  pub heartbeat_interval_secs: u64,
  pub quic_keepalive_secs: u64,
  pub quic_idle_timeout_secs: u64,
  /// Edge ID (用于 SNI 回退)
  pub edge_id: Option<String>,
  /// 显式指定的 SNI server name（优先于 edge_id 构造的域名）
  pub server_name: Option<String>,
}

impl Default for EdgeClientConfig {
  fn default() -> Self {
    Self {
      host: String::new(),
      port: 0,
      ca_cert: Vec::new(),
      client_cert: None,
      client_key: None,
      heartbeat_interval_secs: 30,
      quic_keepalive_secs: 15,
      quic_idle_timeout_secs: 300,
      edge_id: None,
      server_name: None,
    }
  }
}

/// 订阅日志结果
#[derive(Debug, Clone)]
pub struct LogSubscriptionResult {
  pub success: bool,
  pub error_message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelConnectionEventData {
  pub phase: String, // open / close
  pub protocol: String,
  pub channel_id: String,
  pub connection_id: String,
  pub local_addr: String,
  pub link_type_hint: String,
  pub remote_endpoint: String,
  pub reason: String,
  pub timestamp: u64,
}

/// Channel 信息
#[derive(Clone, Debug)]
struct ChannelInfo {
  //  channel_id: String,
  local_addr: String,
  remote_endpoint: String,
  buffer_size: usize,
  dynamic_window: bool,
  protocol: String, // "tcp", "udp", "http", "https", etc.
  link_type: String,
}

/// Channel 本地流量统计（由 transport 收发路径直接累计）
#[derive(Clone, Debug, Default)]
struct ChannelTrafficStats {
  bytes_in: u64,
  bytes_out: u64,
}

#[derive(Clone, Debug)]
pub struct P2pChannelBinding {
  pub channel_id: String,
  pub local_addr: String,
  pub protocol: String,
}

/// TCP 连接信息
struct TcpConnection {
  //  connection_id: String,
  data_tx: mpsc::Sender<Vec<u8>>, // 用于发送数据到本地连接
  shutdown_tx: mpsc::Sender<u8>,  // bit0: FIN, bit1: RST
  channel_id: String,
  protocol: String,
  local_addr: String,
  link_type_hint: String,
  remote_endpoint: String,
}

#[derive(Clone)]
struct UdpAssociation {
  assoc_id: u64,
  channel_id: String,
  connection_id: String,
  target_addr: String,
  link_type_hint: String,
  remote_endpoint: String,
  socket: Arc<UdpSocket>,
  last_active_at_ms: Arc<AtomicU64>,
  shutdown_tx: mpsc::Sender<()>,
}

/// Edge 客户端
pub struct EdgeClient {
  reliable_runtime_push: AtomicBool,
  config: EdgeClientConfig,
  // Terminal owner shutdown tracks control tasks without cancelling in-flight
  // message dispatch. Legacy disconnect remains reusable; this fence does not.
  control_shutdown: tokio::sync::watch::Sender<bool>,
  control_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
  control_task_failed: AtomicBool,
  seq: Arc<AtomicU32>,
  session_id: Arc<RwLock<Option<String>>>,
  authenticated_device_id: Arc<RwLock<String>>,
  connected: Arc<AtomicBool>,
  writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
  pending_requests: PendingRequests,
  pending_type_requests: PendingTypeRequests,
  shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
  log_handler: Arc<Mutex<Option<LogHandler>>>,
  tunnel_event_handler: Arc<Mutex<Option<TunnelEventHandler>>>,
  wg_network_event_handler: Arc<Mutex<Option<WGNetworkEventHandler>>>,
  edge_status_handler: Arc<Mutex<Option<Box<dyn Fn(crate::EdgeStatusPushData) + Send>>>>,
  channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ice_handler: Arc<Mutex<Option<IceHandler>>>,
  wg_p2p_handler: Arc<Mutex<Option<WGP2PEventHandler>>>,
  // One binding per physical control connection, never reused on reconnect.
  wg_path_connection: std::sync::Mutex<Option<Arc<wg_path::PathConnection>>>,
  channels: Arc<Mutex<HashMap<String, ChannelInfo>>>, // channel_id -> ChannelInfo
  channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>, // channel_id -> traffic stats
  connections: Arc<Mutex<HashMap<String, TcpConnection>>>, // "{channel_id}::{connection_id}" -> TcpConnection
  udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>, // "{channel_id}::{connection_id}" -> UdpAssociation
}

impl EdgeClient {
  fn is_tunnel_definition_response_type(msg_type: MessageType) -> bool {
    msg_type == MessageType::TUNNEL_SYNC_RESPONSE
      || msg_type == MessageType::TUNNEL_UPSERT_RESPONSE
      || msg_type == MessageType::TUNNEL_DELETE_RESPONSE
      || msg_type == MessageType::ERROR
  }

  /// 创建新的 Edge 客户端
  pub fn new(config: EdgeClientConfig) -> Self {
    Self {
      config,
      control_shutdown: tokio::sync::watch::channel(false).0,
      control_tasks: std::sync::Mutex::new(Vec::new()),
      control_task_failed: AtomicBool::new(false),
      seq: Arc::new(AtomicU32::new(1)),
      reliable_runtime_push: AtomicBool::new(false),
      session_id: Arc::new(RwLock::new(None)),
      authenticated_device_id: Arc::new(RwLock::new(String::new())),
      connected: Arc::new(AtomicBool::new(false)),
      writer: Arc::new(Mutex::new(None)),
      pending_requests: Arc::new(Mutex::new(HashMap::new())),
      pending_type_requests: Arc::new(Mutex::new(HashMap::new())),
      shutdown_tx: Arc::new(Mutex::new(None)),
      log_handler: Arc::new(Mutex::new(None)),
      tunnel_event_handler: Arc::new(Mutex::new(None)),
      wg_network_event_handler: Arc::new(Mutex::new(None)),
      edge_status_handler: Arc::new(Mutex::new(None)),
      channel_connection_event_handler: Arc::new(Mutex::new(None)),
      ice_handler: Arc::new(Mutex::new(None)),
      wg_p2p_handler: Arc::new(Mutex::new(None)),
      wg_path_connection: std::sync::Mutex::new(None),
      channels: Arc::new(Mutex::new(HashMap::new())),
      channel_traffic: Arc::new(Mutex::new(HashMap::new())),
      connections: Arc::new(Mutex::new(HashMap::new())),
      udp_associations: Arc::new(Mutex::new(HashMap::new())),
    }
  }

  /// 获取下一个序列号
  fn next_seq(&self) -> u32 {
    self.seq.fetch_add(1, Ordering::SeqCst)
  }

  /// 是否已连接
  pub fn supports_reliable_runtime_push(&self) -> bool {
    self.is_connected() && self.reliable_runtime_push.load(Ordering::Acquire)
  }

  pub async fn authenticated_event_source(&self) -> Result<(String, String)> {
    let session=self.session_id.read().await.clone().ok_or(TransportError::NotConnected)?;
    let edge=self.config.edge_id.clone().filter(|id|!id.is_empty()).ok_or_else(||TransportError::Protocol("Edge identity missing".into()))?;
    Ok((edge,session))
  }

  pub fn is_connected(&self) -> bool {
    self.connected.load(Ordering::SeqCst)
  }

  fn normalize_buffer_size(size: usize) -> usize {
    size.clamp(MIN_CHANNEL_BUFFER_SIZE, MAX_CHANNEL_BUFFER_SIZE)
  }

  fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_millis() as u64)
      .unwrap_or(0)
  }

  fn build_channel_connection_event(
    phase: &str,
    protocol: &str,
    channel_id: &str,
    connection_id: &str,
    local_addr: &str,
    link_type_hint: &str,
    remote_endpoint: &str,
    reason: &str,
  ) -> ChannelConnectionEventData {
    ChannelConnectionEventData {
      phase: phase.to_string(),
      protocol: protocol.to_string(),
      channel_id: channel_id.to_string(),
      connection_id: connection_id.to_string(),
      local_addr: local_addr.to_string(),
      link_type_hint: normalize_link_type(link_type_hint),
      remote_endpoint: remote_endpoint.trim().to_string(),
      reason: reason.to_string(),
      timestamp: Self::now_millis(),
    }
  }

  async fn emit_channel_connection_event(
    handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
    event: ChannelConnectionEventData,
  ) {
    let guard = handler.lock().await;
    if let Some(h) = guard.as_ref() {
      h(event);
    }
  }

  fn udp_assoc_key(channel_id: &str, connection_id: &str) -> String {
    format!("{channel_id}::{connection_id}")
  }

  fn tcp_conn_key(channel_id: &str, connection_id: &str) -> String {
    format!("{channel_id}::{connection_id}")
  }

  fn udp_trace_enabled() -> bool {
    crate::debug::is_udp_trace_enabled()
  }

  fn udp_trace(line: impl Into<String>) {
    if !Self::udp_trace_enabled() {
      return;
    }
    let message = line.into();
    eprintln!("{}", message);
    crate::debug::append_udp_trace_line(&message);
  }

  async fn record_channel_traffic(
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channel_id: &str,
    bytes_in_delta: usize,
    bytes_out_delta: usize,
  ) {
    if channel_id.is_empty() || (bytes_in_delta == 0 && bytes_out_delta == 0) {
      return;
    }

    let mut traffic = channel_traffic.lock().await;
    let stat = traffic.entry(channel_id.to_string()).or_default();
    stat.bytes_in = stat.bytes_in.saturating_add(bytes_in_delta as u64);
    stat.bytes_out = stat.bytes_out.saturating_add(bytes_out_delta as u64);
  }

  pub async fn list_p2p_channel_bindings(&self) -> Vec<P2pChannelBinding> {
    let channels = self.channels.lock().await;
    channels
      .iter()
      .filter_map(|(channel_id, info)| {
        if normalize_link_type(&info.link_type) != "p2p" || info.local_addr.trim().is_empty() {
          return None;
        }
        Some(P2pChannelBinding {
          channel_id: channel_id.clone(),
          local_addr: info.local_addr.clone(),
          protocol: info.protocol.clone(),
        })
      })
      .collect()
  }

  pub async fn update_channel_local_addr(&self, channel_id: &str, local_addr: String) {
    let mut channels = self.channels.lock().await;
    if let Some(info) = channels.get_mut(channel_id) {
      info.local_addr = local_addr;
    }
  }

  /// 申请客户端证书(首次连接,无需已有证书)
  ///
  /// `token` — prefixed enrollment credential (invite:, pair:, oauth:<provider>:).
  /// `scopes` — existing scope claims from the current certificate (for merge).
  pub async fn request_certificate(
    &self,
    token: &str,
    device_id: &str,
    scopes: &[String],
  ) -> Result<CertRequestResult> {
    if !token.is_empty() || self.config.client_cert.is_none() || self.config.client_key.is_none() {
      super::enrollment::EnrollmentToken::parse(token)?;
    }
    // 生成密钥对和 CSR
    let key_pair = generate_key_pair()?;
    let csr = generate_csr(&key_pair, device_id)?;

    let response_data = if self.config.client_cert.is_some() && self.config.client_key.is_some() {
      self.connect().await?;
      let result = async {
        let auth = self.authenticate(device_id, "", env!("CARGO_PKG_VERSION"), &[], crate::PROTOCOL_MAJOR, crate::PROTOCOL_MINOR, &[], &[]).await?;
        if !auth.success {
          return Err(TransportError::Certificate(auth.error_message));
        }
        let seq = self.next_seq();
        let mut builder = MessageBuilder::new().seq(seq);
        if let Some(session_id) = self.session_id.read().await.clone() {
          builder = builder.session_id(session_id);
        }
        self.send_request(builder.cert_request(token, device_id, &csr, scopes), seq, MessageType::CERT_RESPONSE).await
      }.await;
      self.disconnect_and_wait().await?;
      result?
    } else {
      let connection = connect_one_way_tls(
        &self.config.host, self.config.port, &self.config.ca_cert,
        self.config.server_name.as_deref(), self.config.edge_id.as_deref(),
      ).await?;
      let (mut reader, mut writer) = connection.into_split();
      let message = MessageBuilder::new().seq(self.next_seq()).cert_request(token, device_id, &csr, scopes);
      write_frame(&mut writer, &message).await?;
      read_frame(&mut reader).await?
    };

    // 解析响应
    let response = MessageReader::parse_cert_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if !response.success {
      let error_detail = format!("{} (code: {})", response.error_message, response.error_code);
      // INTERNAL_ERROR (9999) is a generic server error, not necessarily a certificate issue.
      // Only classify as Certificate error for specific cert-related error codes (e.g. AUTH_FAILED).
      if response.error_code == message::ErrorCode::INTERNAL_ERROR.0 {
        return Err(TransportError::Connection(error_detail));
      }
      return Err(TransportError::Certificate(error_detail));
    }

    Ok(CertRequestResult {
      certificate: response.certificate,
      certificate_chain: response.certificate_chain, // 新增：证书链
      private_key: key_pair.private_key_pem.into_bytes(),
      ca_certificate: response.ca_certificate,
      expires_at: response.expires_at,
      serial_number: response.serial_number,
    })
  }

  /// 连接到 Edge 服务器(mTLS)
  pub async fn connect(&self) -> Result<()> {
    if *self.control_shutdown.borrow() {
      return Err(TransportError::Connection("Control owner has shut down".into()));
    }
    if self.is_connected() {
      return Err(TransportError::AlreadyConnected);
    }

    let client_cert = self.config.client_cert.as_ref().ok_or_else(|| {
      TransportError::Certificate("Client certificate not configured".to_string())
    })?;
    let client_key = self
      .config
      .client_key
      .as_ref()
      .ok_or_else(|| TransportError::Certificate("Client key not configured".to_string()))?;

    // 建立 mTLS 连接 (优先使用 server_name，否则从 edge_id 构造)
    let server_name_ref = self.config.server_name.as_deref();
    let edge_id_ref = self.config.edge_id.as_deref();
    let conn = connect_mtls(
      &self.config.host,
      self.config.port,
      &self.config.ca_cert,
      client_cert,
      client_key,
      server_name_ref,
      edge_id_ref,
    )
    .await?;

    let (reader, writer) = conn.into_split();

    // 保存 writer
    let path_connection = Arc::new(wg_path::PathConnection::new(self.config.edge_id.clone()));
    {
      let mut writer_guard = self.writer.lock().await;
      if let Some(previous) = self.path_connection() {
        previous.close();
      }
      *self.session_id.write().await = None;
      *self
        .wg_path_connection
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(path_connection.clone());
      *writer_guard = Some(writer);
    }
    self.connected.store(true, Ordering::SeqCst);

    // 启动读取循环（但不启动心跳，心跳在认证后启动）
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    *self.shutdown_tx.lock().await = Some(shutdown_tx);

    self.start_read_loop(reader, shutdown_rx, path_connection);
    // 注意：心跳循环延迟到 authenticate() 成功后启动
    Ok(())
  }

  /// 断开连接
  pub async fn disconnect(&self) -> Result<()> {
    if let Some(connection) = self.path_connection() {
      connection.close();
    }

    // 发送关闭信号（无论 connected 状态如何都必须执行，否则 read loop
    // 无法退出，TCP 连接无法关闭，服务端检测断连延迟高达 60s 读超时）。
    // 注意：不能在 is_connected() == false 时早退——心跳循环可能在
    // disconnect() 之前已将 connected 置 false（写失败），但 writer 仍
    // 持有 TCP 连接，必须在此处释放以发送 FIN。
    if let Some(tx) = self.shutdown_tx.lock().await.take() {
      let _ = tx.send(()).await;
    }

    // 清理状态
    *self.writer.lock().await = None;
    *self.session_id.write().await = None;
    self.connected.store(false, Ordering::SeqCst);

    // 关闭并清理 UDP 关联
    <Self as udp_assoc::UdpAssocOps>::shutdown_all_udp_associations(self.udp_associations.clone())
      .await;
    // 主动关闭 TCP 本地桥接连接，避免连接在 disconnect 后悬挂
    <Self as tcp_bridge::TcpBridge>::shutdown_all_tcp_connections(self.connections.clone(), 0x02)
      .await;

    // 清理 channel / tcp connection 缓存
    self.channels.lock().await.clear();
    self.channel_traffic.lock().await.clear();
    self.connections.lock().await.clear();

    // 清理 pending requests
    let mut pending = self.pending_requests.lock().await;
    pending.clear();

    let mut pending_type = self.pending_type_requests.lock().await;
    pending_type.clear();

    let mut log_handler = self.log_handler.lock().await;
    *log_handler = None;
    drop(log_handler);

    let mut tunnel_event_handler = self.tunnel_event_handler.lock().await;
    *tunnel_event_handler = None;
    drop(tunnel_event_handler);

    let mut wg_network_event_handler = self.wg_network_event_handler.lock().await;
    *wg_network_event_handler = None;
    drop(wg_network_event_handler);

    let mut channel_connection_event_handler = self.channel_connection_event_handler.lock().await;
    *channel_connection_event_handler = None;

    let mut ice_handler = self.ice_handler.lock().await;
    *ice_handler = None;

    Ok(())
  }

  fn track_control_task(&self, task: tokio::task::JoinHandle<()>) {
    let mut tasks = self.control_tasks.lock().unwrap_or_else(|e| e.into_inner());
    tasks.retain_mut(|task| {
      if !task.is_finished() { return true; }
      let mut context = std::task::Context::from_waker(std::task::Waker::noop());
      match std::future::Future::poll(std::pin::Pin::new(task), &mut context) {
        std::task::Poll::Ready(result) => {
          if result.is_err() { self.control_task_failed.store(true, Ordering::SeqCst); }
          false
        }
        std::task::Poll::Pending => true,
      }
    });
    tasks.push(task);
  }

  /// Terminal close for a serial connection owner. Stop heartbeat immediately,
  /// close the stream even after a read error, and await all control dispatch.
  /// Call outside message callbacks and serialize with connect/authenticate.
  pub async fn disconnect_and_wait(&self) -> Result<()> {
    self.control_shutdown.send_replace(true);
    self.disconnect().await?;
    self.connected.store(false, Ordering::SeqCst);
    if let Some(tx) = self.shutdown_tx.lock().await.take() { let _ = tx.send(()).await; }
    *self.writer.lock().await = None;
    self.unsubscribe_wg_p2p_events().await?;
    let tasks = std::mem::take(&mut *self.control_tasks.lock().unwrap_or_else(|e| e.into_inner()));
    for task in tasks {
      if let Err(error) = task.await {
        self.control_task_failed.store(true, Ordering::SeqCst);
        log::error!("Control task drain failed: {error}");
      }
    }
    if self.control_task_failed.load(Ordering::SeqCst) {
      return Err(TransportError::Connection("Control task failed; successful drain unproven".into()));
    }
    Ok(())
  }

  /// 发送消息并等待响应
  async fn remove_pending_registration(
    seq: u32,
    pending: &PendingRequests,
    pending_type: &PendingTypeRequests,
  ) {
    pending.lock().await.remove(&seq);
    pending_type.lock().await.retain(|_, queue| {
      queue.retain(|pending_seq| *pending_seq != seq);
      !queue.is_empty()
    });
  }

  async fn send_request(
    &self,
    data: Vec<u8>,
    seq: u32,
    expect_type: MessageType,
  ) -> Result<Vec<u8>> {
    if !self.is_connected() {
      return Err(TransportError::NotConnected);
    }
    let started_at = Instant::now();
    let request_len = data.len();
    let trace_definition_flow = Self::is_tunnel_definition_response_type(expect_type);
    let mut registration = PendingRequestGuard {
      client: self,
      seq,
      expect_type,
      stage: "registering",
      finished: false,
    };
    log::debug!(
      "[ReqFlow] request begin edge={}:{} seq={} expect_type={}",
      self.config.host,
      self.config.port,
      seq,
      expect_type.0
    );
    if trace_definition_flow {
      let (wire_type, wire_seq, wire_body_type) = match message::root_as_message(&data) {
        Ok(msg) => {
          let header = msg.header();
          let wire_type = header.map(|h| h.type_().0).unwrap_or_default();
          let wire_seq = header.map(|h| h.seq()).unwrap_or_default();
          let wire_body_type = format!("{:?}", msg.body_type());
          (wire_type, wire_seq, wire_body_type)
        }
        Err(_) => (0_u16, 0_u32, String::from("<invalid-flatbuffer>")),
      };
      eprintln!(
        "[ReqFlow] send_request begin seq={} expect_type={} request_len={} wire_type={} wire_seq={} wire_body_type={}",
        seq, expect_type.0, request_len, wire_type, wire_seq, wire_body_type
      );
    }

    // 创建响应通道
    let (tx, rx) = oneshot::channel();
    {
      let mut pending = self.pending_requests.lock().await;
      pending.insert(seq, tx);
    }
    {
      let mut pending = self.pending_type_requests.lock().await;
      pending
        .entry(expect_type.0)
        .or_insert_with(VecDeque::new)
        .push_back(seq);
      // ERROR responses must carry this request's sequence. A seq=0 error
      // can belong to a one-way uplink or a session broadcast, so assigning
      // it to the oldest request would corrupt an unrelated RPC.
    }

    // 发送消息
    registration.stage = "waiting_writer";
    let write_result = async {
      let mut writer_guard = self.writer.lock().await;
      let writer = writer_guard.as_mut().ok_or(TransportError::NotConnected)?;
      registration.stage = "writing";
      if trace_definition_flow {
        eprintln!(
          "[ReqFlow] send_request writing seq={} expect_type={} elapsed={}ms",
          seq,
          expect_type.0,
          started_at.elapsed().as_millis()
        );
      }
      if let Err(error) = write_frame(writer, &data).await {
        if trace_definition_flow {
          eprintln!(
            "[ReqFlow] send_request write failed seq={} expect_type={} elapsed={}ms err={}",
            seq,
            expect_type.0,
            started_at.elapsed().as_millis(),
            error
          );
        }
        return Err(error.into());
      }
      if trace_definition_flow {
        eprintln!(
          "[ReqFlow] send_request write ok seq={} expect_type={} elapsed={}ms",
          seq,
          expect_type.0,
          started_at.elapsed().as_millis()
        );
      }
      Ok(())
    }
    .await;
    if let Err(error) = write_result {
      registration.cleanup().await;
      return Err(error);
    }

    // 等待响应（带超时）
    registration.stage = "waiting_response";
    log::debug!(
      "[ReqFlow] request sent edge={}:{} seq={} expect_type={} elapsed={}ms",
      self.config.host,
      self.config.port,
      seq,
      expect_type.0,
      started_at.elapsed().as_millis()
    );
    let response = tokio::time::timeout(REQUEST_RESPONSE_TIMEOUT, rx).await;
    registration.cleanup().await;
    let response = match response {
      Ok(Ok(v)) => v,
      Ok(Err(_)) => {
        if trace_definition_flow {
          eprintln!(
            "[ReqFlow] send_request response channel closed seq={} expect_type={} elapsed={}ms",
            seq,
            expect_type.0,
            started_at.elapsed().as_millis()
          );
        }
        return Err(TransportError::Connection(
          "Response channel closed".to_string(),
        ));
      }
      Err(_) => {
        if trace_definition_flow {
          eprintln!(
            "[ReqFlow] send_request wait timeout seq={} expect_type={} timeout={}ms elapsed={}ms",
            seq,
            expect_type.0,
            REQUEST_RESPONSE_TIMEOUT.as_millis(),
            started_at.elapsed().as_millis()
          );
        }
        return Err(TransportError::Timeout);
      }
    };

    if trace_definition_flow {
      eprintln!(
        "[ReqFlow] send_request response ok seq={} expect_type={} response_len={} elapsed={}ms",
        seq,
        expect_type.0,
        response.len(),
        started_at.elapsed().as_millis()
      );
    }

    if MessageReader::get_type(&response).ok() == Some(MessageType::ERROR) {
      let error = MessageReader::parse_error(&response)
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
      return Err(TransportError::Protocol(format!(
        "Edge error {}: {} ({})",
        error.code, error.message, error.details
      )));
    }

    Ok(response)
  }

  /// 发送单向消息（不等待响应）
  async fn send_fire_and_forget(&self, data: Vec<u8>) -> Result<()> {
    if !self.is_connected() {
      return Err(TransportError::NotConnected);
    }
    let mut writer_guard = self.writer.lock().await;
    let writer = writer_guard.as_mut().ok_or(TransportError::NotConnected)?;
    write_frame(writer, &data).await?;
    Ok(())
  }

  /// 认证
  pub async fn authenticate(
    &self,
    device_id: &str,
    hostname: &str,
    client_version: &str,
    capabilities: &[String],
    protocol_major: u16,
    protocol_minor: u16,
    required_features: &[String],
    requested_features: &[String],
  ) -> Result<AuthResult> {
    if protocol_major != crate::PROTOCOL_MAJOR {
      return Err(TransportError::AuthFailed(format!(
        "This client implements protocol {}.{}, requested {}.{}; update the desktop/Agent/native addon together",
        crate::PROTOCOL_MAJOR, crate::PROTOCOL_MINOR, protocol_major, protocol_minor,
      )));
    }
    eprintln!(
      "[Auth] Starting authentication: device={}",
      device_id
    );

    let seq = self.next_seq();
    let caps: Vec<&str> = capabilities.iter().map(|s| s.as_str()).collect();
    let required: Vec<&str> = required_features.iter().map(|s| s.as_str()).collect();
    let mut requested: Vec<&str> = requested_features.iter().map(|s| s.as_str()).collect();
    if !requested.contains(&"wg.runtime-push.v1") { requested.push("wg.runtime-push.v1"); }

    let msg = MessageBuilder::new().seq(seq).auth_request(
      device_id,
      hostname,
      client_version,
      &caps,
      protocol_major,
      protocol_minor,
      &required,
      &requested,
    );

    eprintln!(
      "[Auth] Sending AUTH_REQUEST, seq={}, msg_len={}",
      seq,
      msg.len()
    );

    let response_data = self
      .send_request(msg, seq, MessageType::AUTH_RESPONSE)
      .await?;
    eprintln!("[Auth] Received AUTH_RESPONSE, len={}", response_data.len());

    let response = MessageReader::parse_auth_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if let Err(error) = crate::protocol::compatibility::validate_auth_response(&response) {
      let _ = self.disconnect().await;
      return Err(error);
    }

    self.reliable_runtime_push.store(response.success && response.accepted_features.iter().any(|f|f=="wg.runtime-push.v1"), Ordering::Release);
    if response.success {
      {
        let mut session_id = self.session_id.write().await;
        if let Some(connection) = self.path_connection() {
          connection.cancel_subscription();
        }
        *session_id = Some(response.session_id.clone());
      }
      *self.authenticated_device_id.write().await = device_id.trim().to_string();
      // 认证成功后启动心跳循环
      self.start_heartbeat_loop();
      eprintln!("[Auth] Heartbeat loop started after successful authentication");
    }

    Ok(AuthResult {
      success: response.success,
      session_id: response.session_id,
      server_version: response.server_version,
      error_code: response.error_code,
      error_message: response.error_message,
      negotiated_protocol_major: response.negotiated_protocol_major,
      negotiated_protocol_minor: response.negotiated_protocol_minor,
      accepted_features: response.accepted_features,
      rejected_features: response.rejected_features,
      compatibility_level: response.compatibility_level,
      reason_code: response.reason_code,
    })
  }

  fn start_heartbeat_loop(&self) {
    let interval_secs = self.config.heartbeat_interval_secs;
    let writer = self.writer.clone();
    let session_id = self.session_id.clone();
    let connected = self.connected.clone();
    let seq_counter = self.seq.clone();

    let mut shutdown = self.control_shutdown.subscribe();
    let task = tokio::spawn(async move {
      let mut heartbeat_interval = interval(Duration::from_secs(interval_secs));

      loop {
        if *shutdown.borrow() { break; }
        tokio::select! {
          biased;
          _ = shutdown.changed() => break,
          _ = heartbeat_interval.tick() => (),
        }

        if !connected.load(Ordering::SeqCst) {
          break;
        }

        let seq = seq_counter.fetch_add(1, Ordering::SeqCst);
        let sid = session_id.read().await.clone();

        let mut builder = MessageBuilder::new().seq(seq);
        if let Some(s) = sid {
          builder = builder.session_id(s);
        }
        let msg = builder.heartbeat();

        let mut writer_guard = writer.lock().await;
        if let Some(w) = writer_guard.as_mut() {
          if write_frame(w, &msg).await.is_err() {
            connected.store(false, Ordering::SeqCst);
            break;
          }
        }
      }
    });
    self.track_control_task(task);
  }
}

// Unwinding can skip async cleanup. Notify owned control tasks on final drop;
// hard process death is still handled by the Edge heartbeat/connection timeout.
impl Drop for EdgeClient {
  fn drop(&mut self) {
    self.control_shutdown.send_replace(true);
    self.connected.store(false, Ordering::SeqCst);
    if let Some(connection) = self.path_connection() { connection.close(); }
    if let Ok(guard) = self.shutdown_tx.try_lock() {
      if let Some(tx) = guard.as_ref() { let _ = tx.try_send(()); }
    }
  }
}

/// 认证结果
#[derive(Debug, Clone)]
pub struct AuthResult {
  pub success: bool,
  pub session_id: String,
  pub server_version: String,
  pub error_code: u32,
  pub error_message: String,
  pub negotiated_protocol_major: u16,
  pub negotiated_protocol_minor: u16,
  pub accepted_features: Vec<String>,
  pub rejected_features: Vec<String>,
  pub compatibility_level: u8,
  pub reason_code: u16,
}

/// Edge 操作结果
#[derive(Debug, Clone)]
pub struct EdgeOperationResult {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

#[derive(Debug, Clone)]
pub struct EdgeConfigResult {
  pub success: bool,
  pub config_json: String,
  pub restart_required: bool,
  pub error_message: String,
}

#[cfg(test)]
mod tests {
  use super::ChannelInfo;
  use super::EdgeClient;
  use super::EdgeClientConfig;
  use super::P2pChannelBinding;
  use super::TcpConnection;
  use crate::client::utils::resolve_local_channel_link_type;
  use std::collections::HashMap;
  use std::sync::Arc;
  use tokio::sync::{mpsc, Mutex};

  #[tokio::test]
  async fn terminal_close_waits_control_tasks_and_refuses_reconnect() {
    let client = Arc::new(EdgeClient::new(EdgeClientConfig::default()));
    client.connected.store(true, std::sync::atomic::Ordering::SeqCst);
    client.start_heartbeat_loop(); // No writer/socket: exercises notification only.
    let (release, receipt) = tokio::sync::oneshot::channel();
    let (started, entered) = tokio::sync::oneshot::channel();
    client.track_control_task(tokio::spawn(async move {
      let _ = started.send(()); let _ = receipt.await;
    }));
    entered.await.unwrap();
    let closing = client.clone();
    let close = tokio::spawn(async move { closing.disconnect_and_wait().await });
    tokio::task::yield_now().await;
    assert!(!close.is_finished());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), close).await.unwrap().unwrap().unwrap();
    assert!(!client.is_connected());
    // The terminal fence fails before any network connection is attempted.
    assert!(client.connect().await.is_err());
    client.disconnect_and_wait().await.unwrap();
  }

  #[tokio::test]
  async fn terminal_close_remembers_control_task_failure() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    client.track_control_task(tokio::spawn(async { panic!("injected control task failure"); }));
    assert!(client.disconnect_and_wait().await.is_err());
    assert!(client.disconnect_and_wait().await.is_err());
  }

  #[tokio::test]
  async fn final_drop_notifies_edge_reader_without_async_cleanup() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    let (tx, mut rx) = mpsc::channel(1);
    *client.shutdown_tx.lock().await = Some(tx);
    let mut heartbeat = client.control_shutdown.subscribe();
    drop(client);
    assert!(rx.recv().await.is_some());
    heartbeat.changed().await.unwrap();
    assert!(*heartbeat.borrow());
  }

  #[test]
  fn tcp_conn_key_scopes_connection_by_channel() {
    let key_a = EdgeClient::tcp_conn_key("tun-a:tcp-main", "conn-1");
    let key_b = EdgeClient::tcp_conn_key("tun-b:tcp-main", "conn-1");
    assert_ne!(key_a, key_b);
    assert_eq!(key_a, "tun-a:tcp-main::conn-1".to_string());
    assert_eq!(key_b, "tun-b:tcp-main::conn-1".to_string());
  }

  #[test]
  fn resolve_stop_result_channel_id_prefers_explicit_channel_id() {
    assert_eq!(
      EdgeClient::resolve_stop_result_channel_id("tun-1", " chan-a ", "main"),
      Some("chan-a".to_string())
    );
  }

  #[test]
  fn resolve_stop_result_channel_id_falls_back_to_tunnel_key() {
    assert_eq!(
      EdgeClient::resolve_stop_result_channel_id("tun-1", " ", " tcp-main "),
      Some("tun-1:tcp-main".to_string())
    );
    assert_eq!(
      EdgeClient::resolve_stop_result_channel_id("tun-1", "", ""),
      None
    );
  }

  #[tokio::test]
  async fn shutdown_tcp_connections_for_channel_only_targets_selected_channel() {
    let (data_tx_a, _data_rx_a) = mpsc::channel::<Vec<u8>>(1);
    let (shutdown_tx_a, mut shutdown_rx_a) = mpsc::channel::<u8>(1);
    let (data_tx_b, _data_rx_b) = mpsc::channel::<Vec<u8>>(1);
    let (shutdown_tx_b, mut shutdown_rx_b) = mpsc::channel::<u8>(1);

    let mut map: HashMap<String, TcpConnection> = HashMap::new();
    map.insert(
      EdgeClient::tcp_conn_key("tun-a:tcp-main", "conn-1"),
      TcpConnection {
        data_tx: data_tx_a,
        shutdown_tx: shutdown_tx_a,
        channel_id: "tun-a:tcp-main".to_string(),
        protocol: "tcp".to_string(),
        local_addr: "127.0.0.1:3306".to_string(),
        link_type_hint: "p2p".to_string(),
        remote_endpoint: "edge-a.example.com:10001".to_string(),
      },
    );
    map.insert(
      EdgeClient::tcp_conn_key("tun-b:tcp-main", "conn-1"),
      TcpConnection {
        data_tx: data_tx_b,
        shutdown_tx: shutdown_tx_b,
        channel_id: "tun-b:tcp-main".to_string(),
        protocol: "tcp".to_string(),
        local_addr: "127.0.0.1:5432".to_string(),
        link_type_hint: "relay".to_string(),
        remote_endpoint: "edge-b.example.com:10002".to_string(),
      },
    );
    let connections = Arc::new(Mutex::new(map));

    EdgeClient::shutdown_tcp_connections_for_channel(connections, "tun-a:tcp-main", 0x02).await;

    assert_eq!(shutdown_rx_a.recv().await, Some(0x02));
    assert!(shutdown_rx_b.try_recv().is_err());
  }

  #[tokio::test]
  async fn shutdown_all_tcp_connections_notifies_all_connections() {
    let (data_tx_a, _data_rx_a) = mpsc::channel::<Vec<u8>>(1);
    let (shutdown_tx_a, mut shutdown_rx_a) = mpsc::channel::<u8>(1);
    let (data_tx_b, _data_rx_b) = mpsc::channel::<Vec<u8>>(1);
    let (shutdown_tx_b, mut shutdown_rx_b) = mpsc::channel::<u8>(1);

    let mut map: HashMap<String, TcpConnection> = HashMap::new();
    map.insert(
      EdgeClient::tcp_conn_key("tun-a:tcp-main", "conn-1"),
      TcpConnection {
        data_tx: data_tx_a,
        shutdown_tx: shutdown_tx_a,
        channel_id: "tun-a:tcp-main".to_string(),
        protocol: "tcp".to_string(),
        local_addr: "127.0.0.1:3306".to_string(),
        link_type_hint: "p2p".to_string(),
        remote_endpoint: "edge-a.example.com:10001".to_string(),
      },
    );
    map.insert(
      EdgeClient::tcp_conn_key("tun-b:tcp-main", "conn-1"),
      TcpConnection {
        data_tx: data_tx_b,
        shutdown_tx: shutdown_tx_b,
        channel_id: "tun-b:tcp-main".to_string(),
        protocol: "tcp".to_string(),
        local_addr: "127.0.0.1:5432".to_string(),
        link_type_hint: "relay".to_string(),
        remote_endpoint: "edge-b.example.com:10002".to_string(),
      },
    );
    let connections = Arc::new(Mutex::new(map));

    EdgeClient::shutdown_all_tcp_connections(connections, 0x01).await;

    assert_eq!(shutdown_rx_a.recv().await, Some(0x01));
    assert_eq!(shutdown_rx_b.recv().await, Some(0x01));
  }

  #[test]
  fn build_channel_connection_event_carries_link_and_remote_context() {
    let event = EdgeClient::build_channel_connection_event(
      "open",
      "tcp",
      "tun-a:tcp-main",
      "conn-1",
      "127.0.0.1:3306",
      " wg ",
      " 198.51.100.12:443 ",
      "local-connected",
    );

    assert_eq!(event.phase, "open");
    assert_eq!(event.protocol, "tcp");
    assert_eq!(event.channel_id, "tun-a:tcp-main");
    assert_eq!(event.connection_id, "conn-1");
    assert_eq!(event.local_addr, "127.0.0.1:3306");
    assert_eq!(event.link_type_hint, "wireguard");
    assert_eq!(event.remote_endpoint, "198.51.100.12:443");
    assert_eq!(event.reason, "local-connected");
    assert!(event.timestamp > 0);
  }

  #[test]
  fn resolve_local_channel_link_type_falls_back_to_transport() {
    assert_eq!(
      resolve_local_channel_link_type("p2p", ""),
      "p2p".to_string()
    );
    assert_eq!(
      resolve_local_channel_link_type("wg", ""),
      "wireguard".to_string()
    );
    assert_eq!(
      resolve_local_channel_link_type("unknown", ""),
      "relay".to_string()
    );
  }

  #[test]
  fn resolve_local_channel_link_type_prefers_link_policy_preferred() {
    let metadata = r#"{"link_policy":{"preferred":["wireguard","relay"]}}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", metadata),
      "wireguard".to_string()
    );
  }

  #[test]
  fn resolve_local_channel_link_type_supports_link_policy_camel_case() {
    let metadata = r#"{"linkPolicy":{"preferred":["p2p","relay"]}}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", metadata),
      "p2p".to_string()
    );
  }

  #[test]
  fn resolve_local_channel_link_type_supports_transport_policy_sources() {
    let snake = r#"{"transport_policy":{"preferred_links":["wireguard","relay"]}}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", snake),
      "wireguard".to_string()
    );

    let camel = r#"{"transportPolicy":{"linkType":"p2p"}}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", camel),
      "p2p".to_string()
    );
  }

  #[test]
  fn resolve_local_channel_link_type_uses_top_level_override() {
    let metadata = r#"{"link_type":"p2p"}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", metadata),
      "p2p".to_string()
    );
    let metadata_camel = r#"{"linkType":"wireguard"}"#;
    assert_eq!(
      resolve_local_channel_link_type("relay", metadata_camel),
      "wireguard".to_string()
    );
  }

  #[test]
  fn resolve_local_channel_link_type_ignores_invalid_metadata() {
    let metadata = r#"{"link_policy":{"preferred":["invalid"]}}"#;
    assert_eq!(
      resolve_local_channel_link_type("wireguard", metadata),
      "wireguard".to_string()
    );

    assert_eq!(
      resolve_local_channel_link_type("p2p", "{not-json"),
      "p2p".to_string()
    );
  }

  #[tokio::test]
  async fn list_p2p_channel_bindings_filters_non_p2p_and_empty_addr() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    {
      let mut channels = client.channels.lock().await;
      channels.insert(
        "tun-1:http-main:publisher:actor-a".to_string(),
        ChannelInfo {
          local_addr: "127.0.0.1:18080".to_string(),
          remote_endpoint: "edge-a.example.com:443".to_string(),
          buffer_size: 16 * 1024,
          dynamic_window: true,
          protocol: "http".to_string(),
          link_type: "p2p".to_string(),
        },
      );
      channels.insert(
        "tun-1:tcp-main:consumer:actor-b".to_string(),
        ChannelInfo {
          local_addr: "127.0.0.1:13306".to_string(),
          remote_endpoint: "edge-b.example.com:443".to_string(),
          buffer_size: 16 * 1024,
          dynamic_window: true,
          protocol: "tcp".to_string(),
          link_type: "relay".to_string(),
        },
      );
      channels.insert(
        "tun-1:tcp-empty:consumer:actor-c".to_string(),
        ChannelInfo {
          local_addr: "   ".to_string(),
          remote_endpoint: "edge-c.example.com:443".to_string(),
          buffer_size: 16 * 1024,
          dynamic_window: true,
          protocol: "tcp".to_string(),
          link_type: "p2p".to_string(),
        },
      );
    }

    let bindings = client.list_p2p_channel_bindings().await;
    assert_eq!(bindings.len(), 1);
    let P2pChannelBinding {
      channel_id,
      local_addr,
      protocol,
    } = bindings.into_iter().next().expect("binding should exist");
    assert_eq!(channel_id, "tun-1:http-main:publisher:actor-a");
    assert_eq!(local_addr, "127.0.0.1:18080");
    assert_eq!(protocol, "http");
  }

  #[tokio::test]
  async fn update_channel_local_addr_only_updates_existing_channel() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    {
      let mut channels = client.channels.lock().await;
      channels.insert(
        "tun-2:tcp-main:consumer:actor-a".to_string(),
        ChannelInfo {
          local_addr: "127.0.0.1:12000".to_string(),
          remote_endpoint: "edge-a.example.com:443".to_string(),
          buffer_size: 16 * 1024,
          dynamic_window: true,
          protocol: "tcp".to_string(),
          link_type: "p2p".to_string(),
        },
      );
    }

    client
      .update_channel_local_addr(
        "tun-2:tcp-main:consumer:actor-a",
        "127.0.0.1:22000".to_string(),
      )
      .await;
    client
      .update_channel_local_addr("tun-2:missing", "127.0.0.1:9999".to_string())
      .await;

    let channels = client.channels.lock().await;
    assert_eq!(
      channels
        .get("tun-2:tcp-main:consumer:actor-a")
        .map(|info| info.local_addr.clone()),
      Some("127.0.0.1:22000".to_string())
    );
    assert!(channels.get("tun-2:missing").is_none());
  }
}
