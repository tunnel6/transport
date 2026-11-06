use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct ChannelRoute {
  pub local_addr: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ForwarderRole {
  Publisher,
  Consumer,
}

pub struct P2pForwarder {
  connection: quinn::Connection,
  role: ForwarderRole,
  routes: Arc<Mutex<HashMap<String, ChannelRoute>>>,
  consumer_tcp_listeners: Arc<Mutex<HashMap<String, ConsumerTcpListener>>>,
  consumer_udp_listeners: Arc<Mutex<HashMap<String, ConsumerUdpListener>>>,
  publisher_udp_associations: Arc<Mutex<HashMap<String, PublisherUdpAssociation>>>,
  publisher_udp_assoc_counter: Arc<AtomicU64>,
  datagram_task: Arc<Mutex<Option<JoinHandle<()>>>>,
  shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

struct ConsumerTcpListener {
  local_addr: SocketAddr,
  task: JoinHandle<()>,
}

struct ConsumerUdpListener {
  local_addr: SocketAddr,
  socket: Arc<UdpSocket>,
  task: JoinHandle<()>,
}

#[derive(Clone)]
struct PublisherUdpAssociation {
  assoc_id: u64,
  target_addr: String,
  socket: Arc<UdpSocket>,
  last_active_at_ms: Arc<AtomicU64>,
  abort: tokio::task::AbortHandle,
}

#[derive(Debug)]
struct UdpFrame {
  channel_id: String,
  peer_client_addr: String,
  payload: Vec<u8>,
}

const CONSUMER_LISTENER_PORT_FALLBACK_MAX_STEPS: u16 = 16;
const UDP_FRAME_VERSION: u8 = 1;
const UDP_ASSOC_READ_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_ASSOC_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

fn canonical_channel_id(channel_id: &str) -> String {
  let raw = channel_id.trim();
  if raw.is_empty() {
    return String::new();
  }
  let mut parts = raw.rsplitn(3, ':');
  let actor = parts.next();
  let role = parts.next();
  let base = parts.next();
  if let (Some(actor), Some(role), Some(base)) = (actor, role, base) {
    if !actor.is_empty() && (role == "consumer" || role == "controller" || role == "publisher") {
      return base.to_string();
    }
  }
  raw.to_string()
}

fn next_port_candidate(base: SocketAddr, step: u16) -> Option<SocketAddr> {
  let next = u32::from(base.port()) + u32::from(step);
  if next > u32::from(u16::MAX) {
    return None;
  }
  Some(SocketAddr::new(base.ip(), next as u16))
}

fn is_addr_in_use_error(err: &std::io::Error) -> bool {
  err.kind() == ErrorKind::AddrInUse
    || err
      .to_string()
      .to_ascii_lowercase()
      .contains("address already in use")
}

async fn resolve_bind_base_addrs(bind_addr: &str) -> Vec<SocketAddr> {
  if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
    return vec![addr];
  }
  match lookup_host(bind_addr).await {
    Ok(iter) => {
      let mut out = Vec::new();
      for addr in iter {
        if !out.contains(&addr) {
          out.push(addr);
        }
      }
      out
    }
    Err(_) => Vec::new(),
  }
}

fn now_millis() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_millis() as u64)
    .unwrap_or(0)
}

fn publisher_assoc_key(channel_id: &str, peer_client_addr: &str) -> String {
  format!("{}::{}", channel_id.trim(), peer_client_addr.trim())
}

fn encode_udp_frame(
  channel_id: &str,
  peer_client_addr: &str,
  payload: &[u8],
) -> Result<Vec<u8>, String> {
  let channel_bytes = channel_id.as_bytes();
  let peer_addr_bytes = peer_client_addr.as_bytes();

  if channel_bytes.len() > u16::MAX as usize {
    return Err("udp frame channel_id too long".to_string());
  }
  if peer_addr_bytes.len() > u16::MAX as usize {
    return Err("udp frame peer_client_addr too long".to_string());
  }

  let mut frame =
    Vec::with_capacity(5 + channel_bytes.len() + peer_addr_bytes.len() + payload.len());
  frame.push(UDP_FRAME_VERSION);
  frame.extend_from_slice(&(channel_bytes.len() as u16).to_be_bytes());
  frame.extend_from_slice(&(peer_addr_bytes.len() as u16).to_be_bytes());
  frame.extend_from_slice(channel_bytes);
  frame.extend_from_slice(peer_addr_bytes);
  frame.extend_from_slice(payload);
  Ok(frame)
}

fn decode_udp_frame(data: &[u8]) -> Result<UdpFrame, String> {
  if data.len() < 5 {
    return Err("udp frame too short".to_string());
  }
  if data[0] != UDP_FRAME_VERSION {
    return Err(format!("udp frame version mismatch: {}", data[0]));
  }

  let channel_len = u16::from_be_bytes([data[1], data[2]]) as usize;
  let peer_addr_len = u16::from_be_bytes([data[3], data[4]]) as usize;

  let header_and_ids_len = 5usize
    .checked_add(channel_len)
    .and_then(|value| value.checked_add(peer_addr_len))
    .ok_or_else(|| "udp frame length overflow".to_string())?;

  if data.len() < header_and_ids_len {
    return Err("udp frame body truncated".to_string());
  }

  let channel_start = 5;
  let channel_end = channel_start + channel_len;
  let peer_start = channel_end;
  let peer_end = peer_start + peer_addr_len;

  let channel_id = String::from_utf8(data[channel_start..channel_end].to_vec())
    .map_err(|_| "udp frame channel_id is not utf8".to_string())?;
  let peer_client_addr = String::from_utf8(data[peer_start..peer_end].to_vec())
    .map_err(|_| "udp frame peer_client_addr is not utf8".to_string())?;
  let payload = data[peer_end..].to_vec();

  Ok(UdpFrame {
    channel_id,
    peer_client_addr,
    payload,
  })
}

fn send_udp_frame(
  connection: &quinn::Connection,
  channel_id: &str,
  peer_client_addr: &str,
  payload: &[u8],
) -> Result<(), String> {
  let frame = encode_udp_frame(channel_id, peer_client_addr, payload)?;
  let max_size = connection.max_datagram_size().unwrap_or(0);
  if max_size == 0 {
    return Err("quic datagram unsupported by peer".to_string());
  }
  if frame.len() > max_size {
    return Err(format!(
      "udp frame too large: frame={} max={} channel={} peer={}",
      frame.len(),
      max_size,
      channel_id,
      peer_client_addr
    ));
  }

  connection
    .send_datagram(frame.into())
    .map_err(|err| format!("send_datagram failed: {}", err))
}

impl P2pForwarder {
  pub fn new(connection: quinn::Connection, role: ForwarderRole) -> Self {
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    Self {
      connection,
      role,
      routes: Arc::new(Mutex::new(HashMap::new())),
      consumer_tcp_listeners: Arc::new(Mutex::new(HashMap::new())),
      consumer_udp_listeners: Arc::new(Mutex::new(HashMap::new())),
      publisher_udp_associations: Arc::new(Mutex::new(HashMap::new())),
      publisher_udp_assoc_counter: Arc::new(AtomicU64::new(1)),
      datagram_task: Arc::new(Mutex::new(None)),
      shutdown_tx,
    }
  }

  pub async fn start_datagram_accept(&self) {
    let mut datagram_task_guard = self.datagram_task.lock().await;
    if datagram_task_guard.is_some() {
      return;
    }

    let conn = self.connection.clone();
    let role = self.role.clone();
    let routes = self.routes.clone();
    let consumer_udp_listeners = self.consumer_udp_listeners.clone();
    let publisher_udp_associations = self.publisher_udp_associations.clone();
    let publisher_udp_assoc_counter = self.publisher_udp_assoc_counter.clone();
    let shutdown_tx = self.shutdown_tx.clone();
    let mut shutdown_rx = self.shutdown_tx.subscribe();

    let task = tokio::spawn(async move {
      loop {
        tokio::select! {
          _ = shutdown_rx.recv() => break,
          result = conn.read_datagram() => {
            match result {
              Ok(datagram) => {
                let frame = match decode_udp_frame(datagram.as_ref()) {
                  Ok(frame) => frame,
                  Err(err) => {
                    eprintln!("[P2pForwarder] drop invalid udp frame: {}", err);
                    continue;
                  }
                };

                if role == ForwarderRole::Publisher {
                  if let Err(err) = handle_publisher_udp_frame(
                    frame,
                    &conn,
                    routes.clone(),
                    publisher_udp_associations.clone(),
                    publisher_udp_assoc_counter.clone(),
                    shutdown_tx.clone(),
                  ).await {
                    eprintln!("[P2pForwarder] publisher udp frame error: {}", err);
                  }
                } else if let Err(err) =
                  handle_consumer_udp_frame(frame, consumer_udp_listeners.clone()).await
                {
                  eprintln!("[P2pForwarder] consumer udp frame error: {}", err);
                }
              }
              Err(err) => {
                eprintln!("[P2pForwarder] read_datagram failed: {}", err);
                break;
              }
            }
          }
        }
      }
    });

    *datagram_task_guard = Some(task);
  }

  pub async fn register_channel(&self, channel_id: String, local_addr: String) {
    let canonical_id = canonical_channel_id(&channel_id);
    eprintln!(
      "[P2pForwarder] register_channel role={:?} channel={} canonical={} local={}",
      self.role, channel_id, canonical_id, local_addr
    );
    let mut routes = self.routes.lock().await;
    routes.insert(
      channel_id.clone(),
      ChannelRoute {
        local_addr: local_addr.clone(),
      },
    );
    if canonical_id != channel_id {
      routes.insert(canonical_id.clone(), ChannelRoute { local_addr });
    }
  }

  pub fn start_publisher_accept(&self) {
    let conn = self.connection.clone();
    let routes = self.routes.clone();
    let mut shutdown_rx = self.shutdown_tx.subscribe();

    tokio::spawn(async move {
      loop {
        tokio::select! {
          _ = shutdown_rx.recv() => break,
          result = conn.accept_bi() => {
            match result {
              Ok((send, recv)) => {
                let routes = routes.clone();
                tokio::spawn(async move {
                  if let Err(e) = handle_publisher_stream(send, recv, routes).await {
                    eprintln!("[P2pForwarder] publisher stream error: {}", e);
                  }
                });
              }
              Err(e) => {
                eprintln!("[P2pForwarder] accept_bi failed: {}", e);
                break;
              }
            }
          }
        }
      }
    });
  }

  pub async fn start_consumer_listener(&self, channel_id: &str) -> Result<SocketAddr, String> {
    self
      .start_consumer_listener_with_bind(channel_id, None)
      .await
  }

  pub async fn start_consumer_listener_with_bind(
    &self,
    channel_id: &str,
    bind_addr: Option<&str>,
  ) -> Result<SocketAddr, String> {
    let canonical_id = canonical_channel_id(channel_id);
    let listener_key = if canonical_id.is_empty() {
      channel_id.trim().to_string()
    } else {
      canonical_id
    };

    if let Some(existing) = self
      .consumer_tcp_listeners
      .lock()
      .await
      .get(&listener_key)
      .map(|l| l.local_addr)
    {
      eprintln!(
        "[P2pForwarder] start_consumer_listener reuse role={:?} channel={} local_listener={}",
        self.role, listener_key, existing
      );
      return Ok(existing);
    }

    let listen_addr = bind_addr
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .unwrap_or("127.0.0.1:0");

    let listener = match TcpListener::bind(listen_addr).await {
      Ok(listener) => listener,
      Err(bind_err) => {
        if !is_addr_in_use_error(&bind_err) {
          return Err(format!("bind {} failed: {}", listen_addr, bind_err));
        }

        let base_addrs = resolve_bind_base_addrs(listen_addr).await;
        if base_addrs.is_empty() {
          return Err(format!("bind {} failed: {}", listen_addr, bind_err));
        }

        let mut selected_listener: Option<TcpListener> = None;
        'resolve: for base_addr in base_addrs.iter().copied() {
          if base_addr.port() == 0 {
            continue;
          }
          for step in 1..=CONSUMER_LISTENER_PORT_FALLBACK_MAX_STEPS {
            let Some(candidate) = next_port_candidate(base_addr, step) else {
              break;
            };
            match TcpListener::bind(candidate).await {
              Ok(listener) => {
                eprintln!(
                  "[P2pForwarder] start_consumer_listener bind fallback role={:?} channel={} requested={} selected={}",
                  self.role, listener_key, listen_addr, candidate
                );
                selected_listener = Some(listener);
                break 'resolve;
              }
              Err(candidate_err) if is_addr_in_use_error(&candidate_err) => continue,
              Err(candidate_err) => {
                return Err(format!("bind {} failed: {}", candidate, candidate_err));
              }
            }
          }
        }

        if let Some(listener) = selected_listener {
          listener
        } else {
          let preferred_base = base_addrs[0];
          let ephemeral = SocketAddr::new(preferred_base.ip(), 0);
          let fallback_listener = TcpListener::bind(ephemeral)
            .await
            .map_err(|_| format!("bind {} failed: {}", listen_addr, bind_err))?;
          let selected_addr = fallback_listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
          eprintln!(
            "[P2pForwarder] start_consumer_listener bind fallback role={:?} channel={} requested={} selected={}",
            self.role, listener_key, listen_addr, selected_addr
          );
          fallback_listener
        }
      }
    };
    let local_addr = listener.local_addr().map_err(|e| format!("{}", e))?;

    let conn = self.connection.clone();
    let ch_id = listener_key.clone();
    let mut shutdown_rx = self.shutdown_tx.subscribe();

    let task = tokio::spawn(async move {
      loop {
        tokio::select! {
          _ = shutdown_rx.recv() => break,
          result = listener.accept() => {
            match result {
              Ok((tcp_stream, _)) => {
                let conn = conn.clone();
                let ch_id = ch_id.clone();
                tokio::spawn(async move {
                  if let Err(e) = handle_consumer_connection(tcp_stream, conn, &ch_id).await {
                    eprintln!("[P2pForwarder] consumer conn error: {}", e);
                  }
                });
              }
              Err(e) => {
                eprintln!("[P2pForwarder] accept failed: {}", e);
                break;
              }
            }
          }
        }
      }
    });

    self.consumer_tcp_listeners.lock().await.insert(
      listener_key.clone(),
      ConsumerTcpListener { local_addr, task },
    );
    eprintln!(
      "[P2pForwarder] start_consumer_listener role={:?} channel={} local_listener={}",
      self.role, listener_key, local_addr
    );

    Ok(local_addr)
  }

  pub async fn start_consumer_udp_listener(&self, channel_id: &str) -> Result<SocketAddr, String> {
    self
      .start_consumer_udp_listener_with_bind(channel_id, None)
      .await
  }

  pub async fn start_consumer_udp_listener_with_bind(
    &self,
    channel_id: &str,
    bind_addr: Option<&str>,
  ) -> Result<SocketAddr, String> {
    let canonical_id = canonical_channel_id(channel_id);
    let listener_key = if canonical_id.is_empty() {
      channel_id.trim().to_string()
    } else {
      canonical_id
    };

    if let Some(existing) = self
      .consumer_udp_listeners
      .lock()
      .await
      .get(&listener_key)
      .map(|l| l.local_addr)
    {
      eprintln!(
        "[P2pForwarder] start_consumer_udp_listener reuse role={:?} channel={} local_listener={}",
        self.role, listener_key, existing
      );
      return Ok(existing);
    }

    let listen_addr = bind_addr
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .unwrap_or("127.0.0.1:0");

    let socket = match UdpSocket::bind(listen_addr).await {
      Ok(socket) => socket,
      Err(bind_err) => {
        if !is_addr_in_use_error(&bind_err) {
          return Err(format!("bind {} failed: {}", listen_addr, bind_err));
        }

        let base_addrs = resolve_bind_base_addrs(listen_addr).await;
        if base_addrs.is_empty() {
          return Err(format!("bind {} failed: {}", listen_addr, bind_err));
        }

        let mut selected_socket: Option<UdpSocket> = None;
        'resolve: for base_addr in base_addrs.iter().copied() {
          if base_addr.port() == 0 {
            continue;
          }
          for step in 1..=CONSUMER_LISTENER_PORT_FALLBACK_MAX_STEPS {
            let Some(candidate) = next_port_candidate(base_addr, step) else {
              break;
            };
            match UdpSocket::bind(candidate).await {
              Ok(socket) => {
                eprintln!(
                  "[P2pForwarder] start_consumer_udp_listener bind fallback role={:?} channel={} requested={} selected={}",
                  self.role, listener_key, listen_addr, candidate
                );
                selected_socket = Some(socket);
                break 'resolve;
              }
              Err(candidate_err) if is_addr_in_use_error(&candidate_err) => continue,
              Err(candidate_err) => {
                return Err(format!("bind {} failed: {}", candidate, candidate_err));
              }
            }
          }
        }

        if let Some(socket) = selected_socket {
          socket
        } else {
          let preferred_base = base_addrs[0];
          let ephemeral = SocketAddr::new(preferred_base.ip(), 0);
          let fallback_socket = UdpSocket::bind(ephemeral)
            .await
            .map_err(|_| format!("bind {} failed: {}", listen_addr, bind_err))?;
          let selected_addr = fallback_socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
          eprintln!(
            "[P2pForwarder] start_consumer_udp_listener bind fallback role={:?} channel={} requested={} selected={}",
            self.role, listener_key, listen_addr, selected_addr
          );
          fallback_socket
        }
      }
    };

    let local_addr = socket.local_addr().map_err(|e| format!("{}", e))?;
    let socket = Arc::new(socket);
    let socket_for_task = socket.clone();
    let conn = self.connection.clone();
    let ch_id = listener_key.clone();
    let mut shutdown_rx = self.shutdown_tx.subscribe();

    let task = tokio::spawn(async move {
      let mut buf = vec![0u8; 64 * 1024];
      loop {
        tokio::select! {
          _ = shutdown_rx.recv() => break,
          result = socket_for_task.recv_from(&mut buf) => {
            match result {
              Ok((n, peer_addr)) => {
                if n == 0 {
                  continue;
                }

                let peer_addr_text = peer_addr.to_string();
                if let Err(err) = send_udp_frame(&conn, &ch_id, &peer_addr_text, &buf[..n]) {
                  eprintln!(
                    "[P2pForwarder] consumer udp send failed channel={} client={} bytes={} err={}",
                    ch_id,
                    peer_addr_text,
                    n,
                    err
                  );
                  break;
                }
              }
              Err(err) => {
                eprintln!("[P2pForwarder] consumer udp listener recv failed channel={} err={}", ch_id, err);
                break;
              }
            }
          }
        }
      }
    });

    self.consumer_udp_listeners.lock().await.insert(
      listener_key.clone(),
      ConsumerUdpListener {
        local_addr,
        socket,
        task,
      },
    );

    eprintln!(
      "[P2pForwarder] start_consumer_udp_listener role={:?} channel={} local_listener={}",
      self.role, listener_key, local_addr
    );

    Ok(local_addr)
  }

  pub fn is_publisher(&self) -> bool {
    self.role == ForwarderRole::Publisher
  }

  pub fn is_consumer(&self) -> bool {
    self.role == ForwarderRole::Consumer
  }

  pub async fn consumer_addr(&self, channel_id: &str) -> Option<SocketAddr> {
    let canonical_id = canonical_channel_id(channel_id);
    let lookup_key = if canonical_id.is_empty() {
      channel_id.trim().to_string()
    } else {
      canonical_id
    };

    if let Some(addr) = self
      .consumer_tcp_listeners
      .lock()
      .await
      .get(&lookup_key)
      .map(|l| l.local_addr)
    {
      return Some(addr);
    }

    self
      .consumer_udp_listeners
      .lock()
      .await
      .get(&lookup_key)
      .map(|l| l.local_addr)
  }

  pub async fn close(&self) {
    if let Some(task) = self.datagram_task.lock().await.take() {
      task.abort();
    }

    let tcp_listeners = {
      let mut map = self.consumer_tcp_listeners.lock().await;
      map
        .drain()
        .map(|(_, listener)| listener)
        .collect::<Vec<_>>()
    };
    for listener in tcp_listeners {
      listener.task.abort();
    }

    let udp_listeners = {
      let mut map = self.consumer_udp_listeners.lock().await;
      map
        .drain()
        .map(|(_, listener)| listener)
        .collect::<Vec<_>>()
    };
    for listener in udp_listeners {
      listener.task.abort();
    }

    let udp_associations = {
      let mut map = self.publisher_udp_associations.lock().await;
      map.drain().map(|(_, assoc)| assoc).collect::<Vec<_>>()
    };
    for assoc in udp_associations {
      assoc.abort.abort();
    }

    let _ = self.shutdown_tx.send(());
    self.connection.close(0u32.into(), b"closed");
  }
}

async fn resolve_route_for_channel(
  routes: Arc<Mutex<HashMap<String, ChannelRoute>>>,
  channel_id: &str,
) -> Option<String> {
  let canonical_id = canonical_channel_id(channel_id);

  let local_addr = {
    let routes = routes.lock().await;
    eprintln!(
      "[P2pForwarder] route lookup channel={} canonical={} routes={}",
      channel_id,
      canonical_id,
      routes.len()
    );
    routes
      .get(channel_id)
      .or_else(|| {
        if canonical_id != channel_id {
          routes.get(&canonical_id)
        } else {
          None
        }
      })
      .map(|r| r.local_addr.clone())
  };

  local_addr
}

async fn handle_publisher_udp_frame(
  frame: UdpFrame,
  connection: &quinn::Connection,
  routes: Arc<Mutex<HashMap<String, ChannelRoute>>>,
  publisher_udp_associations: Arc<Mutex<HashMap<String, PublisherUdpAssociation>>>,
  publisher_udp_assoc_counter: Arc<AtomicU64>,
  shutdown_tx: tokio::sync::broadcast::Sender<()>,
) -> Result<(), String> {
  if frame.payload.is_empty() {
    return Ok(());
  }

  let local_addr = resolve_route_for_channel(routes, &frame.channel_id)
    .await
    .ok_or_else(|| format!("no route for channel {}", frame.channel_id))?;

  let canonical_id = canonical_channel_id(&frame.channel_id);
  let route_key = if canonical_id.is_empty() {
    frame.channel_id.clone()
  } else {
    canonical_id
  };
  let assoc_key = publisher_assoc_key(&route_key, &frame.peer_client_addr);

  let mut stale_abort: Option<tokio::task::AbortHandle> = None;
  let association = {
    let mut associations = publisher_udp_associations.lock().await;
    if let Some(existing) = associations.get(&assoc_key) {
      if existing.target_addr == local_addr {
        Some(existing.clone())
      } else {
        stale_abort = Some(existing.abort.clone());
        associations.remove(&assoc_key);
        None
      }
    } else {
      None
    }
  };

  if let Some(abort) = stale_abort {
    abort.abort();
  }

  let association = if let Some(existing) = association {
    existing
  } else {
    let socket = Arc::new(
      UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind udp association failed: {}", e))?,
    );
    socket.connect(&local_addr).await.map_err(|e| {
      format!(
        "connect udp association target {} failed: {}",
        local_addr, e
      )
    })?;

    let assoc_id = publisher_udp_assoc_counter.fetch_add(1, Ordering::Relaxed);
    let last_active_at_ms = Arc::new(AtomicU64::new(now_millis()));

    let socket_for_task = socket.clone();
    let conn_for_task = connection.clone();
    let channel_id_for_task = frame.channel_id.clone();
    let peer_client_for_task = frame.peer_client_addr.clone();
    let assoc_key_for_task = assoc_key.clone();
    let last_active_for_task = last_active_at_ms.clone();
    let associations_for_task = publisher_udp_associations.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();

    let task = tokio::spawn(async move {
      let mut buf = vec![0u8; 64 * 1024];
      let loop_exit_reason = loop {
        tokio::select! {
          _ = shutdown_rx.recv() => {
            break "shutdown signal".to_string();
          }
          recv_result = timeout(UDP_ASSOC_READ_TIMEOUT, socket_for_task.recv(&mut buf)) => {
            match recv_result {
              Ok(Ok(n)) => {
                if n == 0 {
                  continue;
                }
                last_active_for_task.store(now_millis(), Ordering::Relaxed);
                if let Err(err) = send_udp_frame(
                  &conn_for_task,
                  &channel_id_for_task,
                  &peer_client_for_task,
                  &buf[..n],
                ) {
                  break format!("send udp frame failed: {}", err);
                }
              }
              Ok(Err(err)) => {
                if err.kind() == std::io::ErrorKind::ConnectionRefused {
                  continue;
                }
                break format!("udp recv failed: {}", err);
              }
              Err(_) => {
                let idle_ms = now_millis().saturating_sub(last_active_for_task.load(Ordering::Relaxed));
                if idle_ms >= UDP_ASSOC_IDLE_TIMEOUT.as_millis() as u64 {
                  break format!("idle timeout {}ms", idle_ms);
                }
              }
            }
          }
        }
      };

      let mut associations = associations_for_task.lock().await;
      if let Some(existing) = associations.get(&assoc_key_for_task) {
        if existing.assoc_id == assoc_id {
          associations.remove(&assoc_key_for_task);
        }
      }
      drop(associations);

      eprintln!(
        "[P2pForwarder] publisher udp association closed channel={} client={} target={} reason={}",
        channel_id_for_task,
        peer_client_for_task,
        socket_for_task
          .peer_addr()
          .map(|addr| addr.to_string())
          .unwrap_or_else(|_| "<unknown>".to_string()),
        loop_exit_reason
      );
    });

    let assoc = PublisherUdpAssociation {
      assoc_id,
      target_addr: local_addr.clone(),
      socket,
      last_active_at_ms,
      abort: task.abort_handle(),
    };

    let mut associations = publisher_udp_associations.lock().await;
    if let Some(existing) = associations.get(&assoc_key) {
      task.abort();
      existing.clone()
    } else {
      associations.insert(assoc_key.clone(), assoc.clone());
      assoc
    }
  };

  association
    .last_active_at_ms
    .store(now_millis(), Ordering::Relaxed);

  association.socket.send(&frame.payload).await.map_err(|e| {
    format!(
      "forward udp payload to local target {} failed: {}",
      local_addr, e
    )
  })?;

  Ok(())
}

async fn handle_consumer_udp_frame(
  frame: UdpFrame,
  consumer_udp_listeners: Arc<Mutex<HashMap<String, ConsumerUdpListener>>>,
) -> Result<(), String> {
  if frame.payload.is_empty() {
    return Ok(());
  }

  let target_addr: SocketAddr = frame
    .peer_client_addr
    .parse()
    .map_err(|e| format!("parse consumer peer client addr failed: {}", e))?;

  let canonical_id = canonical_channel_id(&frame.channel_id);
  let listener_key = if canonical_id.is_empty() {
    frame.channel_id.clone()
  } else {
    canonical_id
  };

  let socket = {
    let listeners = consumer_udp_listeners.lock().await;
    listeners
      .get(&listener_key)
      .map(|listener| listener.socket.clone())
  }
  .ok_or_else(|| format!("no udp consumer listener for channel {}", frame.channel_id))?;

  socket
    .send_to(&frame.payload, target_addr)
    .await
    .map_err(|e| {
      format!(
        "forward udp payload to local client {} failed: {}",
        target_addr, e
      )
    })?;

  Ok(())
}

async fn handle_publisher_stream(
  send: quinn::SendStream,
  mut recv: quinn::RecvStream,
  routes: Arc<Mutex<HashMap<String, ChannelRoute>>>,
) -> Result<(), String> {
  let mut len_buf = [0u8; 2];
  recv
    .read_exact(&mut len_buf)
    .await
    .map_err(|e| format!("read header len: {}", e))?;
  let ch_len = u16::from_be_bytes(len_buf) as usize;
  if ch_len > 256 {
    return Err("channel_id too long".into());
  }
  let mut ch_buf = vec![0u8; ch_len];
  recv
    .read_exact(&mut ch_buf)
    .await
    .map_err(|e| format!("read channel_id: {}", e))?;
  let channel_id = String::from_utf8(ch_buf).map_err(|_| "invalid channel_id utf8")?;

  let local_addr = resolve_route_for_channel(routes, &channel_id)
    .await
    .ok_or_else(|| format!("no route for channel {}", channel_id))?;

  let tcp_stream = TcpStream::connect(&local_addr)
    .await
    .map_err(|e| format!("connect to {}: {}", local_addr, e))?;

  bridge_streams(tcp_stream, send, recv).await;
  Ok(())
}

async fn handle_consumer_connection(
  tcp_stream: TcpStream,
  conn: quinn::Connection,
  channel_id: &str,
) -> Result<(), String> {
  let (send, recv) = conn
    .open_bi()
    .await
    .map_err(|e| format!("open_bi: {}", e))?;
  let mut send = send;

  let ch_bytes = channel_id.as_bytes();
  let len_buf = (ch_bytes.len() as u16).to_be_bytes();
  send
    .write_all(&len_buf)
    .await
    .map_err(|e| format!("write header len: {}", e))?;
  send
    .write_all(ch_bytes)
    .await
    .map_err(|e| format!("write channel_id: {}", e))?;

  bridge_streams(tcp_stream, send, recv).await;
  Ok(())
}

async fn bridge_streams(
  tcp_stream: TcpStream,
  mut quic_send: quinn::SendStream,
  mut quic_recv: quinn::RecvStream,
) {
  let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

  let tcp_to_quic = async {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
      match tcp_read.read(&mut buf).await {
        Ok(0) | Err(_) => break,
        Ok(n) => {
          if quic_send.write_all(&buf[..n]).await.is_err() {
            break;
          }
        }
      }
    }
    let _ = quic_send.finish();
  };

  let quic_to_tcp = async {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
      match quic_recv.read(&mut buf).await {
        Ok(None) | Err(_) => break,
        Ok(Some(n)) => {
          if tcp_write.write_all(&buf[..n]).await.is_err() {
            break;
          }
        }
      }
    }
    let _ = tcp_write.shutdown().await;
  };

  tokio::join!(tcp_to_quic, quic_to_tcp);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonical_channel_id_strips_actor_suffix_for_known_roles() {
    assert_eq!(
      canonical_channel_id("tun-1:udp-main:consumer:device-a"),
      "tun-1:udp-main"
    );
    assert_eq!(
      canonical_channel_id("tun-1:udp-main:controller:device-b"),
      "tun-1:udp-main"
    );
    assert_eq!(
      canonical_channel_id("tun-1:udp-main:publisher:device-c"),
      "tun-1:udp-main"
    );
  }

  #[test]
  fn canonical_channel_id_keeps_unknown_or_plain_id() {
    assert_eq!(canonical_channel_id("tun-1:udp-main"), "tun-1:udp-main");
    assert_eq!(
      canonical_channel_id("tun-1:udp-main:custom-role:device-c"),
      "tun-1:udp-main:custom-role:device-c"
    );
    assert_eq!(canonical_channel_id(""), "");
  }

  #[test]
  fn udp_frame_roundtrip_preserves_fields() {
    let payload = vec![1u8, 2, 3, 4, 9];
    let encoded = encode_udp_frame("tun-1:udp-main", "127.0.0.1:30000", &payload)
      .expect("encode should succeed");
    let decoded = decode_udp_frame(&encoded).expect("decode should succeed");
    assert_eq!(decoded.channel_id, "tun-1:udp-main");
    assert_eq!(decoded.peer_client_addr, "127.0.0.1:30000");
    assert_eq!(decoded.payload, payload);
  }

  #[test]
  fn udp_frame_decode_rejects_invalid_payloads() {
    assert!(
      decode_udp_frame(&[]).is_err(),
      "empty payload should be rejected"
    );
    assert!(
      decode_udp_frame(&[9, 0, 0, 0, 0]).is_err(),
      "unsupported frame version should be rejected"
    );

    let truncated = vec![UDP_FRAME_VERSION, 0, 3, 0, 1, b'a'];
    assert!(
      decode_udp_frame(&truncated).is_err(),
      "truncated body should be rejected"
    );
  }

  #[test]
  fn udp_frame_encode_rejects_oversized_channel_or_peer() {
    let oversized = "x".repeat((u16::MAX as usize) + 1);
    assert!(
      encode_udp_frame(&oversized, "127.0.0.1:1", b"").is_err(),
      "oversized channel id should be rejected"
    );
    assert!(
      encode_udp_frame("tun-1:udp-main", &oversized, b"").is_err(),
      "oversized peer addr should be rejected"
    );
  }

  #[tokio::test]
  async fn resolve_route_prefers_exact_then_canonical_match() {
    let routes = Arc::new(Mutex::new(HashMap::new()));
    {
      let mut guard = routes.lock().await;
      guard.insert(
        "tun-1:udp-main".to_string(),
        ChannelRoute {
          local_addr: "127.0.0.1:7001".to_string(),
        },
      );
      guard.insert(
        "tun-1:udp-main:consumer:actor-a".to_string(),
        ChannelRoute {
          local_addr: "127.0.0.1:7002".to_string(),
        },
      );
    }

    let exact = resolve_route_for_channel(routes.clone(), "tun-1:udp-main:consumer:actor-a")
      .await
      .expect("exact route should exist");
    assert_eq!(exact, "127.0.0.1:7002");

    let canonical = resolve_route_for_channel(routes, "tun-1:udp-main:consumer:actor-b")
      .await
      .expect("canonical route should exist");
    assert_eq!(canonical, "127.0.0.1:7001");
  }
}
