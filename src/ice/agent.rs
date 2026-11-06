use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::client::cert_verifier::CaOnlyVerifier;

use super::dataplane::QuicDataPlane;
use super::forwarder::{ForwarderRole, P2pForwarder};
use super::probe;

fn token_brief(token: &str) -> String {
  let prefix: String = token.chars().take(8).collect();
  if token.chars().count() > 8 {
    format!("{}...(len={})", prefix, token.len())
  } else {
    format!("{}(len={})", prefix, token.len())
  }
}

fn ice_probe_log(msg: &str) {
  let line = format!("[ICE][Probe] {}", msg);
  eprintln!("{}", line);
  crate::debug::append_udp_trace_line(&line);
}

const ICE_BURST_HINT_PREFIX: &str = "ice:burst=";
const STANDARD_PUNCH_NEIGHBOR_RADIUS: u16 = 2;
const STANDARD_PUNCH_MIN_WINDOW_MS: u32 = 1_000;
const STANDARD_PUNCH_MIN_ATTEMPTS_CAP: u32 = 24;
const STANDARD_PUNCH_FALLBACK_BURST: usize = 2;
const DEFAULT_QUIC_KEEPALIVE_SECS: u64 = 15;
const DEFAULT_QUIC_IDLE_TIMEOUT_SECS: u64 = 300;
const MIN_QUIC_KEEPALIVE_SECS: u64 = 1;
const MIN_QUIC_IDLE_TIMEOUT_SECS: u64 = 5;
const QUIC_IDLE_TIMEOUT_MARGIN_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum IceState {
  Idle,
  Gathering,
  Punching,
  Connecting,
  Connected,
  Fallback,
  Failed,
  Closed,
}

#[derive(Debug, Clone)]
pub enum IceEvent {
  StateChanged {
    state: IceState,
    error: Option<String>,
  },
  PunchResult {
    ice_session_id: String,
    success: bool,
    peer_addr: Option<String>,
    attempts_sent: u32,
    failure_reason: Option<String>,
  },
  QuicConnected {
    ice_session_id: String,
    connection_id: String,
    local_addr: String,
    peer_addr: String,
    rtt_ms: u32,
  },
}

#[derive(Debug, Clone)]
pub struct IceStateSnapshot {
  pub state: IceState,
  pub ice_session_id: Option<String>,
  pub connection_id: Option<String>,
  pub remote_addr: Option<String>,
  pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IceAgentConfig {
  pub probe_interval: Duration,
  pub probe_count: u32,
  pub client_cert_pem: Vec<u8>,
  pub client_key_pem: Vec<u8>,
  pub ca_cert_pem: Vec<u8>,
  pub quic_keepalive_interval: Duration,
  pub quic_idle_timeout: Duration,
}

impl Default for IceAgentConfig {
  fn default() -> Self {
    Self {
      probe_interval: Duration::from_millis(50),
      probe_count: 7,
      client_cert_pem: Vec::new(),
      client_key_pem: Vec::new(),
      ca_cert_pem: Vec::new(),
      quic_keepalive_interval: Duration::from_secs(DEFAULT_QUIC_KEEPALIVE_SECS),
      quic_idle_timeout: Duration::from_secs(DEFAULT_QUIC_IDLE_TIMEOUT_SECS),
    }
  }
}

struct AgentInner {
  state: IceState,
  ice_session_id: Option<String>,
  udp_socket: Option<Arc<UdpSocket>>,
  probe_task: Option<JoinHandle<()>>,
  punch_task: Option<JoinHandle<()>>,
  quic_endpoint: Option<quinn::Endpoint>,
  dataplane: Option<Arc<QuicDataPlane>>,
  forwarder: Option<Arc<P2pForwarder>>,
}

pub struct IceAgent {
  inner: Arc<Mutex<AgentInner>>,
  config: IceAgentConfig,
  event_tx: tokio::sync::mpsc::UnboundedSender<IceEvent>,
}

impl IceAgent {
  pub fn new(config: IceAgentConfig) -> (Self, tokio::sync::mpsc::UnboundedReceiver<IceEvent>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let agent = Self {
      inner: Arc::new(Mutex::new(AgentInner {
        state: IceState::Idle,
        ice_session_id: None,
        udp_socket: None,
        probe_task: None,
        punch_task: None,
        quic_endpoint: None,
        dataplane: None,
        forwarder: None,
      })),
      config,
      event_tx: tx,
    };
    (agent, rx)
  }

  pub async fn handle_ice_start(
    &self,
    ice_session_id: &str,
    token: &str,
    pwd: &str,
    udp_addr: &str,
    udp_addr_alt: &str,
    gather_timeout_ms: u32,
  ) -> Result<(), String> {
    let mut reuse_socket: Option<Arc<UdpSocket>> = None;
    let mut should_bind_new = false;
    let mut duplicate_start_active = false;
    let mut duplicate_start_ignored_state: Option<IceState> = None;
    {
      let mut inner = self.inner.lock().await;
      if inner.ice_session_id.as_deref() == Some(ice_session_id) {
        if inner.probe_task.is_some() {
          // Drop duplicated ICE_START retransmissions while a probe burst is in-flight.
          duplicate_start_active = true;
        } else if matches!(
          inner.state,
          IceState::Punching
            | IceState::Connecting
            | IceState::Connected
            | IceState::Fallback
            | IceState::Failed
            | IceState::Closed
        ) {
          // Ignore stale ICE_START retransmissions once this sid has progressed
          // beyond gathering. Re-entering gathering here can abort active punch/
          // connect tasks and harm hole-punch success rate.
          duplicate_start_ignored_state = Some(inner.state.clone());
        }
      }

      if !duplicate_start_active && duplicate_start_ignored_state.is_none() {
        inner.state = IceState::Gathering;
        if let Some(task) = inner.probe_task.take() {
          task.abort();
        }
        if let Some(task) = inner.punch_task.take() {
          task.abort();
        }

        if inner.ice_session_id.as_deref() == Some(ice_session_id) {
          if let Some(existing) = inner.udp_socket.as_ref() {
            reuse_socket = Some(existing.clone());
          } else {
            should_bind_new = true;
          }
        } else {
          inner.ice_session_id = Some(ice_session_id.to_string());
          should_bind_new = true;
        }
      }
    }
    if duplicate_start_active {
      ice_probe_log(&format!(
        "ICE_START sid={} duplicated while probing; keep current probe task",
        ice_session_id
      ));
      return Ok(());
    }
    if let Some(state) = duplicate_start_ignored_state {
      ice_probe_log(&format!(
        "ICE_START sid={} duplicated in state={:?}; ignore retransmission",
        ice_session_id, state
      ));
      return Ok(());
    }

    let socket = if let Some(existing) = reuse_socket {
      existing
    } else if should_bind_new {
      let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind udp: {}", e))?;
      let socket = Arc::new(socket);
      let mut inner = self.inner.lock().await;
      inner.udp_socket = Some(socket.clone());
      socket
    } else {
      return Err("no udp socket available for ice start".into());
    };

    let local_bind = socket
      .local_addr()
      .map(|addr| addr.to_string())
      .unwrap_or_else(|e| format!("<local_addr_error:{}>", e));
    ice_probe_log(&format!(
      "ICE_START sid={} token={} bind={} primary_raw={} alt_raw={} gather_timeout_ms={}",
      ice_session_id,
      token_brief(token),
      local_bind,
      udp_addr,
      udp_addr_alt,
      gather_timeout_ms
    ));

    self.emit(IceEvent::StateChanged {
      state: IceState::Gathering,
      error: None,
    });

    let primary = Self::resolve_socket_addr(udp_addr).await.map_err(|e| {
      let err = format!("resolve addr {}: {}", udp_addr, e);
      ice_probe_log(&format!(
        "ICE_START sid={} primary_resolve_failed: {}",
        ice_session_id, err
      ));
      err
    })?;
    let alt = Self::resolve_socket_addr(udp_addr_alt).await.map_err(|e| {
      let err = format!("resolve alt {}: {}", udp_addr_alt, e);
      ice_probe_log(&format!(
        "ICE_START sid={} alt_resolve_failed: {}",
        ice_session_id, err
      ));
      err
    })?;

    ice_probe_log(&format!(
      "ICE_START sid={} resolved primary={} alt={}",
      ice_session_id, primary, alt
    ));

    let interval_ms = self.config.probe_interval.as_millis().max(1) as u32;
    // Keep probe burst in a practical "production" range:
    // - RFC8445 Ta default is 50ms
    // - mainstream ICE stacks commonly cap binding checks near single-digit counts
    // We target a short burst (<= ~2s window) with a hard max to avoid noisy floods.
    let burst_window_ms = gather_timeout_ms.min(2_000).max(interval_ms);
    let adaptive_count = ((burst_window_ms + interval_ms - 1) / interval_ms).clamp(4, 12);
    let probe_count = self.config.probe_count.max(adaptive_count).max(1).min(12);
    ice_probe_log(&format!(
      "ICE_START sid={} probe_config count={} interval_ms={} (base_count={} gather_timeout_ms={})",
      ice_session_id, probe_count, interval_ms, self.config.probe_count, gather_timeout_ms
    ));

    let probe_cfg = probe::ProbeConfig {
      token: token.to_string(),
      pwd: pwd.to_string(),
      primary_addr: primary,
      alt_addr: alt,
      count: probe_count,
      interval: self.config.probe_interval,
    };
    let sid = ice_session_id.to_string();
    let probe_socket = socket.clone();
    let handle = tokio::spawn(async move {
      probe::send_probes(&probe_socket, &probe_cfg).await;
      ice_probe_log(&format!("ICE_START sid={} async probe burst done", sid));
    });

    let mut inner = self.inner.lock().await;
    inner.probe_task = Some(handle);
    Ok(())
  }

  async fn resolve_socket_addr(raw: &str) -> Result<SocketAddr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
      return Err("empty address".into());
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
      return Ok(addr);
    }

    let mut candidates = lookup_host(trimmed)
      .await
      .map_err(|e| format!("dns lookup failed: {}", e))?;
    if let Some(v4) = candidates.find(|addr| addr.is_ipv4()) {
      return Ok(v4);
    }

    lookup_host(trimmed)
      .await
      .map_err(|e| format!("dns lookup failed: {}", e))?
      .next()
      .ok_or_else(|| "no socket addresses resolved".to_string())
  }

  fn with_port_delta(addr: SocketAddr, delta: i32) -> Option<SocketAddr> {
    let base = i32::from(addr.port());
    let next = base + delta;
    if !(1..=i32::from(u16::MAX)).contains(&next) {
      return None;
    }
    Some(SocketAddr::new(addr.ip(), next as u16))
  }

  pub async fn handle_ice_punch(
    &self,
    ice_session_id: &str,
    target_addr: &str,
    token: &str,
    pwd: &str,
    attempts: u32,
    interval_ms: u32,
    start_delay_ms: u32,
    extra_target_addrs: Vec<String>,
  ) -> Result<(), String> {
    let mut inner = self.inner.lock().await;
    if inner.ice_session_id.as_deref() != Some(ice_session_id) {
      ice_probe_log(&format!(
        "ICE_PUNCH sid={} dropped: current_sid={:?}",
        ice_session_id, inner.ice_session_id
      ));
      return Ok(());
    }
    inner.state = IceState::Punching;
    if let Some(task) = inner.probe_task.take() {
      task.abort();
    }
    if let Some(task) = inner.punch_task.take() {
      task.abort();
    }
    let socket = inner.udp_socket.clone();
    drop(inner);

    self.emit(IceEvent::StateChanged {
      state: IceState::Punching,
      error: None,
    });

    let target: SocketAddr = target_addr
      .parse()
      .map_err(|e| format!("parse target: {}", e))?;
    let socket = socket.ok_or("no udp socket bound")?;

    let mut extra_targets: Vec<SocketAddr> = Vec::new();
    let mut burst_per_attempt: usize = 1;
    let mut burst_hint_seen = false;
    for addr_str in &extra_target_addrs {
      if let Some(raw) = addr_str.strip_prefix(ICE_BURST_HINT_PREFIX) {
        burst_hint_seen = true;
        if let Ok(value) = raw.trim().parse::<usize>() {
          burst_per_attempt = value.clamp(1, 4);
        }
        continue;
      }
      if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        extra_targets.push(addr);
      }
    }
    if extra_targets.is_empty() {
      for step in 1..=STANDARD_PUNCH_NEIGHBOR_RADIUS {
        if let Some(addr) = Self::with_port_delta(target, i32::from(step)) {
          if addr != target && !extra_targets.contains(&addr) {
            extra_targets.push(addr);
          }
        }
        if let Some(addr) = Self::with_port_delta(target, -i32::from(step)) {
          if addr != target && !extra_targets.contains(&addr) {
            extra_targets.push(addr);
          }
        }
      }
      if !extra_targets.is_empty() && burst_per_attempt < STANDARD_PUNCH_FALLBACK_BURST {
        burst_per_attempt = STANDARD_PUNCH_FALLBACK_BURST;
      }
    }
    let safe_interval_ms = interval_ms.max(1);
    let min_attempts = ((STANDARD_PUNCH_MIN_WINDOW_MS + safe_interval_ms - 1) / safe_interval_ms)
      .clamp(10, STANDARD_PUNCH_MIN_ATTEMPTS_CAP);
    let effective_attempts = attempts.max(min_attempts);

    let local_bind = socket
      .local_addr()
      .map(|addr| addr.to_string())
      .unwrap_or_else(|e| format!("<local_addr_error:{}>", e));
    ice_probe_log(&format!(
      "ICE_PUNCH token={} bind={} target={} extras={:?} attempts={} effective_attempts={} interval_ms={} start_delay_ms={} burst_per_attempt={} burst_hint_seen={}",
      token_brief(token),
      local_bind,
      target,
      extra_targets,
      attempts,
      effective_attempts,
      interval_ms,
      start_delay_ms,
      burst_per_attempt,
      burst_hint_seen
    ));

    let punch_cfg = probe::PunchConfig {
      token: token.to_string(),
      pwd: pwd.to_string(),
      target_addr: target,
      extra_targets,
      attempts: effective_attempts,
      interval: Duration::from_millis(interval_ms as u64),
      burst_per_attempt,
    };

    let event_tx = self.event_tx.clone();
    let sid = ice_session_id.to_string();
    let handle = tokio::spawn(async move {
      if start_delay_ms > 0 {
        time::sleep(Duration::from_millis(start_delay_ms as u64)).await;
      }
      let result = probe::send_punch(&socket, &punch_cfg).await;
      let _ = event_tx.send(IceEvent::PunchResult {
        ice_session_id: sid,
        success: result.success,
        peer_addr: result.peer_observed_addr.clone(),
        attempts_sent: result.attempts_sent,
        failure_reason: result.failure_reason.clone(),
      });
    });
    let mut inner = self.inner.lock().await;
    inner.punch_task = Some(handle);
    Ok(())
  }

  pub async fn handle_ice_quic_start(
    &self,
    ice_session_id: &str,
    role: u8,
    peer_addr: &str,
    alpn: &str,
    connect_timeout_ms: u32,
  ) -> Result<(), String> {
    let mut inner = self.inner.lock().await;
    if inner.ice_session_id.as_deref() != Some(ice_session_id) {
      ice_probe_log(&format!(
        "ICE_QUIC_START sid={} dropped: current_sid={:?}",
        ice_session_id, inner.ice_session_id
      ));
      return Ok(());
    }
    inner.state = IceState::Connecting;
    if let Some(task) = inner.probe_task.take() {
      task.abort();
    }
    if let Some(task) = inner.punch_task.take() {
      task.abort();
    }
    let socket = inner.udp_socket.take();
    let prev_forwarder = inner.forwarder.take();
    let prev_dataplane = inner.dataplane.take();
    let prev_endpoint = inner.quic_endpoint.take();
    drop(inner);

    if let Some(forwarder) = prev_forwarder {
      forwarder.close().await;
    }
    if let Some(dataplane) = prev_dataplane {
      dataplane.close().await;
    }
    if let Some(endpoint) = prev_endpoint {
      endpoint.close(0u32.into(), b"replaced");
    }

    self.emit(IceEvent::StateChanged {
      state: IceState::Connecting,
      error: None,
    });

    let socket = socket.ok_or("no udp socket bound")?;
    let local_addr = socket
      .local_addr()
      .map_err(|e| format!("local_addr: {}", e))?;
    let mut shared_socket = socket;
    let mut owned_socket_opt: Option<UdpSocket> = None;
    let mut last_refs = Arc::strong_count(&shared_socket);
    let wait_budget_ms = u64::from(connect_timeout_ms).min(2_000).max(300);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_budget_ms);
    while tokio::time::Instant::now() < deadline {
      match Arc::try_unwrap(shared_socket) {
        Ok(owned) => {
          owned_socket_opt = Some(owned);
          break;
        }
        Err(still_shared) => {
          last_refs = Arc::strong_count(&still_shared);
          shared_socket = still_shared;
          if last_refs > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
          }
        }
      }
    }
    let owned_socket =
      owned_socket_opt.ok_or_else(|| format!("udp socket still shared (refs={})", last_refs))?;
    let std_socket = owned_socket
      .into_std()
      .map_err(|e| format!("into_std: {}", e))?;

    let peer: SocketAddr = peer_addr
      .parse()
      .map_err(|e| format!("parse peer: {}", e))?;
    let timeout = Duration::from_millis(connect_timeout_ms as u64);

    let is_server = role == 0;
    let endpoint = self
      .build_endpoint(std_socket, is_server, alpn)
      .map_err(|e| format!("build endpoint: {}", e))?;

    let connection = if is_server {
      self.accept_connection(&endpoint, timeout).await?
    } else {
      self.connect_to_peer(&endpoint, peer, alpn, timeout).await?
    };

    let rtt_ms = connection.rtt().as_millis() as u32;
    let conn_id = format!("{:x}", connection.stable_id());
    let remote = connection.remote_address();

    let fwd_role = if is_server {
      ForwarderRole::Publisher
    } else {
      ForwarderRole::Consumer
    };
    let forwarder = Arc::new(P2pForwarder::new(connection.clone(), fwd_role));
    forwarder.start_datagram_accept().await;
    if is_server {
      forwarder.start_publisher_accept();
    }

    let mut inner = self.inner.lock().await;
    inner.state = IceState::Connected;
    inner.quic_endpoint = Some(endpoint);
    let conn_for_monitor = connection.clone();
    inner.dataplane = Some(Arc::new(QuicDataPlane::new(connection)));
    inner.forwarder = Some(forwarder);
    drop(inner);

    self.emit(IceEvent::QuicConnected {
      ice_session_id: ice_session_id.to_string(),
      connection_id: conn_id.clone(),
      local_addr: local_addr.to_string(),
      peer_addr: remote.to_string(),
      rtt_ms,
    });

    let inner_for_monitor = self.inner.clone();
    let event_tx = self.event_tx.clone();
    let monitor_connection_id = conn_id;
    tokio::spawn(async move {
      let err = conn_for_monitor.closed().await;
      let mut inner = inner_for_monitor.lock().await;
      let current_connection_id = inner
        .dataplane
        .as_ref()
        .map(|dp| dp.connection_id())
        .unwrap_or_default();
      if inner.state == IceState::Connected && current_connection_id == monitor_connection_id {
        inner.state = IceState::Fallback;
        drop(inner);
        let _ = event_tx.send(IceEvent::StateChanged {
          state: IceState::Fallback,
          error: Some(format!("quic connection lost: {}", err)),
        });
      } else if !current_connection_id.is_empty() && current_connection_id != monitor_connection_id
      {
        ice_probe_log(&format!(
          "ICE monitor stale close ignored: closed_conn_id={} current_conn_id={}",
          monitor_connection_id, current_connection_id
        ));
      }
    });

    Ok(())
  }

  fn build_endpoint(
    &self,
    socket: std::net::UdpSocket,
    is_server: bool,
    alpn: &str,
  ) -> Result<quinn::Endpoint, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = rustls_pemfile::certs(&mut &self.config.client_cert_pem[..])
      .filter_map(|r| r.ok())
      .collect::<Vec<CertificateDer<'static>>>();
    if certs.is_empty() {
      return Err("no client certificate found".into());
    }

    let key = rustls_pemfile::private_key(&mut &self.config.client_key_pem[..])
      .map_err(|e| format!("parse key: {}", e))?
      .ok_or("no private key found")?;

    let mut ca_certs = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &self.config.ca_cert_pem[..]) {
      if let Ok(c) = cert {
        let _ = ca_certs.add(c);
      }
    }

    let alpn_bytes = vec![alpn.as_bytes().to_vec()];

    if is_server {
      let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(
          rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_certs.clone()))
            .build()
            .map_err(|e| format!("client verifier: {}", e))?,
        )
        .with_single_cert(certs.clone(), PrivateKeyDer::from(key.clone_key()))
        .map_err(|e| format!("server cert: {}", e))?;
      server_crypto.alpn_protocols = alpn_bytes.clone();

      let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
          .map_err(|e| format!("quic server config: {}", e))?,
      ));
      server_config.transport_config(Arc::new(self.transport_config()));

      let verifier = CaOnlyVerifier::new_allow_invalid_purpose(Arc::new(ca_certs))
        .map_err(|e| format!("p2p verifier: {}", e))?;
      let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, PrivateKeyDer::from(key))
        .map_err(|e| format!("client auth cert: {}", e))?;
      client_crypto.alpn_protocols = alpn_bytes;

      let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
          .map_err(|e| format!("quic client config: {}", e))?,
      ));
      client_config.transport_config(Arc::new(self.transport_config()));

      let runtime = quinn::default_runtime().ok_or("no async runtime")?;
      let mut ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        runtime
          .wrap_udp_socket(socket)
          .map_err(|e| format!("wrap socket: {}", e))?,
        runtime,
      )
      .map_err(|e| format!("endpoint: {}", e))?;
      ep.set_default_client_config(client_config);
      Ok(ep)
    } else {
      let verifier = CaOnlyVerifier::new_allow_invalid_purpose(Arc::new(ca_certs))
        .map_err(|e| format!("p2p verifier: {}", e))?;
      let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, PrivateKeyDer::from(key))
        .map_err(|e| format!("client auth cert: {}", e))?;
      client_crypto.alpn_protocols = alpn_bytes;

      let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
          .map_err(|e| format!("quic client config: {}", e))?,
      ));
      client_config.transport_config(Arc::new(self.transport_config()));

      let runtime = quinn::default_runtime().ok_or("no async runtime")?;
      let mut ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        runtime
          .wrap_udp_socket(socket)
          .map_err(|e| format!("wrap socket: {}", e))?,
        runtime,
      )
      .map_err(|e| format!("endpoint: {}", e))?;
      ep.set_default_client_config(client_config);
      Ok(ep)
    }
  }

  fn transport_config(&self) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    let keepalive = self
      .config
      .quic_keepalive_interval
      .max(Duration::from_secs(MIN_QUIC_KEEPALIVE_SECS));
    let min_idle = keepalive.saturating_add(Duration::from_secs(QUIC_IDLE_TIMEOUT_MARGIN_SECS));
    let idle = self
      .config
      .quic_idle_timeout
      .max(Duration::from_secs(MIN_QUIC_IDLE_TIMEOUT_SECS))
      .max(min_idle);
    let idle_timeout = quinn::IdleTimeout::try_from(idle)
      .or_else(|_| {
        quinn::IdleTimeout::try_from(Duration::from_secs(DEFAULT_QUIC_IDLE_TIMEOUT_SECS))
      })
      .expect("default QUIC idle timeout should fit quinn::IdleTimeout");
    config.max_idle_timeout(Some(idle_timeout));
    config.keep_alive_interval(Some(keepalive));
    config
  }

  async fn connect_to_peer(
    &self,
    endpoint: &quinn::Endpoint,
    peer: SocketAddr,
    _alpn: &str,
    timeout: Duration,
  ) -> Result<quinn::Connection, String> {
    let connecting = endpoint
      .connect(peer, "yat-p2p")
      .map_err(|e| format!("connect: {}", e))?;

    match time::timeout(timeout, connecting).await {
      Ok(Ok(conn)) => Ok(conn),
      Ok(Err(e)) => Err(format!("quic connect failed: {}", e)),
      Err(_) => Err("quic connect timeout".into()),
    }
  }

  async fn accept_connection(
    &self,
    endpoint: &quinn::Endpoint,
    timeout: Duration,
  ) -> Result<quinn::Connection, String> {
    let incoming = time::timeout(timeout, endpoint.accept())
      .await
      .map_err(|_| "accept timeout".to_string())?
      .ok_or("endpoint closed")?;

    let connection = time::timeout(
      timeout,
      incoming
        .accept()
        .map_err(|e| format!("accept error: {}", e))?,
    )
    .await
    .map_err(|_| "connection handshake timeout".to_string())?
    .map_err(|e| format!("handshake failed: {}", e))?;

    Ok(connection)
  }

  pub async fn handle_ice_state_change(&self, state_str: &str, error: Option<String>) {
    let new_state = match state_str {
      "fallback" => IceState::Fallback,
      "failed" => IceState::Failed,
      "connected" => IceState::Connected,
      "closed" => IceState::Closed,
      _ => return,
    };
    let mut inner = self.inner.lock().await;
    inner.state = new_state.clone();
    drop(inner);
    self.emit(IceEvent::StateChanged {
      state: new_state,
      error,
    });
  }

  pub async fn close(&self) {
    let mut inner = self.inner.lock().await;
    inner.state = IceState::Closed;
    if let Some(task) = inner.probe_task.take() {
      task.abort();
    }
    if let Some(task) = inner.punch_task.take() {
      task.abort();
    }
    if let Some(fwd) = inner.forwarder.take() {
      fwd.close().await;
    }
    if let Some(dp) = inner.dataplane.take() {
      dp.close().await;
    }
    if let Some(ep) = inner.quic_endpoint.take() {
      ep.close(0u32.into(), b"closed");
    }
    inner.udp_socket = None;
    inner.ice_session_id = None;
  }

  pub async fn forwarder(&self) -> Option<Arc<P2pForwarder>> {
    self.inner.lock().await.forwarder.clone()
  }

  pub async fn snapshot(&self) -> IceStateSnapshot {
    let inner = self.inner.lock().await;
    let (connection_id, remote_addr, rtt_ms) = if let Some(dp) = &inner.dataplane {
      (
        Some(dp.connection_id()),
        Some(dp.remote_address()),
        Some(dp.rtt_ms()),
      )
    } else {
      (None, None, None)
    };
    IceStateSnapshot {
      state: inner.state.clone(),
      ice_session_id: inner.ice_session_id.clone(),
      connection_id,
      remote_addr,
      rtt_ms,
    }
  }

  fn emit(&self, event: IceEvent) {
    let _ = self.event_tx.send(event);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn duplicate_ice_start_during_punching_is_ignored() {
    let (agent, _rx) = IceAgent::new(IceAgentConfig::default());
    let sid = "ice:test:dup-start";
    let token = "0123456789abcdef0123456789abcdef";
    let pwd = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let udp = "127.0.0.1:3478";

    agent
      .handle_ice_start(sid, token, pwd, udp, udp, 5_000)
      .await
      .expect("first ice_start should succeed");
    {
      let mut inner = agent.inner.lock().await;
      if let Some(task) = inner.probe_task.take() {
        task.abort();
      }
      inner.state = IceState::Punching;
    }

    agent
      .handle_ice_start(sid, token, pwd, udp, udp, 5_000)
      .await
      .expect("duplicated ice_start should be ignored in punching");

    let snap = agent.snapshot().await;
    assert_eq!(snap.state, IceState::Punching);
  }
}
