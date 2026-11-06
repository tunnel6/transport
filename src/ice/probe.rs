use ring::hmac;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration, Instant};

// UDP packet wire format (matches edge/internal/channel/ice/udp_listener.go):
//   magic(4) | type(1) | ufrag(32) | hmac(32) = 69 bytes
// hmac = HMAC-SHA256(hex_decode(ice_pwd), magic || type || ufrag)
const UDP_MAGIC: u32 = 0x59415450; // "YATP"
const UDP_PACKET_LEN: usize = 69;
const UFRAG_LEN: usize = 32;
const MAC_LEN: usize = 32;

const PKT_PROBE: u8 = 0x01;
const PKT_PROBE_ALT: u8 = 0x02;
const PKT_PUNCH: u8 = 0x03;
const PKT_FILTER_CHALLENGE: u8 = 0x05;
const PKT_FILTER_ACK: u8 = 0x06;

fn token_brief(token: &str) -> String {
  let prefix: String = token.chars().take(8).collect();
  if token.chars().count() > 8 {
    format!("{}...(len={})", prefix, token.len())
  } else {
    format!("{}(len={})", prefix, token.len())
  }
}

fn probe_log(msg: &str) {
  let line = format!("[ICE][Probe] {}", msg);
  eprintln!("{}", line);
  crate::debug::append_udp_trace_line(&line);
}

fn should_log_probe_attempt(attempt_idx: u32, total: u32) -> bool {
  if total <= 6 {
    return true;
  }
  let attempt = attempt_idx + 1;
  attempt <= 3 || attempt == total || attempt % 5 == 0
}

fn hex_decode(s: &str) -> Vec<u8> {
  let b = s.as_bytes();
  if b.len() % 2 != 0 {
    return s.as_bytes().to_vec();
  }
  let mut out = Vec::with_capacity(b.len() / 2);
  let mut i = 0;
  while i < b.len() {
    let hi = match (b[i] as char).to_digit(16) {
      Some(v) => v as u8,
      None => return s.as_bytes().to_vec(),
    };
    let lo = match (b[i + 1] as char).to_digit(16) {
      Some(v) => v as u8,
      None => return s.as_bytes().to_vec(),
    };
    out.push((hi << 4) | lo);
    i += 2;
  }
  out
}
fn pack_header(pkt_type: u8) -> [u8; 5] {
  let mut hdr = [0u8; 5];
  hdr[0..4].copy_from_slice(&UDP_MAGIC.to_be_bytes());
  hdr[4] = pkt_type;
  hdr
}

fn ufrag_padded(token: &str) -> [u8; UFRAG_LEN] {
  let bytes = token.as_bytes();
  let mut out = [b' '; UFRAG_LEN];
  let take = bytes.len().min(UFRAG_LEN);
  out[..take].copy_from_slice(&bytes[..take]);
  out
}

fn compute_mac(pwd: &str, pkt_type: u8, ufrag: &[u8; UFRAG_LEN]) -> [u8; MAC_LEN] {
  let key_bytes = hex_decode(pwd);
  let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
  let mut ctx = hmac::Context::with_key(&key);
  ctx.update(&pack_header(pkt_type));
  ctx.update(ufrag);
  let tag = ctx.sign();
  let mut out = [0u8; MAC_LEN];
  out.copy_from_slice(tag.as_ref());
  out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  // Avoid early-exit branches: reduce all byte diffs into one accumulator.
  let mut diff = 0u8;
  for (&x, &y) in a.iter().zip(b.iter()) {
    diff |= x ^ y;
  }
  diff == 0
}

fn build_packet(pkt_type: u8, token: &str, pwd: &str) -> [u8; UDP_PACKET_LEN] {
  let mut pkt = [0u8; UDP_PACKET_LEN];
  pkt[0..4].copy_from_slice(&UDP_MAGIC.to_be_bytes());
  pkt[4] = pkt_type;
  let uf = ufrag_padded(token);
  pkt[5..37].copy_from_slice(&uf);
  let mac = compute_mac(pwd, pkt_type, &uf);
  pkt[37..69].copy_from_slice(&mac);
  pkt
}

pub struct ProbeConfig {
  pub token: String,
  pub pwd: String,
  pub primary_addr: SocketAddr,
  pub alt_addr: SocketAddr,
  pub count: u32,
  pub interval: Duration,
}

pub struct PunchConfig {
  pub token: String,
  pub pwd: String,
  pub target_addr: SocketAddr,
  pub extra_targets: Vec<SocketAddr>,
  pub attempts: u32,
  pub interval: Duration,
  pub burst_per_attempt: usize,
}

pub struct PunchResult {
  pub success: bool,
  pub peer_observed_addr: Option<String>,
  pub failure_reason: Option<String>,
  pub attempts_sent: u32,
}
// __PROBE_TAIL__

pub async fn send_probes(socket: &UdpSocket, cfg: &ProbeConfig) {
  let pkt_primary = build_packet(PKT_PROBE, &cfg.token, &cfg.pwd);
  let pkt_alt = build_packet(PKT_PROBE_ALT, &cfg.token, &cfg.pwd);
  let local_bind = socket
    .local_addr()
    .map(|addr| addr.to_string())
    .unwrap_or_else(|e| format!("<local_addr_error:{}>", e));

  probe_log(&format!(
    "send_probes start token={} bind={} primary={} alt={} count={} interval_ms={}",
    token_brief(&cfg.token),
    local_bind,
    cfg.primary_addr,
    cfg.alt_addr,
    cfg.count,
    cfg.interval.as_millis()
  ));

  for i in 0..cfg.count {
    match socket.send_to(&pkt_primary, cfg.primary_addr).await {
      Ok(n) => {
        if should_log_probe_attempt(i, cfg.count) {
          probe_log(&format!(
            "send_probes attempt={}/{} type=primary target={} bytes={}",
            i + 1,
            cfg.count,
            cfg.primary_addr,
            n
          ));
        }
      }
      Err(err) => probe_log(&format!(
        "send_probes attempt={}/{} type=primary target={} send_failed={}",
        i + 1,
        cfg.count,
        cfg.primary_addr,
        err
      )),
    }
    match socket.send_to(&pkt_alt, cfg.alt_addr).await {
      Ok(n) => {
        if should_log_probe_attempt(i, cfg.count) {
          probe_log(&format!(
            "send_probes attempt={}/{} type=alt target={} bytes={}",
            i + 1,
            cfg.count,
            cfg.alt_addr,
            n
          ));
        }
      }
      Err(err) => probe_log(&format!(
        "send_probes attempt={}/{} type=alt target={} send_failed={}",
        i + 1,
        cfg.count,
        cfg.alt_addr,
        err
      )),
    }
    respond_filter_challenges(socket, &cfg.token, &cfg.pwd, Duration::from_millis(12)).await;
    if i < cfg.count - 1 {
      time::sleep(cfg.interval).await;
    }
  }

  // Keep a short tail window so the edge can run non-blocking NAT2/NAT3
  // filter checks right after probe bursts without delaying the ICE flow.
  respond_filter_challenges(socket, &cfg.token, &cfg.pwd, Duration::from_millis(120)).await;

  probe_log("send_probes done");
}

async fn respond_filter_challenges(socket: &UdpSocket, token: &str, pwd: &str, window: Duration) {
  let deadline = Instant::now() + window;
  let mut buf = [0u8; 256];
  let token_padded = ufrag_padded(token);
  while Instant::now() < deadline {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
      break;
    }
    let slot = remaining.min(Duration::from_millis(20));
    let recv = time::timeout(slot, socket.recv_from(&mut buf)).await;
    let (n, from) = match recv {
      Ok(Ok(v)) => v,
      Ok(Err(_)) => break,
      Err(_) => break,
    };
    if n < UDP_PACKET_LEN {
      continue;
    }
    if u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) != UDP_MAGIC {
      continue;
    }
    let pkt_type = buf[4];
    if pkt_type != PKT_FILTER_CHALLENGE {
      continue;
    }
    let mut incoming_ufrag = [0u8; UFRAG_LEN];
    incoming_ufrag.copy_from_slice(&buf[5..37]);
    if incoming_ufrag != token_padded {
      continue;
    }
    let received = &buf[37..69];
    let expected = compute_mac(pwd, PKT_FILTER_CHALLENGE, &incoming_ufrag);
    if !constant_time_eq(received, &expected) {
      continue;
    }

    let ack = build_packet(PKT_FILTER_ACK, token, pwd);
    if let Err(err) = socket.send_to(&ack, from).await {
      probe_log(&format!(
        "filter_challenge ack send_failed token={} to={} err={}",
        token_brief(token),
        from,
        err
      ));
      continue;
    }
    probe_log(&format!(
      "filter_challenge ack sent token={} to={}",
      token_brief(token),
      from
    ));
  }
}

fn verify_inbound(buf: &[u8], pwd: &str) -> Option<u8> {
  if buf.len() < UDP_PACKET_LEN {
    return None;
  }
  let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
  if magic != UDP_MAGIC {
    return None;
  }
  let pkt_type = buf[4];
  let mut ufrag = [0u8; UFRAG_LEN];
  ufrag.copy_from_slice(&buf[5..37]);
  let received = &buf[37..69];
  let expected = compute_mac(pwd, pkt_type, &ufrag);
  // constant-time compare to avoid timing-based oracle.
  if constant_time_eq(received, &expected) {
    return Some(pkt_type);
  }
  None
}

pub async fn send_punch(socket: &UdpSocket, cfg: &PunchConfig) -> PunchResult {
  let pkt = build_packet(PKT_PUNCH, &cfg.token, &cfg.pwd);
  let mut buf = [0u8; 128];
  let mut attempts_sent = 0u32;

  let mut all_targets = vec![cfg.target_addr];
  all_targets.extend_from_slice(&cfg.extra_targets);
  let burst_per_attempt = cfg
    .burst_per_attempt
    .clamp(1usize, all_targets.len().max(1));
  let local_bind = socket
    .local_addr()
    .map(|addr| addr.to_string())
    .unwrap_or_else(|e| format!("<local_addr_error:{}>", e));

  probe_log(&format!(
    "send_punch start token={} bind={} targets={:?} attempts={} interval_ms={} burst_per_attempt={}",
    token_brief(&cfg.token),
    local_bind,
    all_targets,
    cfg.attempts,
    cfg.interval.as_millis(),
    burst_per_attempt
  ));

  for i in 0..cfg.attempts {
    // Round-robin in small batches to balance hit-rate and packet budget.
    for b in 0..burst_per_attempt {
      let target_idx = (i as usize * burst_per_attempt + b) % all_targets.len();
      let target = all_targets[target_idx];
      match socket.send_to(&pkt, target).await {
        Ok(n) => probe_log(&format!(
          "send_punch attempt={}/{} batch={}/{} target={} bytes={}",
          i + 1,
          cfg.attempts,
          b + 1,
          burst_per_attempt,
          target,
          n
        )),
        Err(err) => probe_log(&format!(
          "send_punch attempt={}/{} batch={}/{} target={} send_failed={}",
          i + 1,
          cfg.attempts,
          b + 1,
          burst_per_attempt,
          target,
          err
        )),
      }
      attempts_sent += 1;
    }

    let recv = time::timeout(cfg.interval, socket.recv_from(&mut buf)).await;
    if let Ok(Ok((n, from))) = recv {
      if let Some(pkt_type) = verify_inbound(&buf[..n], &cfg.pwd) {
        if pkt_type != PKT_PUNCH {
          probe_log(&format!(
            "send_punch received_authenticated_but_unexpected_type from={} bytes={} type={} attempt={}/{}",
            from,
            n,
            pkt_type,
            i + 1,
            cfg.attempts
          ));
          continue;
        }
        if !all_targets.iter().any(|target| *target == from) {
          probe_log(&format!(
            "send_punch received_authenticated_but_unexpected_source from={} bytes={} attempt={}/{} targets={:?}",
            from,
            n,
            i + 1,
            cfg.attempts,
            all_targets
          ));
          continue;
        }
        probe_log(&format!(
          "send_punch authenticated_response from={} bytes={} attempts_sent={}",
          from, n, attempts_sent
        ));
        return PunchResult {
          success: true,
          peer_observed_addr: Some(from.to_string()),
          failure_reason: None,
          attempts_sent,
        };
      }
      probe_log(&format!(
        "send_punch received_non_authentic from={} bytes={} attempt={}/{}",
        from,
        n,
        i + 1,
        cfg.attempts
      ));
    } else if let Ok(Err(err)) = recv {
      probe_log(&format!(
        "send_punch recv_failed attempt={}/{} err={}",
        i + 1,
        cfg.attempts,
        err
      ));
    } else {
      probe_log(&format!(
        "send_punch recv_timeout attempt={}/{}",
        i + 1,
        cfg.attempts
      ));
    }
  }

  probe_log(&format!(
    "send_punch failed: no authentic response after {} attempts (sent={})",
    cfg.attempts, attempts_sent
  ));

  PunchResult {
    success: false,
    peer_observed_addr: None,
    failure_reason: Some(format!(
      "no authentic response after {} attempts",
      cfg.attempts
    )),
    attempts_sent,
  }
}
