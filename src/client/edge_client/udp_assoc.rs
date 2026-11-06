use super::*;

/// `UdpAssocOps` 定义 UDP 关联（association）生命周期与转发能力。
///
/// 职责边界：
/// - 全量/按 channel 清理 UDP association；
/// - 处理 UDP DATA_PACKET 收包与本地目标转发；
/// - 按需创建、复用、回收 association。
pub(super) trait UdpAssocOps {
  async fn shutdown_all_udp_associations(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
  );

  async fn shutdown_udp_associations_for_channel(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_id: &str,
  );

  async fn handle_udp_packet(
    packet: crate::protocol::message::DataPacketData,
    channel_info: Option<ChannelInfo>,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) -> Result<()>;
}

impl UdpAssocOps for EdgeClient {
  async fn shutdown_all_udp_associations(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
  ) {
    EdgeClient::shutdown_all_udp_associations(udp_associations).await
  }

  async fn shutdown_udp_associations_for_channel(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_id: &str,
  ) {
    EdgeClient::shutdown_udp_associations_for_channel(udp_associations, channel_id).await
  }

  async fn handle_udp_packet(
    packet: crate::protocol::message::DataPacketData,
    channel_info: Option<ChannelInfo>,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) -> Result<()> {
    EdgeClient::handle_udp_packet(
      packet,
      channel_info,
      writer,
      session_id,
      seq_counter,
      channel_traffic,
      udp_associations,
      channel_connection_event_handler,
    )
    .await
  }
}

impl EdgeClient {
  pub(super) async fn shutdown_all_udp_associations(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
  ) {
    let shutdown_txs = {
      let mut associations = udp_associations.lock().await;
      let txs = associations
        .values()
        .map(|assoc| assoc.shutdown_tx.clone())
        .collect::<Vec<_>>();
      associations.clear();
      txs
    };

    for tx in shutdown_txs {
      let _ = tx.send(()).await;
    }
  }

  pub(super) async fn shutdown_udp_associations_for_channel(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_id: &str,
  ) {
    let shutdown_txs = {
      let mut associations = udp_associations.lock().await;
      let keys = associations
        .iter()
        .filter(|(_, assoc)| assoc.channel_id == channel_id)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

      let mut txs = Vec::with_capacity(keys.len());
      for key in keys {
        if let Some(assoc) = associations.remove(&key) {
          txs.push(assoc.shutdown_tx);
        }
      }
      txs
    };

    for tx in shutdown_txs {
      let _ = tx.send(()).await;
    }
  }

  async fn remove_udp_association(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_id: &str,
    connection_id: &str,
  ) {
    let key = Self::udp_assoc_key(channel_id, connection_id);
    let assoc = {
      let mut associations = udp_associations.lock().await;
      associations.remove(&key)
    };
    if let Some(a) = assoc {
      let _ = a.shutdown_tx.send(()).await;
    }
  }

  pub(super) async fn handle_udp_packet(
    packet: crate::protocol::message::DataPacketData,
    channel_info: Option<ChannelInfo>,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) -> Result<()> {
    if packet.flags & 0x03 != 0 {
      Self::udp_trace(format!(
        "[EdgeClient][UDP] close association: channel_id={}, connection_id={}, flags=0x{:02x}",
        packet.channel_id, packet.connection_id, packet.flags
      ));
      Self::remove_udp_association(udp_associations, &packet.channel_id, &packet.connection_id)
        .await;
      return Ok(());
    }

    if packet.data.is_empty() {
      Self::udp_trace(format!(
        "[EdgeClient][UDP] ignore empty packet: channel_id={}, connection_id={}",
        packet.channel_id, packet.connection_id
      ));
      return Ok(());
    }

    let Some(info) = channel_info else {
      Self::udp_trace(format!(
        "[EdgeClient][UDP] drop packet because channel not found: channel_id={}, connection_id={}, bytes={}",
        packet.channel_id, packet.connection_id, packet.data.len()
      ));
      return Ok(());
    };

    let (assoc, association_created) = Self::ensure_udp_association(
      &packet.channel_id,
      &packet.connection_id,
      &info.local_addr,
      &info.link_type,
      &info.remote_endpoint,
      writer,
      session_id,
      seq_counter,
      channel_traffic,
      udp_associations,
      channel_connection_event_handler.clone(),
    )
    .await?;

    assoc
      .last_active_at_ms
      .store(Self::now_millis(), Ordering::Relaxed);
    if !association_created {
      Self::emit_channel_connection_event(
        &channel_connection_event_handler,
        Self::build_channel_connection_event(
          "activity",
          "udp",
          &packet.channel_id,
          &packet.connection_id,
          &info.local_addr,
          &info.link_type,
          &info.remote_endpoint,
          "udp-inbound",
        ),
      )
      .await;
    }
    if let Err(err) = assoc.socket.send(&packet.data).await {
      Self::udp_trace(format!(
        "[EdgeClient][UDP] failed to forward to local target: channel_id={}, connection_id={}, target_addr={}, local_bind={}, bytes={}, err={}",
        packet.channel_id,
        packet.connection_id,
        info.local_addr,
        assoc
          .socket
          .local_addr()
          .map(|addr| addr.to_string())
          .unwrap_or_else(|_| "<unknown>".to_string()),
        packet.data.len(),
        err
      ));
      return Err(TransportError::Io(err));
    }

    Self::udp_trace(format!(
      "[EdgeClient][UDP] forwarded to local target: channel_id={}, connection_id={}, target_addr={}, bytes={}",
      packet.channel_id,
      packet.connection_id,
      info.local_addr,
      packet.data.len()
    ));

    Ok(())
  }

  async fn ensure_udp_association(
    channel_id: &str,
    connection_id: &str,
    local_addr: &str,
    link_type_hint: &str,
    remote_endpoint: &str,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) -> Result<(UdpAssociation, bool)> {
    let key = Self::udp_assoc_key(channel_id, connection_id);
    let mut stale_assoc_shutdown_tx: Option<mpsc::Sender<()>> = None;

    {
      let mut associations = udp_associations.lock().await;
      if let Some(existing) = associations.get(&key) {
        if existing.target_addr == local_addr {
          Self::udp_trace(format!(
            "[EdgeClient][UDP] reuse association: channel_id={}, connection_id={}, target_addr={}",
            channel_id, connection_id, local_addr
          ));
          return Ok((existing.clone(), false));
        }
      }

      // 同一 connection_id 但目标地址发生变化（常见于隧道重建/端口变更），
      // 旧 socket 会持续发送到历史端口，需要先剔除并重建。
      if let Some(stale_assoc) = associations.remove(&key) {
        Self::udp_trace(format!(
          "[EdgeClient][UDP] rebuild association due to target changed: channel_id={}, connection_id={}, old_target_addr={}, new_target_addr={}",
          channel_id,
          connection_id,
          stale_assoc.target_addr,
          local_addr
        ));
        stale_assoc_shutdown_tx = Some(stale_assoc.shutdown_tx);
      }
    }

    if let Some(tx) = stale_assoc_shutdown_tx {
      let _ = tx.send(()).await;
    }

    let socket = Arc::new(
      UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(TransportError::Io)?,
    );
    socket
      .connect(local_addr)
      .await
      .map_err(TransportError::Io)?;

    let last_active_at_ms = Arc::new(AtomicU64::new(Self::now_millis()));
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let assoc = UdpAssociation {
      assoc_id: UDP_ASSOC_COUNTER.fetch_add(1, Ordering::Relaxed),
      channel_id: channel_id.to_string(),
      connection_id: connection_id.to_string(),
      target_addr: local_addr.to_string(),
      link_type_hint: normalize_link_type(link_type_hint),
      remote_endpoint: remote_endpoint.trim().to_string(),
      socket: socket.clone(),
      last_active_at_ms: last_active_at_ms.clone(),
      shutdown_tx,
    };

    {
      let mut associations = udp_associations.lock().await;
      if let Some(existing) = associations.get(&key) {
        return Ok((existing.clone(), false));
      }
      associations.insert(key.clone(), assoc.clone());
    }

    Self::udp_trace(format!(
      "[EdgeClient][UDP] created association: channel_id={}, connection_id={}, target_addr={}, local_bind={}",
      channel_id,
      connection_id,
      local_addr,
      socket
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
    ));

    let assoc_for_task = assoc.clone();
    let udp_associations_for_task = udp_associations.clone();
    let channel_connection_event_handler_for_task = channel_connection_event_handler.clone();
    tokio::spawn(async move {
      Self::run_udp_association_loop(
        assoc_for_task,
        key,
        shutdown_rx,
        writer,
        session_id,
        seq_counter,
        channel_traffic,
        udp_associations_for_task,
        channel_connection_event_handler_for_task,
      )
      .await;
    });

    Self::emit_channel_connection_event(
      &channel_connection_event_handler,
      Self::build_channel_connection_event(
        "open",
        "udp",
        channel_id,
        connection_id,
        local_addr,
        link_type_hint,
        remote_endpoint,
        "udp-association-created",
      ),
    )
    .await;

    Ok((assoc, true))
  }

  async fn run_udp_association_loop(
    assoc: UdpAssociation,
    assoc_key: String,
    mut shutdown_rx: mpsc::Receiver<()>,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) {
    let mut buf = vec![0u8; 64 * 1024];
    let loop_exit_reason = loop {
      tokio::select! {
        _ = shutdown_rx.recv() => {
          break "shutdown signal".to_string();
        }
        recv_result = tokio::time::timeout(UDP_ASSOC_READ_TIMEOUT, assoc.socket.recv(&mut buf)) => {
          match recv_result {
            Ok(Ok(n)) => {
              if n == 0 {
                continue;
              }

              assoc.last_active_at_ms.store(Self::now_millis(), Ordering::Relaxed);

              Self::udp_trace(format!(
                "[EdgeClient][UDP] local reply captured: channel_id={}, connection_id={}, from_target={}, bytes={}",
                assoc.channel_id,
                assoc.connection_id,
                assoc.target_addr,
                n
              ));

              let sid = session_id.read().await.clone();
              let mut builder = MessageBuilder::new().seq(seq_counter.fetch_add(1, Ordering::SeqCst));
              if let Some(sid_value) = sid {
                builder = builder.session_id(sid_value);
              }

              let packet = builder.data_packet(
                &assoc.channel_id,
                &assoc.connection_id,
                0,
                &buf[..n],
                0,
              );

              let mut writer_guard = writer.lock().await;
              if let Some(w) = writer_guard.as_mut() {
                if write_frame(w, &packet).await.is_err() {
                  Self::udp_trace(format!(
                    "[EdgeClient][UDP] failed to send local reply back to edge: channel_id={}, connection_id={}, bytes={}",
                    assoc.channel_id, assoc.connection_id, n
                  ));
                  break "writer send to edge failed".to_string();
                }
                Self::record_channel_traffic(
                  &channel_traffic,
                  &assoc.channel_id,
                  0,
                  n,
                ).await;
                Self::udp_trace(format!(
                  "[EdgeClient][UDP] sent local reply to edge: channel_id={}, connection_id={}, bytes={}",
                  assoc.channel_id, assoc.connection_id, n
                ));
              } else {
                break "writer is none".to_string();
              }
            }
            Ok(Err(err)) => {
              if err.kind() == std::io::ErrorKind::ConnectionRefused {
                // UDP 目标端口无监听时，connected UDP socket 在 recv 可能返回 ConnectionRefused。
                // 这里不立刻销毁 association，继续等待后续数据，便于排查并减少频繁重建。
                Self::udp_trace(format!(
                  "[EdgeClient][UDP] local recv connection refused: channel_id={}, connection_id={}, target_addr={}, local_bind={}, err={}",
                  assoc.channel_id,
                  assoc.connection_id,
                  assoc.target_addr,
                  assoc
                    .socket
                    .local_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|_| "<unknown>".to_string()),
                  err
                ));
                continue;
              }
              Self::udp_trace(format!(
                "[EdgeClient][UDP] local recv error: channel_id={}, connection_id={}, target_addr={}, err={}",
                assoc.channel_id,
                assoc.connection_id,
                assoc.target_addr,
                err
              ));
              break format!("local recv error: {}", err);
            }
            Err(_) => {
              let idle_ms = Self::now_millis().saturating_sub(assoc.last_active_at_ms.load(Ordering::Relaxed));
              if idle_ms >= UDP_ASSOC_IDLE_TIMEOUT.as_millis() as u64 {
                break format!("idle timeout {}ms", idle_ms);
              }
            }
          }
        }
      }
    };
    Self::udp_trace(format!(
      "[EdgeClient][UDP] association loop exit: channel_id={}, connection_id={}, target_addr={}, reason={}",
      assoc.channel_id,
      assoc.connection_id,
      assoc.target_addr,
      loop_exit_reason
    ));

    let mut associations = udp_associations.lock().await;
    if let Some(existing) = associations.get(&assoc_key) {
      if existing.assoc_id == assoc.assoc_id {
        associations.remove(&assoc_key);
      }
    }
    drop(associations);

    Self::emit_channel_connection_event(
      &channel_connection_event_handler,
      Self::build_channel_connection_event(
        "close",
        "udp",
        &assoc.channel_id,
        &assoc.connection_id,
        &assoc.target_addr,
        &assoc.link_type_hint,
        &assoc.remote_endpoint,
        &loop_exit_reason,
      ),
    )
    .await;
  }
}
