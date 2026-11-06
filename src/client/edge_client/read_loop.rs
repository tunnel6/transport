use super::data_packet::DataPacket;
use super::http::HTTP;
use super::ice::ICE;
use super::*;

/// Internal event type for the read loop's tokio::select! branch.
enum ReadLoopEvent {
  Shutdown,
  Frame(Result<Vec<u8>>),
}

/// `ReadDispatch` 负责 read loop 的通用消息分发能力。
///
/// 职责边界：
/// - 处理轻量 push 通知（日志、事件）；
/// - 处理请求-响应匹配（按 seq / 按类型）；
/// - 提供 fallback 分发，避免未匹配响应丢失。
pub(super) trait ReadDispatch {
  async fn handle_push_notifications(
    msg_type: MessageType,
    data: &[u8],
    log_handler: &Arc<Mutex<Option<LogHandler>>>,
    tunnel_event_handler: &Arc<Mutex<Option<TunnelEventHandler>>>,
    wg_network_event_handler: &Arc<Mutex<Option<WGNetworkEventHandler>>>,
  ) -> bool;

  async fn dispatch_pending_response(
    msg_type: MessageType,
    data: Vec<u8>,
    pending: &PendingRequests,
    pending_type: &PendingTypeRequests,
  ) -> Option<Vec<u8>>;

  async fn dispatch_pending_response_by_fallback_seq(data: Vec<u8>, pending: &PendingRequests);
}

impl ReadDispatch for EdgeClient {
  async fn handle_push_notifications(
    msg_type: MessageType,
    data: &[u8],
    log_handler: &Arc<Mutex<Option<LogHandler>>>,
    tunnel_event_handler: &Arc<Mutex<Option<TunnelEventHandler>>>,
    wg_network_event_handler: &Arc<Mutex<Option<WGNetworkEventHandler>>>,
  ) -> bool {
    if msg_type == MessageType::EDGE_LOG_PUSH {
      if let Ok(push) = MessageReader::parse_edge_log_push(data) {
        let handler = log_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          h(push.log_lines);
        }
      }
      return true;
    }

    if msg_type == MessageType::TUNNEL_EVENT_PUSH {
      if let Ok(event) = MessageReader::parse_tunnel_event_push(data) {
        let handler = tunnel_event_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          h(event);
        }
      }
      return true;
    }

    if msg_type == MessageType::WG_NETWORK_EVENT_PUSH {
      if let Ok(event) = MessageReader::parse_wg_network_event_push(data) {
        let handler = wg_network_event_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          h(event);
        }
      }
      return true;
    }

    false
  }

  async fn dispatch_pending_response(
    msg_type: MessageType,
    mut data: Vec<u8>,
    pending: &PendingRequests,
    pending_type: &PendingTypeRequests,
  ) -> Option<Vec<u8>> {
    // Prefer seq-based dispatch first to avoid head-of-line blocking
    // when same response type requests complete out of order.
    if let Ok(incoming_seq) = MessageReader::get_seq(&data) {
      if incoming_seq != 0 {
        let tx_opt = {
          let mut pending_guard = pending.lock().await;
          pending_guard.remove(&incoming_seq)
        };
        if let Some(tx) = tx_opt {
          if Self::is_tunnel_definition_response_type(msg_type) {
            eprintln!(
              "[ReqFlow] dispatch by seq type={} incoming_seq={}",
              msg_type.0, incoming_seq
            );
          }
          let _ = tx.send(data);
          return None;
        }
        // A late response belongs only to its original request. Falling back
        // by type here would complete a newer request with the wrong payload.
        log::debug!(
          "[ReqFlow] ignored late response type={} seq={}",
          msg_type.0,
          incoming_seq
        );
        return None;
      }
    }

    // Uncorrelated errors are diagnostics only. In particular, a rejected
    // WG_PATH_REQUEST must never fail a concurrent runtime GET. Legacy peers
    // which omit the error sequence cannot safely complete a specific RPC.
    if msg_type == MessageType::ERROR {
      return None;
    }

    // Legacy Edge responses use seq=0. Skip waiters dropped by an outer deadline
    // and entries already completed by their explicit sequence number.
    loop {
      let seq_opt = {
        let mut pending_guard = pending_type.lock().await;
        if let Some(queue) = pending_guard.get_mut(&msg_type.0) {
          let seq = queue.pop_front();
          if queue.is_empty() {
            pending_guard.remove(&msg_type.0);
          }
          seq
        } else {
          None
        }
      };
      let Some(seq) = seq_opt else {
        break;
      };
      if Self::is_tunnel_definition_response_type(msg_type) {
        eprintln!(
          "[ReqFlow] dispatch by type type={} -> pending_seq={} (incoming_seq={:?})",
          msg_type.0,
          seq,
          MessageReader::get_seq(&data).ok()
        );
      }
      let tx_opt = {
        let mut pending_guard = pending.lock().await;
        pending_guard.remove(&seq)
      };
      if let Some(tx) = tx_opt {
        match tx.send(data) {
          Ok(()) => return None,
          Err(returned_data) => data = returned_data,
        }
      }
    }

    Some(data)
  }

  async fn dispatch_pending_response_by_fallback_seq(data: Vec<u8>, pending: &PendingRequests) {
    if let Ok(seq) = MessageReader::get_seq(&data) {
      if let Ok(t) = MessageReader::get_type(&data) {
        if Self::is_tunnel_definition_response_type(t) {
          eprintln!(
            "[ReqFlow] fallback dispatch by seq incoming_type={} incoming_seq={}",
            t.0, seq
          );
        }
      }
      let mut pending_guard = pending.lock().await;
      if let Some(tx) = pending_guard.remove(&seq) {
        let _ = tx.send(data);
      }
    }
  }
}

impl EdgeClient {
  async fn dispatch_wg_p2p_event(
    msg_type: MessageType,
    data: &[u8],
    handler: &Arc<Mutex<Option<super::WGP2PEventHandler>>>,
  ) {
    let msg = match MessageReader::parse(data) {
      Ok(m) => m,
      Err(e) => {
        log::warn!("[WGP2P] failed to parse message: {}", e);
        return;
      }
    };

    let event = match msg_type {
      MessageType::WG_GATHER_INFO => {
        let body = match msg.body_as_wggather_info() {
          Some(b) => b,
          None => return,
        };
        let session_id = body.session_id().unwrap_or("").to_string();
        log::debug!(
          "[WGP2P] received gather request from Edge: session_id={}",
          session_id
        );
        super::WGP2PEvent::Gather { session_id }
      }
      MessageType::WG_PUNCH_INFO => {
        let body = match msg.body_as_wgpunch_info() {
          Some(b) => b,
          None => return,
        };
        let session_id = body.session_id().unwrap_or("").to_string();
        let client_id = body.client_id().unwrap_or("").to_string();
        let mut punch_addrs = Vec::new();
        if let Some(addrs) = body.punch_addrs() {
          for i in 0..addrs.len() {
            punch_addrs.push(addrs.get(i).to_string());
          }
        }
        log::debug!(
          "[WGP2P] received punch request: session_id={} client_id={} addrs={:?}",
          session_id,
          client_id,
          punch_addrs
        );
        super::WGP2PEvent::Punch {
          session_id,
          client_id,
          punch_addrs,
        }
      }
      _ => return,
    };

    let h = handler.lock().await;
    if let Some(cb) = h.as_ref() {
      log::trace!("[WGP2P] dispatching event to handler: {:?}", event);
      cb(event);
    } else {
      log::warn!("[WGP2P] no handler registered, dropping event: {:?}", event);
    }
  }
}
impl EdgeClient {
  pub(super) fn start_read_loop(
    &self,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    mut shutdown_rx: mpsc::Receiver<()>,
    path_connection: Arc<super::wg_path::PathConnection>,
  ) {
    let pending = self.pending_requests.clone();
    let pending_type = self.pending_type_requests.clone();
    let connected = self.connected.clone();
    let log_handler = self.log_handler.clone();
    let edge_status_handler=self.edge_status_handler.clone();
    let tunnel_event_handler = self.tunnel_event_handler.clone();
    let wg_network_event_handler = self.wg_network_event_handler.clone();
    let channel_connection_event_handler = self.channel_connection_event_handler.clone();
    let ice_handler = self.ice_handler.clone();
    let wg_p2p_handler = self.wg_p2p_handler.clone();
    let writer = self.writer.clone();
    let session_id = self.session_id.clone();
    let seq_counter = self.seq.clone();
    let channels = self.channels.clone();
    let channel_traffic = self.channel_traffic.clone();
    let connections = self.connections.clone();
    let udp_associations = self.udp_associations.clone();
    let read_inactivity_timeout = self.config.heartbeat_interval_secs * 3;

    let task = tokio::spawn(async move {
      loop {
        // Read inactivity watchdog: if no frame arrives within 3x heartbeat
        // interval, the connection is likely dead (half-open). Declare it
        // disconnected so the reconnect monitor can restore it quickly,
        // instead of waiting for TCP keepalive or retransmission timeout.
        let read_result = tokio::time::timeout(
          std::time::Duration::from_secs(read_inactivity_timeout),
          async {
            tokio::select! {
              _ = shutdown_rx.recv() => ReadLoopEvent::Shutdown,
              result = read_frame(&mut reader) => ReadLoopEvent::Frame(result),
            }
          }
        ).await;

        match read_result {
          Ok(ReadLoopEvent::Shutdown) => break,
          Ok(ReadLoopEvent::Frame(result)) => {
            match result {
              Ok(data) => {
                let msg_type = MessageReader::get_type(&data);
                if let Ok(t) = msg_type {
                  {
                    let current_session = session_id.read().await;
                    if let Err(error) = path_connection.observe_control_frame(t, &data, current_session.as_deref()) {
                      log::warn!("WG lifecycle guard: {}", error);
                    }
                  }
                  if Self::is_tunnel_definition_response_type(t) {
                    let incoming_seq = MessageReader::get_seq(&data).ok();
                    eprintln!(
                      "[ReqFlow] incoming msg type={} seq={:?} len={}",
                      t.0,
                      incoming_seq,
                      data.len()
                    );
                  }
                  if t==MessageType::EDGE_STATUS_PUSH {
                    let seq=MessageReader::get_seq(&data).unwrap_or(0);
                    let solicited=if seq!=0 {pending.lock().await.contains_key(&seq)} else {
                      let candidates=pending_type.lock().await.get(&MessageType::EDGE_STATUS_PUSH.0).cloned().unwrap_or_default();
                      let active=pending.lock().await; candidates.iter().any(|seq|active.contains_key(seq))
                    };
                    if !solicited {
                      if let Ok(value)=MessageReader::parse_edge_status_push(&data) {
                        if let Some(handler)=edge_status_handler.lock().await.as_ref() {handler(value);}
                      }
                      continue;
                    }
                  }
                  Self::route_message(
                    t,
                    data,
                    &writer,
                    &session_id,
                    &seq_counter,
                    &channel_traffic,
                    &channels,
                    &connections,
                    &udp_associations,
                    &channel_connection_event_handler,
                    &log_handler,
                    &tunnel_event_handler,
                    &wg_network_event_handler,
                    &ice_handler,
                    &wg_p2p_handler,
                    &pending,
                    &pending_type,
                  ).await;
                  continue;
                }

                <Self as ReadDispatch>::dispatch_pending_response_by_fallback_seq(data, &pending).await;
              }
              Err(err) => {
                // 连接断开：记录错误并尽快终止 pending 请求，避免上层继续等待到 timeout。
                eprintln!("[ReqFlow] read loop terminated due to read_frame error: {}", err);
                connected.store(false, Ordering::SeqCst);
                {
                  let mut pending_guard = pending.lock().await;
                  pending_guard.clear();
                }
                {
                  let mut pending_type_guard = pending_type.lock().await;
                  pending_type_guard.clear();
                }
                break;
              }
            }
          }
          Err(_) => {
            // Read inactivity timeout: no frame received for 3x heartbeat interval.
            // Connection is likely dead (half-open). Declare disconnected so the
            // reconnect monitor can restore it.
            log::warn!(
              "[ReqFlow] read inactivity timeout ({}s): no data received, declaring connection dead",
              read_inactivity_timeout
            );
            connected.store(false, Ordering::SeqCst);
            {
              let mut pending_guard = pending.lock().await;
              pending_guard.clear();
            }
            {
              let mut pending_type_guard = pending_type.lock().await;
              pending_type_guard.clear();
            }
            break;
          }
        }
      }
      path_connection.close();
    });
    self.track_control_task(task);
  }

  async fn route_message(
    msg_type: MessageType,
    data: Vec<u8>,
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channels: &Arc<Mutex<HashMap<String, ChannelInfo>>>,
    connections: &Arc<Mutex<HashMap<String, TcpConnection>>>,
    udp_associations: &Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
    log_handler: &Arc<Mutex<Option<LogHandler>>>,
    tunnel_event_handler: &Arc<Mutex<Option<TunnelEventHandler>>>,
    wg_network_event_handler: &Arc<Mutex<Option<WGNetworkEventHandler>>>,
    ice_handler: &Arc<Mutex<Option<IceHandler>>>,
    wg_p2p_handler: &Arc<Mutex<Option<super::WGP2PEventHandler>>>,
    pending: &PendingRequests,
    pending_type: &PendingTypeRequests,
  ) {
    match msg_type {
      // 处理 DATA_PACKET - TCP/UDP 透明代理
      MessageType::DATA_PACKET => {
        <Self as DataPacket>::handle_data_packet_frame(
          &data,
          writer,
          session_id,
          seq_counter,
          channel_traffic,
          channels,
          connections,
          udp_associations,
          channel_connection_event_handler,
        )
        .await;
      }
      // 处理 PUSH_REQUEST
      MessageType::PUSH_REQUEST => {
        <Self as HTTP>::handle_push_request_frame(
          &data,
          writer,
          session_id,
          seq_counter,
          channel_traffic,
          channels,
        )
        .await;
      }
      MessageType::EDGE_LOG_PUSH
      | MessageType::TUNNEL_EVENT_PUSH
      | MessageType::WG_NETWORK_EVENT_PUSH => {
        let _ = <Self as ReadDispatch>::handle_push_notifications(
          msg_type,
          &data,
          log_handler,
          tunnel_event_handler,
          wg_network_event_handler,
        )
        .await;
      }
      MessageType::ICE_START => {
        <Self as ICE>::handle_ice_start(&data, ice_handler).await;
      }
      MessageType::ICE_PUNCH => {
        <Self as ICE>::handle_ice_punch(&data, ice_handler).await;
      }
      MessageType::ICE_QUIC_START => {
        <Self as ICE>::handle_ice_quic_start(&data, ice_handler).await;
      }
      MessageType::ICE_STATE => {
        <Self as ICE>::handle_ice_state(&data, ice_handler).await;
      }
      MessageType::WG_GATHER_INFO | MessageType::WG_PUNCH_INFO => {
        Self::dispatch_wg_p2p_event(msg_type, &data, wg_p2p_handler).await;
      }
      // These are uplinks. They must never consume an unrelated request waiter.
      MessageType::WG_PATH_RUNTIME | MessageType::WG_PATH_REPORT | MessageType::WG_PATH_REQUEST => {
      }
      _ => {
        if msg_type == MessageType::ERROR {
          match MessageReader::parse_error(&data) {
            Ok(error) => log::warn!(
              "[ReqFlow] ERROR from edge: code={} message={} details={}",
              error.code,
              error.message,
              error.details
            ),
            Err(error) => log::warn!("[ReqFlow] ERROR from edge: failed to parse body: {}", error),
          }
        }
        let Some(data) =
          <Self as ReadDispatch>::dispatch_pending_response(msg_type, data, pending, pending_type)
            .await
        else {
          return;
        };
        <Self as ReadDispatch>::dispatch_pending_response_by_fallback_seq(data, pending).await;
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn wg_path_commands_cannot_consume_unrelated_request_waiters() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    let mut rx = register(&client, 42, MessageType::WG_GET_NETWORK_ACK).await;
    for kind in [
      MessageType::WG_PATH_RUNTIME,
      MessageType::WG_PATH_REPORT,
      MessageType::WG_PATH_REQUEST,
    ] {
      EdgeClient::route_message(
        kind,
        response(kind, 42),
        &client.writer,
        &client.session_id,
        &client.seq,
        &client.channel_traffic,
        &client.channels,
        &client.connections,
        &client.udp_associations,
        &client.channel_connection_event_handler,
        &client.log_handler,
        &client.tunnel_event_handler,
        &client.wg_network_event_handler,
        &client.ice_handler,
        &client.wg_p2p_handler,
        &client.pending_requests,
        &client.pending_type_requests,
      )
      .await;
      assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
      ));
      assert_eq!(client.pending_requests.lock().await.len(), 1);
    }
    let expected = response(MessageType::WG_GET_NETWORK_ACK, 42);
    assert!(<EdgeClient as ReadDispatch>::dispatch_pending_response(
      MessageType::WG_GET_NETWORK_ACK,
      expected.clone(),
      &client.pending_requests,
      &client.pending_type_requests
    )
    .await
    .is_none());
    assert_eq!(rx.await.unwrap(), expected);
  }

  fn response(msg_type: MessageType, seq: u32) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let header = message::MessageHeader::create(
      &mut builder,
      &message::MessageHeaderArgs {
        type_: msg_type,
        seq,
        ..Default::default()
      },
    );
    let error_body = if msg_type == MessageType::ERROR {
      let text = builder.create_string("network not found");
      Some(
        message::Error::create(
          &mut builder,
          &message::ErrorArgs {
            code: message::ErrorCode::INTERNAL_ERROR,
            message: Some(text),
            ..Default::default()
          },
        )
        .as_union_value(),
      )
    } else {
      None
    };
    let msg = message::Message::create(
      &mut builder,
      &message::MessageArgs {
        header: Some(header),
        body_type: if error_body.is_some() {
          message::MessageBody::Error
        } else {
          message::MessageBody::NONE
        },
        body: error_body,
      },
    );
    builder.finish(msg, None);
    builder.finished_data().to_vec()
  }

  async fn register(
    client: &EdgeClient,
    seq: u32,
    msg_type: MessageType,
  ) -> oneshot::Receiver<Vec<u8>> {
    let (tx, rx) = oneshot::channel();
    client.pending_requests.lock().await.insert(seq, tx);
    let mut types = client.pending_type_requests.lock().await;
    types.entry(msg_type.0).or_default().push_back(seq);
    rx
  }

  async fn assert_clean(client: &EdgeClient) {
    tokio::time::timeout(Duration::from_secs(1), async {
      loop {
        if client.pending_requests.lock().await.is_empty()
          && client.pending_type_requests.lock().await.is_empty()
        {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("request registrations must be cleaned up");
  }

  #[tokio::test]
  async fn cancelled_request_does_not_leave_pending_registration() {
    let client = Arc::new(EdgeClient::new(EdgeClientConfig::default()));
    client.connected.store(true, Ordering::SeqCst);
    let writer_guard = client.writer.lock().await;
    let task_client = client.clone();
    let task = tokio::spawn(async move {
      task_client
        .send_request(vec![], 42, MessageType::WG_GET_NETWORK_ACK)
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
      while !client
        .pending_type_requests
        .lock()
        .await
        .contains_key(&MessageType::WG_GET_NETWORK_ACK.0)
      {
        tokio::task::yield_now().await;
      }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(writer_guard);
    assert_clean(&client).await;
  }

  #[tokio::test]
  async fn missing_writer_does_not_leave_pending_registration() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    client.connected.store(true, Ordering::SeqCst);
    assert!(matches!(
      client
        .send_request(vec![], 42, MessageType::WG_GET_NETWORK_ACK)
        .await,
      Err(TransportError::NotConnected)
    ));
    assert_clean(&client).await;
  }

  #[tokio::test]
  async fn late_sequenced_response_cannot_complete_another_request() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    let mut rx = register(&client, 43, MessageType::WG_GET_NETWORK_ACK).await;
    EdgeClient::dispatch_pending_response(
      MessageType::WG_GET_NETWORK_ACK,
      response(MessageType::WG_GET_NETWORK_ACK, 42),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert!(matches!(
      rx.try_recv(),
      Err(oneshot::error::TryRecvError::Empty)
    ));
    let expected = response(MessageType::WG_GET_NETWORK_ACK, 43);
    EdgeClient::dispatch_pending_response(
      MessageType::WG_GET_NETWORK_ACK,
      expected.clone(),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert_eq!(rx.await.unwrap(), expected);
  }

  #[tokio::test]
  async fn legacy_response_skips_cancelled_and_completed_waiters() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    drop(register(&client, 41, MessageType::EDGE_STATUS_PUSH).await);
    drop(register(&client, 42, MessageType::EDGE_STATUS_PUSH).await);
    client.pending_requests.lock().await.remove(&42);
    let rx = register(&client, 43, MessageType::EDGE_STATUS_PUSH).await;
    let expected = response(MessageType::EDGE_STATUS_PUSH, 0);
    EdgeClient::dispatch_pending_response(
      MessageType::EDGE_STATUS_PUSH,
      expected.clone(),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert_eq!(
      tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap()
        .unwrap(),
      expected
    );
  }

  #[tokio::test]
  async fn wg_uplink_errors_cannot_fail_concurrent_snapshot_requests() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    let mut first = register(&client, 42, MessageType::WG_NETWORK_RUNTIME_RESPONSE).await;
    let mut second = register(&client, 43, MessageType::WG_NETWORK_RUNTIME_RESPONSE).await;
    // Model both a pre-fix ERROR queue and a current one-way path frame with
    // its own sequence. Neither error belongs to either snapshot request.
    client
      .pending_type_requests
      .lock()
      .await
      .entry(MessageType::ERROR.0)
      .or_default()
      .extend([42, 43]);
    for seq in [0, 41] {
      EdgeClient::route_message(
        MessageType::ERROR,
        response(MessageType::ERROR, seq),
        &client.writer,
        &client.session_id,
        &client.seq,
        &client.channel_traffic,
        &client.channels,
        &client.connections,
        &client.udp_associations,
        &client.channel_connection_event_handler,
        &client.log_handler,
        &client.tunnel_event_handler,
        &client.wg_network_event_handler,
        &client.ice_handler,
        &client.wg_p2p_handler,
        &client.pending_requests,
        &client.pending_type_requests,
      )
      .await;
      assert!(matches!(
        first.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
      ));
      assert!(matches!(
        second.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
      ));
      assert_eq!(client.pending_requests.lock().await.len(), 2);
    }
    // Real snapshot responses still reach their own waiter, out of order.
    let later = response(MessageType::WG_NETWORK_RUNTIME_RESPONSE, 43);
    EdgeClient::dispatch_pending_response(
      MessageType::WG_NETWORK_RUNTIME_RESPONSE,
      later.clone(),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert_eq!(second.await.unwrap(), later);
    let earlier = response(MessageType::WG_NETWORK_RUNTIME_RESPONSE, 42);
    EdgeClient::dispatch_pending_response(
      MessageType::WG_NETWORK_RUNTIME_RESPONSE,
      earlier.clone(),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert_eq!(first.await.unwrap(), earlier);
  }

  #[tokio::test]
  async fn sequenced_edge_error_frame_completes_its_pending_request() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    let rx = register(&client, 42, MessageType::WG_NETWORK_RUNTIME_RESPONSE).await;
    let expected = response(MessageType::ERROR, 42);
    EdgeClient::route_message(
      MessageType::ERROR,
      expected.clone(),
      &client.writer,
      &client.session_id,
      &client.seq,
      &client.channel_traffic,
      &client.channels,
      &client.connections,
      &client.udp_associations,
      &client.channel_connection_event_handler,
      &client.log_handler,
      &client.tunnel_event_handler,
      &client.wg_network_event_handler,
      &client.ice_handler,
      &client.wg_p2p_handler,
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    let received = tokio::time::timeout(Duration::from_secs(1), rx)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(received, expected);
    assert_eq!(
      MessageReader::parse_error(&received).unwrap().message,
      "network not found"
    );
  }
}
