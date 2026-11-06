use super::*;

/// `TcpBridge` 定义 TCP 本地桥接与连接生命周期管理能力。
///
/// 职责边界：
/// - 批量关闭连接（全量/按 channel）；
/// - 建立本地 TCP 连接并维护 edge 与本地流之间的数据桥接。
pub(super) trait TcpBridge {
  async fn shutdown_all_tcp_connections(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    close_flags: u8,
  );

  async fn shutdown_tcp_connections_for_channel(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_id: &str,
    close_flags: u8,
  );

  async fn handle_new_connection(
    connection_id: String,
    channel_id: String,
    protocol: String,
    local_addr: String,
    link_type_hint: String,
    remote_endpoint: String,
    max_buffer_size: usize,
    dynamic_window: bool,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
    initial_data: Vec<u8>,
  ) -> Result<()>;
}

impl TcpBridge for EdgeClient {
  async fn shutdown_all_tcp_connections(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    close_flags: u8,
  ) {
    EdgeClient::shutdown_all_tcp_connections(connections, close_flags).await
  }

  async fn shutdown_tcp_connections_for_channel(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_id: &str,
    close_flags: u8,
  ) {
    EdgeClient::shutdown_tcp_connections_for_channel(connections, channel_id, close_flags).await
  }

  async fn handle_new_connection(
    connection_id: String,
    channel_id: String,
    protocol: String,
    local_addr: String,
    link_type_hint: String,
    remote_endpoint: String,
    max_buffer_size: usize,
    dynamic_window: bool,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
    initial_data: Vec<u8>,
  ) -> Result<()> {
    EdgeClient::handle_new_connection(
      connection_id,
      channel_id,
      protocol,
      local_addr,
      link_type_hint,
      remote_endpoint,
      max_buffer_size,
      dynamic_window,
      writer,
      session_id,
      seq_counter,
      channel_traffic,
      connections,
      channel_connection_event_handler,
      initial_data,
    )
    .await
  }
}

impl EdgeClient {
  pub(super) async fn shutdown_all_tcp_connections(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    close_flags: u8,
  ) {
    let shutdown_txs = {
      let connections_guard = connections.lock().await;
      connections_guard
        .values()
        .map(|conn| conn.shutdown_tx.clone())
        .collect::<Vec<_>>()
    };

    for tx in shutdown_txs {
      let _ = tx.send(close_flags).await;
    }
  }

  pub(super) async fn shutdown_tcp_connections_for_channel(
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_id: &str,
    close_flags: u8,
  ) {
    let shutdown_txs = {
      let connections_guard = connections.lock().await;
      connections_guard
        .values()
        .filter(|conn| conn.channel_id == channel_id)
        .map(|conn| conn.shutdown_tx.clone())
        .collect::<Vec<_>>()
    };

    for tx in shutdown_txs {
      let _ = tx.send(close_flags).await;
    }
  }

  pub(super) async fn handle_new_connection(
    connection_id: String,
    channel_id: String,
    protocol: String,
    local_addr: String,
    link_type_hint: String,
    remote_endpoint: String,
    max_buffer_size: usize,
    dynamic_window: bool,
    writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: Arc<RwLock<Option<String>>>,
    seq_counter: Arc<AtomicU32>,
    channel_traffic: Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    connections: Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_connection_event_handler: Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
    initial_data: Vec<u8>,
  ) -> Result<()> {
    // 连接到本地服务
    let mut local_stream = TcpStream::connect(&local_addr)
      .await
      .map_err(|e| TransportError::Io(e))?;

    // 如果有初始数据，立即写入
    if !initial_data.is_empty() {
      eprintln!(
        "[EdgeClient][{}] Writing initial data: {} bytes",
        connection_id,
        initial_data.len()
      );
      if let Ok(s) = std::str::from_utf8(&initial_data[..initial_data.len().min(200)]) {
        eprintln!(
          "[EdgeClient][{}] Initial data preview: {}",
          connection_id, s
        );
      }
      local_stream
        .write_all(&initial_data)
        .await
        .map_err(|e| TransportError::Io(e))?;
    }

    // 创建 channels
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<u8>(1);

    // 保存连接
    {
      let mut conns = connections.lock().await;
      let conn_key = Self::tcp_conn_key(&channel_id, &connection_id);
      conns.insert(
        conn_key,
        TcpConnection {
          data_tx,
          shutdown_tx,
          channel_id: channel_id.clone(),
          protocol: protocol.clone(),
          local_addr: local_addr.clone(),
          link_type_hint: normalize_link_type(&link_type_hint),
          remote_endpoint: remote_endpoint.trim().to_string(),
        },
      );
    }

    Self::emit_channel_connection_event(
      &channel_connection_event_handler,
      Self::build_channel_connection_event(
        "open",
        &protocol,
        &channel_id,
        &connection_id,
        &local_addr,
        &link_type_hint,
        &remote_endpoint,
        "local-connected",
      ),
    )
    .await;

    // 启动读取循环，从本地服务读取数据并发送到edge
    let connection_id_clone = connection_id.clone();
    let channel_id_clone = channel_id.clone();
    let protocol_clone = protocol.clone();
    let local_addr_clone = local_addr.clone();
    let link_type_hint_clone = normalize_link_type(&link_type_hint);
    let remote_endpoint_clone = remote_endpoint.trim().to_string();
    let connections_clone = connections.clone();
    let connection_event_handler_clone = channel_connection_event_handler.clone();

    tokio::spawn(async move {
      let negotiated_max = Self::normalize_buffer_size(max_buffer_size);
      let window_min = if dynamic_window {
        DYNAMIC_WINDOW_FLOOR
          .min(negotiated_max)
          .max(MIN_CHANNEL_BUFFER_SIZE)
      } else {
        negotiated_max
      };
      let mut window_cur = if dynamic_window {
        negotiated_max
          .min(DEFAULT_CHANNEL_BUFFER_SIZE)
          .max(window_min)
      } else {
        negotiated_max
      };
      let mut buf = vec![0u8; window_cur];
      let mut response_buffer = Vec::new(); // 仅用于累积 headers（headers 解析完后不再追加）
      let mut headers_complete = false;
      let mut content_length: Option<usize> = None;
      let mut is_chunked = false;
      let mut body_bytes_received: usize = 0; // 已收到的 body 字节数
      let mut response_sent = false; // 标记响应是否已发送
      let mut edge_fin_received = false; // Edge 已发送 FIN（请求数据完成）
      let mut grow_streak = 0usize;
      let mut small_read_streak = 0usize;
      let exit_reason = loop {
        tokio::select! {
            Some(close_flags) = shutdown_rx.recv() => {
                if close_flags & 0x02 != 0 {
                    eprintln!(
                        "[EdgeClient][{}] Edge RST received, stop forwarding local response immediately",
                        connection_id_clone
                    );
                    break "edge-rst";
                }

                if close_flags & 0x01 != 0 && !edge_fin_received {
                    // Edge 发送了 FIN，表示请求数据已完成
                    // 但本地服务的响应可能还在流式传输，不能 break
                    edge_fin_received = true;
                    eprintln!("[EdgeClient][{}] Edge FIN received, body_bytes_received={}, headers_complete={}, continue reading local response",
                        connection_id_clone, body_bytes_received, headers_complete);
                }
            }
            // 从 edge 接收数据并写入本地
            Some(data) = data_rx.recv(), if !edge_fin_received => {
                if let Err(e) = local_stream.write_all(&data).await {
                    eprintln!("[EdgeClient] Write to local failed: {}", e);
                    break "write-local-failed";
                }
            }
            // 从本地读取数据并发送到 edge
            result = local_stream.read(&mut buf[..window_cur]) => {
                match result {
                    Ok(0) => {
                        // EOF - 连接关闭
                        eprintln!("[EdgeClient][{}] Local EOF, total body_bytes_received={}, headers_complete={}, edge_fin={}, response_sent={}",
                            connection_id_clone, body_bytes_received, headers_complete, edge_fin_received, response_sent);

                        // 发送 FIN
                        let sid = session_id.read().await.clone();
                        let mut builder = MessageBuilder::new()
                            .seq(seq_counter.fetch_add(1, Ordering::SeqCst));
                        if let Some(s) = sid {
                            builder = builder.session_id(s);
                        }
                        let msg = builder.data_packet(
                            &channel_id_clone,
                            &connection_id_clone,
                            0,
                            &[],
                            0x01, // FIN flag
                        );

                        let mut writer_guard = writer.lock().await;
                        if let Some(w) = writer_guard.as_mut() {
                            let _ = write_frame(w, &msg).await;
                        }

                        // 清理连接
                        let mut conns = connections_clone.lock().await;
                        let conn_key = Self::tcp_conn_key(&channel_id_clone, &connection_id_clone);
                        conns.remove(&conn_key);
                        drop(conns);
                        Self::emit_channel_connection_event(
                            &connection_event_handler_clone,
                            Self::build_channel_connection_event(
                                "close",
                                &protocol_clone,
                                &channel_id_clone,
                                &connection_id_clone,
                                &local_addr_clone,
                                &link_type_hint_clone,
                                &remote_endpoint_clone,
                                "local-eof",
                            ),
                        ).await;
                        break "local-eof";
                    }
                    Ok(n) => {
                        // 如果响应已发送，忽略后续数据（Keep-Alive 后的新请求）
                        if response_sent {
                            eprintln!("[EdgeClient][{}] Ignoring {} bytes after response_sent", connection_id_clone, n);
                            continue;
                        }

                        // headers 解析阶段：累积数据直到找到 headers 结束标记
                        if !headers_complete {
                            response_buffer.extend_from_slice(&buf[..n]);

                            // 查找 headers 结束标记
                            if let Some(pos) = response_buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                headers_complete = true;
                                let headers_end_pos = pos + 4;

                                // 解析 Content-Length 和 Transfer-Encoding
                                if let Ok(headers_str) = std::str::from_utf8(&response_buffer[..headers_end_pos]) {
                                    for line in headers_str.lines() {
                                        let line_lower = line.to_lowercase();
                                        if line_lower.starts_with("content-length:") {
                                            if let Some(value) = line.split(':').nth(1) {
                                                content_length = value.trim().parse().ok();
                                            }
                                        } else if line_lower.starts_with("transfer-encoding:") && line_lower.contains("chunked") {
                                            is_chunked = true;
                                        }
                                    }
                                }
                                // headers 解析完毕，计算已收到的 body 字节数
                                body_bytes_received = response_buffer.len() - headers_end_pos;
                                // 释放 response_buffer 内存，后续不再需要
                                response_buffer = Vec::new();
                                eprintln!("[EdgeClient] Headers parsed, Content-Length: {:?}, chunked: {}", content_length, is_chunked);
                            }
                        } else {
                            // headers 已解析，只追踪 body 字节计数
                            body_bytes_received += n;
                        }

                        // 检查响应是否完整
                        // - 有 Content-Length：按字节数判断
                        // - chunked 或无 Content-Length：不主动判断完成，等待 EOF
                        let response_complete = if let Some(expected_len) = content_length {
                            body_bytes_received >= expected_len
                        } else {
                            // chunked 编码或无 Content-Length，依赖连接关闭（EOF）来结束
                            false
                        };

                        if response_complete {
                            eprintln!("[EdgeClient][{}] Response complete! body_bytes_received={}, content_length={:?}",
                                connection_id_clone, body_bytes_received, content_length);
                            // 先发送当前读取的数据
                            let sid = session_id.read().await.clone();
                            let mut builder = MessageBuilder::new()
                                .seq(seq_counter.fetch_add(1, Ordering::SeqCst));
                            if let Some(s) = sid {
                                builder = builder.session_id(s);
                            }
                            let data_msg = builder.data_packet(
                                &channel_id_clone,
                                &connection_id_clone,
                                0,
                                &buf[..n],
                                0, // no flags
                            );

                            let mut writer_guard = writer.lock().await;
                            if let Some(w) = writer_guard.as_mut() {
                                if write_frame(w, &data_msg).await.is_err() {
                                    break "send-response-chunk-failed";
                                }
                            }
                            Self::record_channel_traffic(
                              &channel_traffic,
                              &channel_id_clone,
                              0,
                              n,
                            ).await;
                            drop(writer_guard);

                            // 发送 FIN 给 Edge，但不关闭本地连接（保持 Keep-Alive）
                            let sid = session_id.read().await.clone();
                            let mut builder = MessageBuilder::new()
                                .seq(seq_counter.fetch_add(1, Ordering::SeqCst));
                            if let Some(s) = sid {
                                builder = builder.session_id(s);
                            }
                            let msg = builder.data_packet(
                                &channel_id_clone,
                                &connection_id_clone,
                                0,
                                &[],
                                0x01, // FIN flag
                            );

                            let mut writer_guard = writer.lock().await;
                            if let Some(w) = writer_guard.as_mut() {
                                let _ = write_frame(w, &msg).await;
                            }

                            // 标记响应已发送
                            response_sent = true;

                            // 清理 Edge 端连接，但保持本地连接
                            let mut conns = connections_clone.lock().await;
                            let conn_key =
                              Self::tcp_conn_key(&channel_id_clone, &connection_id_clone);
                            conns.remove(&conn_key);
                            drop(conns);
                            Self::emit_channel_connection_event(
                                &connection_event_handler_clone,
                                Self::build_channel_connection_event(
                                    "close",
                                    &protocol_clone,
                                    &channel_id_clone,
                                    &connection_id_clone,
                                    &local_addr_clone,
                                    &link_type_hint_clone,
                                    &remote_endpoint_clone,
                                    "response-complete",
                                ),
                            ).await;

                            // 继续读取循环，等待本地连接自然关闭（Keep-Alive 超时）
                            // 后续数据会被忽略
                            continue;
                        }

                        // 发送数据到edge
                        let send_start = Instant::now();
                        // eprintln!(
                        //   "[EdgeClient][{}] Streaming chunk: {} bytes, total_body={}, window={}",
                        //   connection_id_clone, n, body_bytes_received, window_cur
                        // );
                        let sid = session_id.read().await.clone();
                        let mut builder = MessageBuilder::new()
                            .seq(seq_counter.fetch_add(1, Ordering::SeqCst));
                        if let Some(s) = sid {
                            builder = builder.session_id(s);
                        }
                        let msg = builder.data_packet(
                            &channel_id_clone,
                            &connection_id_clone,
                            0,
                            &buf[..n],
                            0, // no flags
                        );

                        let mut writer_guard = writer.lock().await;
                        if let Some(w) = writer_guard.as_mut() {
                            if let Err(e) = write_frame(w, &msg).await {
                                eprintln!("[EdgeClient][{}] write_frame FAILED: {:?}, total_body={}",
                                    connection_id_clone, e, body_bytes_received);
                                break "stream-write-failed";
                            }
                        } else {
                            eprintln!("[EdgeClient][{}] writer is None! total_body={}", connection_id_clone, body_bytes_received);
                            break "writer-missing";
                        }
                        Self::record_channel_traffic(
                          &channel_traffic,
                          &channel_id_clone,
                          0,
                          n,
                        ).await;

                        if dynamic_window {
                            let send_cost = send_start.elapsed();
                            let mut next_window = window_cur;

                            // 连续高占用 + 发送开销低，逐步增大窗口（最多到协商上限）
                            if n >= (window_cur * 9 / 10) && send_cost <= Duration::from_millis(3) {
                                grow_streak += 1;
                                small_read_streak = 0;
                                if grow_streak >= 3 && window_cur < negotiated_max {
                                    next_window = (window_cur * 2).min(negotiated_max);
                                    grow_streak = 0;
                                }
                            } else {
                                grow_streak = 0;
                            }

                            // 发送耗时偏高，快速减小窗口，减轻背压
                            if send_cost >= Duration::from_millis(15) && window_cur > window_min {
                                next_window = (window_cur / 2).max(window_min);
                                small_read_streak = 0;
                            } else if n <= (window_cur / 4) && window_cur > window_min {
                                // 长时间小读，缓慢回落，降低单连接内存占用
                                small_read_streak += 1;
                                if small_read_streak >= 8 {
                                    next_window = (window_cur / 2).max(window_min);
                                    small_read_streak = 0;
                                }
                            } else {
                                small_read_streak = 0;
                            }

                            if next_window != window_cur {
                                log::debug!(
                                    "[EdgeClient] Adjust window: {} -> {} (send_cost={:?}, read={})",
                                    window_cur,
                                    next_window,
                                    send_cost,
                                    n
                                );
                                window_cur = next_window;
                                if buf.len() != window_cur {
                                    buf.resize(window_cur, 0);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[EdgeClient][{}] Read from local FAILED: {}, total_body={}",
                            connection_id_clone, e, body_bytes_received);
                        break "read-local-failed";
                    }
                }
            }
        }
      };

      let mut conns = connections_clone.lock().await;
      let conn_key = Self::tcp_conn_key(&channel_id_clone, &connection_id_clone);
      let removed = conns.remove(&conn_key).is_some();
      drop(conns);
      if removed {
        Self::emit_channel_connection_event(
          &connection_event_handler_clone,
          Self::build_channel_connection_event(
            "close",
            &protocol_clone,
            &channel_id_clone,
            &connection_id_clone,
            &local_addr_clone,
            &link_type_hint_clone,
            &remote_endpoint_clone,
            exit_reason,
          ),
        )
        .await;
      }
    });

    Ok(())
  }
}
