use super::*;
use crate::client::utils::{is_chunked_complete, parse_http_response};

/// `HTTP` 负责 PUSH_REQUEST 到本地 HTTP 服务的完整转发流程。
///
/// 职责边界：
/// - 解析并接收 PUSH_REQUEST；
/// - 调用本地 HTTP 转发并获取响应；
/// - 将 HTTP 响应重新封装为 push_response 回传给 edge。
pub(super) trait HTTP {
  async fn handle_push_request_frame(
    data: &[u8],
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channels: &Arc<Mutex<HashMap<String, ChannelInfo>>>,
  );
}

impl HTTP for EdgeClient {
  async fn handle_push_request_frame(
    data: &[u8],
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channels: &Arc<Mutex<HashMap<String, ChannelInfo>>>,
  ) {
    let push_start = std::time::Instant::now();
    if let Ok(ParsedResponse::PushRequest(req)) = MessageReader::parse_response(data) {
      eprintln!(
        "[EdgeClient] Received PUSH_REQUEST: {} {} {} (parsed in {:?})",
        req.method,
        req.path,
        req.channel_id,
        push_start.elapsed()
      );
      if !req.body.is_empty() {
        Self::record_channel_traffic(channel_traffic, &req.channel_id, req.body.len(), 0).await;
      }
      let channels_clone = channels.clone();
      let writer_clone = writer.clone();
      let session_id_clone = session_id.clone();
      let seq_counter_clone = seq_counter.clone();
      let channel_traffic_clone = channel_traffic.clone();
      tokio::spawn(async move {
        let forward_start = std::time::Instant::now();
        // 获取 channel 信息
        let channel_info = {
          let channels_guard = channels_clone.lock().await;
          channels_guard.get(&req.channel_id).cloned()
        };

        let (status_code, response_headers, response_body, error_msg) =
          if let Some(info) = channel_info {
            // 转发到本地 HTTP 服务
            Self::forward_http_request(
              &info.local_addr,
              &req,
              Some(channel_traffic_clone.clone()),
              Some(req.channel_id.clone()),
            )
            .await
          } else {
            (
              404,
              vec![],
              vec![],
              format!("Channel not found: {}", req.channel_id),
            )
          };

        eprintln!(
          "[EdgeClient] Forward completed in {:?}",
          forward_start.elapsed()
        );

        // 返回响应
        let response_start = std::time::Instant::now();
        let session_id_guard = session_id_clone.read().await;
        let mut builder =
          MessageBuilder::new().seq(seq_counter_clone.fetch_add(1, Ordering::SeqCst));
        if let Some(sid) = session_id_guard.as_ref() {
          builder = builder.session_id(sid.clone());
        }
        drop(session_id_guard);

        let response = builder.push_response(
          &req.request_id,
          status_code,
          &response_headers,
          &response_body,
          &error_msg,
        );

        let mut writer_guard = writer_clone.lock().await;
        if let Some(w) = writer_guard.as_mut() {
          let _ = write_frame(w, &response).await;
        }
        eprintln!(
          "[EdgeClient] Response sent in {:?}, total: {:?}",
          response_start.elapsed(),
          push_start.elapsed()
        );
      });
    }
  }
}

impl EdgeClient {
  /// 转发 HTTP 请求到本地服务
  pub(super) async fn forward_http_request(
    local_addr: &str,
    req: &crate::protocol::message::PushRequestData,
    channel_traffic: Option<Arc<Mutex<HashMap<String, ChannelTrafficStats>>>>,
    channel_id: Option<String>,
  ) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
    use tokio::io::AsyncWriteExt;
    let start = std::time::Instant::now();

    // 连接到本地服务
    eprintln!("[HTTP Forward] Connecting to {}", local_addr);
    let mut stream = match TcpStream::connect(local_addr).await {
      Ok(s) => {
        eprintln!("[HTTP Forward] Connected in {:?}", start.elapsed());
        s
      }
      Err(e) => {
        eprintln!("[EdgeClient] Failed to connect to {}: {}", local_addr, e);
        return (502, vec![], vec![], format!("Failed to connect: {}", e));
      }
    };

    // 构建 HTTP 请求
    let query = if req.query.is_empty() {
      String::new()
    } else {
      format!("?{}", req.query)
    };

    let mut http_request = format!("{} {}{} HTTP/1.1\r\n", req.method, req.path, query);

    // 添加 headers
    let mut has_host = false;
    for header in &req.headers {
      if header.key.to_lowercase() == "host" {
        has_host = true;
      }
      http_request.push_str(&format!("{}: {}\r\n", header.key, header.value));
    }

    // 如果没有 Host 头，添加一个
    if !has_host {
      http_request.push_str(&format!("Host: {}\r\n", local_addr));
    }

    // 添加 Content-Length
    if !req.body.is_empty() {
      http_request.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }

    http_request.push_str("\r\n");

    let write_start = std::time::Instant::now();
    // 发送请求
    if let Err(e) = stream.write_all(http_request.as_bytes()).await {
      eprintln!("[EdgeClient] Failed to write request headers: {}", e);
      return (502, vec![], vec![], format!("Failed to write: {}", e));
    }

    if !req.body.is_empty() {
      if let Err(e) = stream.write_all(&req.body).await {
        eprintln!("[EdgeClient] Failed to write request body: {}", e);
        return (502, vec![], vec![], format!("Failed to write body: {}", e));
      }
    }
    eprintln!("[HTTP Forward] Request sent in {:?}", write_start.elapsed());

    // 读取响应 - 智能读取（根据 Content-Length 或 Connection: close）
    let read_start = std::time::Instant::now();
    let response_data =
      match Self::read_http_response(&mut stream, channel_traffic, channel_id).await {
        Ok(data) => data,
        Err(e) => {
          eprintln!("[EdgeClient] Failed to read response: {:?}", e);
          return (
            502,
            vec![],
            vec![],
            format!("Failed to read response: {:?}", e),
          );
        }
      };
    eprintln!(
      "[HTTP Forward] Response received: {} bytes in {:?}",
      response_data.len(),
      read_start.elapsed()
    );

    eprintln!("[HTTP Forward] Total forward time: {:?}", start.elapsed());

    // 解析 HTTP 响应
    parse_http_response(&response_data)
  }

  async fn record_http_response_body_traffic(
    channel_traffic: &Option<Arc<Mutex<HashMap<String, ChannelTrafficStats>>>>,
    channel_id: &Option<String>,
    bytes_out_delta: usize,
  ) {
    if bytes_out_delta == 0 {
      return;
    }
    let Some(traffic) = channel_traffic.as_ref() else {
      return;
    };
    let Some(channel) = channel_id.as_deref() else {
      return;
    };
    Self::record_channel_traffic(traffic, channel, 0, bytes_out_delta).await;
  }

  /// 智能读取 HTTP 响应（根据 Content-Length 或分块编码）
  async fn read_http_response(
    stream: &mut TcpStream,
    channel_traffic: Option<Arc<Mutex<HashMap<String, ChannelTrafficStats>>>>,
    channel_id: Option<String>,
  ) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let start = std::time::Instant::now();

    // 一次性读取足够大的数据块（包含 headers + body）
    let mut initial_buf = vec![0u8; 65536]; // 64KB
    let n = stream
      .read(&mut initial_buf)
      .await
      .map_err(TransportError::Io)?;
    initial_buf.truncate(n);

    eprintln!(
      "[HTTP Forward] Initial read: {} bytes in {:?}",
      n,
      start.elapsed()
    );

    // 在内存中查找 headers 结束位置（\r\n\r\n 或 \n\n）
    let header_end = initial_buf
      .windows(4)
      .position(|w| w == b"\r\n\r\n")
      .map(|pos| pos + 4)
      .or_else(|| {
        initial_buf
          .windows(2)
          .position(|w| w == b"\n\n")
          .map(|pos| pos + 2)
      })
      .ok_or_else(|| {
        TransportError::Io(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          "headers not found",
        ))
      })?;

    let headers_bytes = &initial_buf[..header_end];
    let headers_str = std::str::from_utf8(headers_bytes)
      .map_err(|_| TransportError::Protocol("invalid UTF-8 in headers".to_string()))?;

    // 解析关键 headers
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut line_count = 0;

    for line in headers_str.lines() {
      line_count += 1;
      let line_lower = line.to_lowercase();
      if line_lower.starts_with("content-length:") {
        if let Some(value) = line.split(':').nth(1) {
          content_length = value.trim().parse().ok();
        }
      } else if line_lower.starts_with("transfer-encoding:") && line_lower.contains("chunked") {
        is_chunked = true;
      }
    }

    eprintln!(
      "[HTTP Forward] Headers parsed: {} lines in {:?}, Content-Length: {:?}",
      line_count,
      start.elapsed(),
      content_length
    );

    let body_start_time = std::time::Instant::now();
    // 检查是否已经读取了完整的响应
    let already_read_body = &initial_buf[header_end..];
    let body = if let Some(expected_len) = content_length {
      let initial_body_len = already_read_body.len().min(expected_len);
      Self::record_http_response_body_traffic(&channel_traffic, &channel_id, initial_body_len)
        .await;
      // 根据 Content-Length 判断
      if already_read_body.len() >= expected_len {
        // 已经读取完整
        already_read_body[..expected_len].to_vec()
      } else {
        // 需要继续读取
        let mut body_buf = already_read_body.to_vec();
        let remaining = expected_len - already_read_body.len();
        let mut pending = remaining;
        let mut buf = vec![0u8; 8192];
        while pending > 0 {
          let read_size = pending.min(buf.len());
          let n = stream
            .read(&mut buf[..read_size])
            .await
            .map_err(TransportError::Io)?;
          if n == 0 {
            return Err(TransportError::Io(std::io::Error::new(
              std::io::ErrorKind::UnexpectedEof,
              "response body ended before Content-Length",
            )));
          }
          body_buf.extend_from_slice(&buf[..n]);
          Self::record_http_response_body_traffic(&channel_traffic, &channel_id, n).await;
          pending -= n;
        }
        body_buf
      }
    } else if is_chunked {
      // chunked 编码：解析 chunk 格式直到遇到 0\r\n\r\n
      let mut body_buf = already_read_body.to_vec();
      Self::record_http_response_body_traffic(
        &channel_traffic,
        &channel_id,
        already_read_body.len(),
      )
      .await;

      // 检查是否已经读取了完整的 chunked body
      if !is_chunked_complete(&body_buf) {
        // 继续读取直到遇到结束标记或超时
        let mut temp_buf = vec![0u8; 8192];
        let mut attempts = 0;
        while attempts < 10 {
          match tokio::time::timeout(Duration::from_millis(100), stream.read(&mut temp_buf)).await {
            Ok(Ok(n)) if n > 0 => {
              body_buf.extend_from_slice(&temp_buf[..n]);
              Self::record_http_response_body_traffic(&channel_traffic, &channel_id, n).await;
              if is_chunked_complete(&body_buf) {
                break;
              }
            }
            _ => break,
          }
          attempts += 1;
        }
      }
      body_buf
    } else {
      // 没有 Content-Length 且不是 chunked，假设已读取的就是全部
      // Connection: close 的情况也在这里处理（不等待 EOF）
      Self::record_http_response_body_traffic(
        &channel_traffic,
        &channel_id,
        already_read_body.len(),
      )
      .await;
      already_read_body.to_vec()
    };

    eprintln!(
      "[HTTP Forward] Body read: {} bytes in {:?}",
      body.len(),
      body_start_time.elapsed()
    );

    // 合并 headers 和 body
    let mut response = headers_bytes.to_vec();
    response.extend_from_slice(&body);
    Ok(response)
  }
}
