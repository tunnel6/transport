use super::tcp_bridge::TcpBridge;
use super::udp_assoc::UdpAssocOps;
use super::*;

/// `DataPacket` 负责处理 `DATA_PACKET` 帧的收包分发逻辑。
///
/// 职责边界：
/// - 按 channel 协议将数据分发到 UDP/TCP 路径；
/// - 维护连接生命周期相关的 TCP 收包处理；
/// - 保持 read loop 只负责消息路由，不承担具体转发细节。
pub(super) trait DataPacket {
  async fn handle_data_packet_frame(
    data: &[u8],
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channels: &Arc<Mutex<HashMap<String, ChannelInfo>>>,
    connections: &Arc<Mutex<HashMap<String, TcpConnection>>>,
    udp_associations: &Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  );

  async fn handle_tcp_data_packet(
    packet: crate::protocol::message::DataPacketData,
    channel_info: Option<ChannelInfo>,
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    connections: &Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_connection_event_handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  );
}

impl DataPacket for EdgeClient {
  async fn handle_data_packet_frame(
    data: &[u8],
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    channels: &Arc<Mutex<HashMap<String, ChannelInfo>>>,
    connections: &Arc<Mutex<HashMap<String, TcpConnection>>>,
    udp_associations: &Arc<Mutex<HashMap<String, UdpAssociation>>>,
    channel_connection_event_handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) {
    if let Ok(packet) = MessageReader::parse_data_packet(data) {
      if !packet.data.is_empty() {
        Self::record_channel_traffic(channel_traffic, &packet.channel_id, packet.data.len(), 0)
          .await;
      }

      let channel_info = {
        let channels_guard = channels.lock().await;
        channels_guard.get(&packet.channel_id).cloned()
      };

      // 检查是否为 UDP 数据包（通过 protocol 字段判断）
      let is_udp = channel_info
        .as_ref()
        .map(|i| i.protocol == "udp")
        .unwrap_or(false);

      if is_udp {
        Self::udp_trace(format!(
          "[EdgeClient][UDP] inbound DATA_PACKET: channel_id={}, connection_id={}, flags=0x{:02x}, bytes={}, local_addr={}",
          packet.channel_id,
          packet.connection_id,
          packet.flags,
          packet.data.len(),
          channel_info.as_ref().map(|i| i.local_addr.as_str()).unwrap_or("<missing>")
        ));
        if let Err(err) = <Self as UdpAssocOps>::handle_udp_packet(
          packet,
          channel_info,
          writer.clone(),
          session_id.clone(),
          seq_counter.clone(),
          channel_traffic.clone(),
          udp_associations.clone(),
          channel_connection_event_handler.clone(),
        )
        .await
        {
          eprintln!("[EdgeClient] UDP packet handling failed: {:?}", err);
        }
        return;
      }

      Self::handle_tcp_data_packet(
        packet,
        channel_info,
        writer,
        session_id,
        seq_counter,
        channel_traffic,
        connections,
        channel_connection_event_handler,
      )
      .await;
    }
  }

  async fn handle_tcp_data_packet(
    packet: crate::protocol::message::DataPacketData,
    channel_info: Option<ChannelInfo>,
    writer: &Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    session_id: &Arc<RwLock<Option<String>>>,
    seq_counter: &Arc<AtomicU32>,
    channel_traffic: &Arc<Mutex<HashMap<String, ChannelTrafficStats>>>,
    connections: &Arc<Mutex<HashMap<String, TcpConnection>>>,
    channel_connection_event_handler: &Arc<Mutex<Option<ChannelConnectionEventHandler>>>,
  ) {
    // DATA_PACKET 处理（TCP）
    if packet.flags & 0x03 != 0 {
      let close_flags = packet.flags & 0x03;
      let close_reason = if close_flags & 0x02 != 0 {
        "edge-rst"
      } else {
        "edge-fin"
      };
      let mut conns = connections.lock().await;
      let conn_key = Self::tcp_conn_key(&packet.channel_id, &packet.connection_id);
      if let Some(conn) = conns.remove(&conn_key) {
        let _ = conn.shutdown_tx.send(close_flags).await;
        drop(conns);
        Self::emit_channel_connection_event(
          channel_connection_event_handler,
          Self::build_channel_connection_event(
            "close",
            &conn.protocol,
            &conn.channel_id,
            &packet.connection_id,
            &conn.local_addr,
            &conn.link_type_hint,
            &conn.remote_endpoint,
            close_reason,
          ),
        )
        .await;
      }
      return;
    }

    let conn_exists = {
      let conns = connections.lock().await;
      let conn_key = Self::tcp_conn_key(&packet.channel_id, &packet.connection_id);
      conns.contains_key(&conn_key)
    };

    if !conn_exists {
      if let Some(info) = channel_info {
        let connection_id = packet.connection_id.clone();
        let local_addr = info.local_addr.clone();
        let link_type_hint = info.link_type.clone();
        let remote_endpoint = info.remote_endpoint.clone();
        let buffer_size = info.buffer_size;
        let dynamic_window = info.dynamic_window;
        let protocol = info.protocol.clone();
        let writer_clone = writer.clone();
        let session_id_clone = session_id.clone();
        let seq_clone = seq_counter.clone();
        let channel_traffic_clone = channel_traffic.clone();
        let connections_clone = connections.clone();
        let connection_event_handler_clone = channel_connection_event_handler.clone();
        let channel_id = packet.channel_id.clone();

        // 启动连接处理
        tokio::spawn(async move {
          if let Err(e) = <Self as TcpBridge>::handle_new_connection(
            connection_id,
            channel_id,
            protocol,
            local_addr,
            link_type_hint,
            remote_endpoint,
            buffer_size,
            dynamic_window,
            writer_clone,
            session_id_clone,
            seq_clone,
            channel_traffic_clone,
            connections_clone,
            connection_event_handler_clone,
            packet.data,
          )
          .await
          {
            eprintln!("[EdgeClient] Connection failed: {:?}", e);
          }
        });
      }
    } else {
      let conns = connections.lock().await;
      let conn_key = Self::tcp_conn_key(&packet.channel_id, &packet.connection_id);
      if let Some(conn) = conns.get(&conn_key) {
        if conn.data_tx.send(packet.data).await.is_err() {
          eprintln!("[EdgeClient] Send to local failed");
        }
      }
    }
  }
}
