use super::*;

/// `ICE` 负责 ICE 协议帧的解析与事件投递。
///
/// 职责边界：
/// - 解析不同类型的 ICE 消息；
/// - 将协议消息映射为 `IceMessage`；
/// - 统一分发到已注册的 ICE 回调处理器。
pub(super) trait ICE {
  async fn handle_ice_start(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>);

  async fn handle_ice_punch(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>);

  async fn handle_ice_quic_start(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>);

  async fn handle_ice_state(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>);
}

impl ICE for EdgeClient {
  async fn handle_ice_start(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>) {
    eprintln!("[IceFlow] received ICE_START frame, bytes={}", data.len());
    match MessageReader::parse_ice_start(data) {
      Ok(msg) => {
        let sid = msg.ice_session_id.clone();
        let udp = msg.edge_udp_addr.clone();
        let alt = msg.edge_udp_addr_alt.clone();
        let handler = ice_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          eprintln!(
            "[IceFlow] dispatch ICE_START to handler sid={} udp={} alt={}",
            sid, udp, alt
          );
          h(IceMessage::Start(msg));
        } else {
          eprintln!(
            "[IceFlow] drop ICE_START: no ice handler subscribed sid={} udp={} alt={}",
            sid, udp, alt
          );
        }
      }
      Err(err) => {
        eprintln!("[IceFlow] parse ICE_START failed: {}", err);
      }
    }
  }

  async fn handle_ice_punch(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>) {
    eprintln!("[IceFlow] received ICE_PUNCH frame, bytes={}", data.len());
    match MessageReader::parse_ice_punch(data) {
      Ok(msg) => {
        let sid = msg.ice_session_id.clone();
        let target = msg.target_addr.clone();
        let handler = ice_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          eprintln!(
            "[IceFlow] dispatch ICE_PUNCH to handler sid={} target={}",
            sid, target
          );
          h(IceMessage::Punch(msg));
        } else {
          eprintln!(
            "[IceFlow] drop ICE_PUNCH: no ice handler subscribed sid={} target={}",
            sid, target
          );
        }
      }
      Err(err) => {
        eprintln!("[IceFlow] parse ICE_PUNCH failed: {}", err);
      }
    }
  }

  async fn handle_ice_quic_start(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>) {
    eprintln!(
      "[IceFlow] received ICE_QUIC_START frame, bytes={}",
      data.len()
    );
    match MessageReader::parse_ice_quic_start(data) {
      Ok(msg) => {
        let sid = msg.ice_session_id.clone();
        let peer = msg.peer_addr.clone();
        let handler = ice_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          eprintln!(
            "[IceFlow] dispatch ICE_QUIC_START to handler sid={} peer={}",
            sid, peer
          );
          h(IceMessage::QuicStart(msg));
        } else {
          eprintln!(
            "[IceFlow] drop ICE_QUIC_START: no ice handler subscribed sid={} peer={}",
            sid, peer
          );
        }
      }
      Err(err) => {
        eprintln!("[IceFlow] parse ICE_QUIC_START failed: {}", err);
      }
    }
  }

  async fn handle_ice_state(data: &[u8], ice_handler: &Arc<Mutex<Option<IceHandler>>>) {
    eprintln!("[IceFlow] received ICE_STATE frame, bytes={}", data.len());
    match MessageReader::parse_ice_state_change(data) {
      Ok(msg) => {
        let sid = msg.ice_session_id.clone();
        let state = msg.state.clone();
        let handler = ice_handler.lock().await;
        if let Some(h) = handler.as_ref() {
          eprintln!(
            "[IceFlow] dispatch ICE_STATE to handler sid={} state={}",
            sid, state
          );
          h(IceMessage::StateChange(msg));
        } else {
          eprintln!(
            "[IceFlow] drop ICE_STATE: no ice handler subscribed sid={} state={}",
            sid, state
          );
        }
      }
      Err(err) => {
        eprintln!("[IceFlow] parse ICE_STATE failed: {}", err);
      }
    }
  }
}
