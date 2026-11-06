use super::{ChannelConnectionEventData, EdgeClient, IceMessage, LogSubscriptionResult};
use crate::error::{Result, TransportError};
use crate::protocol::message::{TunnelEventPushData, WGNetworkEventPushData};
use crate::protocol::{MessageBuilder, MessageReader, MessageType};

/// `Subscriptions` 定义事件订阅与通知上报相关能力。
///
/// 职责边界：
/// - 本地事件回调注册/注销（tunnel/channel/ice/log）；
/// - ICE 结果类 fire-and-forget 上报；
/// - 远端日志订阅协议请求。
#[allow(dead_code)]
pub(super) trait Subscriptions {
  async fn subscribe_tunnel_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(TunnelEventPushData) + Send + 'static;

  async fn unsubscribe_tunnel_events(&self) -> Result<()>;

  async fn subscribe_wg_network_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(WGNetworkEventPushData) + Send + 'static;

  async fn unsubscribe_wg_network_events(&self) -> Result<()>;

  async fn subscribe_channel_connection_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(ChannelConnectionEventData) + Send + 'static;

  async fn unsubscribe_channel_connection_events(&self) -> Result<()>;

  async fn subscribe_ice_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(IceMessage) + Send + 'static;

  async fn unsubscribe_ice_events(&self) -> Result<()>;

  async fn send_ice_punch_result(
    &self,
    ice_session_id: &str,
    success: bool,
    peer_observed_addr: &str,
    attempts_sent: u32,
    first_recv_at: u64,
    failure_reason: &str,
  ) -> Result<()>;

  async fn send_ice_quic_connected(
    &self,
    ice_session_id: &str,
    connection_id: &str,
    local_addr: &str,
    peer_addr: &str,
    rtt_ms: u32,
  ) -> Result<()>;

  async fn subscribe_logs<F>(&self, tail_lines: i32, handler: F) -> Result<LogSubscriptionResult>
  where
    F: Fn(Vec<String>) + Send + 'static;

  async fn unsubscribe_logs(&self) -> Result<LogSubscriptionResult>;
}

impl Subscriptions for EdgeClient {
  async fn subscribe_tunnel_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(TunnelEventPushData) + Send + 'static,
  {
    EdgeClient::subscribe_tunnel_events(self, handler).await
  }

  async fn unsubscribe_tunnel_events(&self) -> Result<()> {
    EdgeClient::unsubscribe_tunnel_events(self).await
  }

  async fn subscribe_wg_network_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(WGNetworkEventPushData) + Send + 'static,
  {
    EdgeClient::subscribe_wg_network_events(self, handler).await
  }

  async fn unsubscribe_wg_network_events(&self) -> Result<()> {
    EdgeClient::unsubscribe_wg_network_events(self).await
  }

  async fn subscribe_channel_connection_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(ChannelConnectionEventData) + Send + 'static,
  {
    EdgeClient::subscribe_channel_connection_events(self, handler).await
  }

  async fn unsubscribe_channel_connection_events(&self) -> Result<()> {
    EdgeClient::unsubscribe_channel_connection_events(self).await
  }

  async fn subscribe_ice_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(IceMessage) + Send + 'static,
  {
    EdgeClient::subscribe_ice_events(self, handler).await
  }

  async fn unsubscribe_ice_events(&self) -> Result<()> {
    EdgeClient::unsubscribe_ice_events(self).await
  }

  async fn send_ice_punch_result(
    &self,
    ice_session_id: &str,
    success: bool,
    peer_observed_addr: &str,
    attempts_sent: u32,
    first_recv_at: u64,
    failure_reason: &str,
  ) -> Result<()> {
    EdgeClient::send_ice_punch_result(
      self,
      ice_session_id,
      success,
      peer_observed_addr,
      attempts_sent,
      first_recv_at,
      failure_reason,
    )
    .await
  }

  async fn send_ice_quic_connected(
    &self,
    ice_session_id: &str,
    connection_id: &str,
    local_addr: &str,
    peer_addr: &str,
    rtt_ms: u32,
  ) -> Result<()> {
    EdgeClient::send_ice_quic_connected(
      self,
      ice_session_id,
      connection_id,
      local_addr,
      peer_addr,
      rtt_ms,
    )
    .await
  }

  async fn subscribe_logs<F>(&self, tail_lines: i32, handler: F) -> Result<LogSubscriptionResult>
  where
    F: Fn(Vec<String>) + Send + 'static,
  {
    EdgeClient::subscribe_logs(self, tail_lines, handler).await
  }

  async fn unsubscribe_logs(&self) -> Result<LogSubscriptionResult> {
    EdgeClient::unsubscribe_logs(self).await
  }
}

impl EdgeClient {
  /// 订阅 Tunnel 元数据事件推送
  pub async fn subscribe_tunnel_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(TunnelEventPushData) + Send + 'static,
  {
    let mut tunnel_handler = self.tunnel_event_handler.lock().await;
    *tunnel_handler = Some(Box::new(handler));
    Ok(())
  }

  /// 取消 Tunnel 元数据事件订阅
  pub async fn unsubscribe_tunnel_events(&self) -> Result<()> {
    let mut tunnel_handler = self.tunnel_event_handler.lock().await;
    *tunnel_handler = None;
    Ok(())
  }

  /// 订阅 WG Network 事件推送（network 级 snapshot）
  pub async fn subscribe_wg_network_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(WGNetworkEventPushData) + Send + 'static,
  {
    let mut wg_handler = self.wg_network_event_handler.lock().await;
    *wg_handler = Some(Box::new(handler));
    Ok(())
  }

  /// 取消 WG Network 事件订阅
  pub async fn unsubscribe_wg_network_events(&self) -> Result<()> {
    let mut wg_handler = self.wg_network_event_handler.lock().await;
    *wg_handler = None;
    Ok(())
  }

  /// 订阅 WG P2P 事件（Gather/Punch 推送）
  pub async fn subscribe_wg_p2p_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(super::WGP2PEvent) + Send + 'static,
  {
    let mut h = self.wg_p2p_handler.lock().await;
    *h = Some(Box::new(handler));
    Ok(())
  }

  /// 取消 WG P2P 事件订阅
  pub async fn unsubscribe_wg_p2p_events(&self) -> Result<()> {
    let mut h = self.wg_p2p_handler.lock().await;
    *h = None;
    Ok(())
  }

  /// 发送 WG Gather 响应
  pub async fn send_wg_gather_response(
    &self,
    session_id: &str,
    client_id: &str,
    local_addrs: &[String],
    public_addr: &str,
    nat_type: u8,
    local_wg_endpoint: &str,
  ) -> Result<()> {
    let mut builder = MessageBuilder::new();
    if let Some(sid) = self.session_id.read().await.clone() {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_gather_info_response(
      session_id,
      client_id,
      local_addrs,
      public_addr,
      nat_type,
      local_wg_endpoint,
    );
    log::debug!(
      "[WGP2P] sending gather response: session_id={} client_id={} local_wg_endpoint={} msg_len={}",
      session_id,
      client_id,
      local_wg_endpoint,
      msg.len()
    );
    let result = self.send_fire_and_forget(msg).await;
    log::debug!(
      "[WGP2P] gather response send result: {:?}",
      result.as_ref().map(|_| "ok").map_err(|e| e.to_string())
    );
    result
  }

  /// 发送 WG Punch 结果
  pub async fn send_wg_punch_response(
    &self,
    session_id: &str,
    client_id: &str,
    success: bool,
    connected_addr: &str,
  ) -> Result<()> {
    let mut builder = MessageBuilder::new();
    if let Some(sid) = self.session_id.read().await.clone() {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_punch_info_response(session_id, client_id, success, connected_addr);
    self.send_fire_and_forget(msg).await
  }

  /// 订阅 channel 连接活动事件（open/close）
  pub async fn subscribe_channel_connection_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(ChannelConnectionEventData) + Send + 'static,
  {
    let mut connection_handler = self.channel_connection_event_handler.lock().await;
    *connection_handler = Some(Box::new(handler));
    Ok(())
  }

  /// 取消 channel 连接活动事件订阅
  pub async fn unsubscribe_channel_connection_events(&self) -> Result<()> {
    let mut connection_handler = self.channel_connection_event_handler.lock().await;
    *connection_handler = None;
    Ok(())
  }

  pub async fn subscribe_ice_events<F>(&self, handler: F) -> Result<()>
  where
    F: Fn(IceMessage) + Send + 'static,
  {
    let mut ice_h = self.ice_handler.lock().await;
    *ice_h = Some(Box::new(handler));
    Ok(())
  }

  pub async fn unsubscribe_ice_events(&self) -> Result<()> {
    let mut ice_h = self.ice_handler.lock().await;
    *ice_h = None;
    Ok(())
  }

  pub async fn send_ice_punch_result(
    &self,
    ice_session_id: &str,
    success: bool,
    peer_observed_addr: &str,
    attempts_sent: u32,
    first_recv_at: u64,
    failure_reason: &str,
  ) -> Result<()> {
    let mut builder = MessageBuilder::new();
    if let Some(sid) = self.session_id.read().await.clone() {
      builder = builder.session_id(sid);
    }
    let msg = builder.ice_punch_result(
      ice_session_id,
      success,
      peer_observed_addr,
      attempts_sent,
      first_recv_at,
      failure_reason,
    );
    self.send_fire_and_forget(msg).await
  }

  pub async fn send_ice_quic_connected(
    &self,
    ice_session_id: &str,
    connection_id: &str,
    local_addr: &str,
    peer_addr: &str,
    rtt_ms: u32,
  ) -> Result<()> {
    let mut builder = MessageBuilder::new();
    if let Some(sid) = self.session_id.read().await.clone() {
      builder = builder.session_id(sid);
    }
    let msg =
      builder.ice_quic_connected(ice_session_id, connection_id, local_addr, peer_addr, rtt_ms);
    self.send_fire_and_forget(msg).await
  }

  /// 订阅日志
  pub async fn subscribe_logs<F>(
    &self,
    tail_lines: i32,
    handler: F,
  ) -> Result<LogSubscriptionResult>
  where
    F: Fn(Vec<String>) + Send + 'static,
  {
    // 1. 设置回调
    {
      let mut log_handler = self.log_handler.lock().await;
      *log_handler = Some(Box::new(handler));
    }

    // 2. 发送订阅请求
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.edge_log_request(true, tail_lines);

    let response_data = self
      .send_request(msg, seq, MessageType::EDGE_LOG_RESPONSE)
      .await?;
    let response = MessageReader::parse_edge_log_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(LogSubscriptionResult {
      success: response.success,
      error_message: response.error_message,
    })
  }

  /// 取消订阅日志
  pub async fn unsubscribe_logs(&self) -> Result<LogSubscriptionResult> {
    {
      let mut log_handler = self.log_handler.lock().await;
      *log_handler = None;
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.edge_log_request(false, 0);

    let response_data = self
      .send_request(msg, seq, MessageType::EDGE_LOG_RESPONSE)
      .await?;
    let response = MessageReader::parse_edge_log_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(LogSubscriptionResult {
      success: response.success,
      error_message: response.error_message,
    })
  }
}

impl EdgeClient {
  /// Passive status broadcasts share the authenticated ingress; solicited
  /// status responses still complete their request waiter first.
  pub async fn subscribe_edge_status_events<F>(&self, handler:F)->Result<()>
  where F:Fn(crate::EdgeStatusPushData)+Send+'static {
    *self.edge_status_handler.lock().await=Some(Box::new(handler));
    Ok(())
  }
}
