use super::{EdgeClient, EdgeOperationResult};
use crate::error::{Result, TransportError};
use crate::protocol::message::EdgeChannelStatusData;
use crate::protocol::{EdgeStatusPushData, MessageBuilder, MessageReader, MessageType};

/// `EdgeOps` 定义 Edge 级别控制面操作。
///
/// 职责边界：
/// - Edge 上线/下线生命周期控制；
/// - Edge 状态拉取与本地流量统计聚合。
#[allow(dead_code)]
pub(super) trait EdgeOps {
  async fn edge_online(&self) -> Result<EdgeOperationResult>;
  async fn edge_offline(&self) -> Result<EdgeOperationResult>;
  async fn request_edge_status(&self) -> Result<EdgeStatusPushData>;
}

impl EdgeOps for EdgeClient {
  async fn edge_online(&self) -> Result<EdgeOperationResult> {
    EdgeClient::edge_online(self).await
  }

  async fn edge_offline(&self) -> Result<EdgeOperationResult> {
    EdgeClient::edge_offline(self).await
  }

  async fn request_edge_status(&self) -> Result<EdgeStatusPushData> {
    EdgeClient::request_edge_status(self).await
  }
}

impl EdgeClient {
  /// Success means the Edge has durably saved the management patch.
  /// An empty JSON string reads the current saved configuration.
  pub async fn edge_config(&self, config_json: &str) -> Result<super::EdgeConfigResult> {
    let seq = self.next_seq();
    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = self.session_id.read().await.clone() { builder = builder.session_id(sid); }
    let request = builder.edge_config_request(config_json);
    let data = self.send_request(request, seq, MessageType::EDGE_CONFIG_RESPONSE).await?;
    let message = crate::protocol::generated::message::root_as_message(&data)
      .map_err(|_| TransportError::Protocol("invalid Edge config response".into()))?;
    let response = message.body_as_edge_config_response()
      .ok_or_else(|| TransportError::Protocol("missing Edge config response".into()))?;
    Ok(super::EdgeConfigResult { success: response.success(),
      config_json: response.config_json().unwrap_or("").to_string(),
      restart_required: response.restart_required(),
      error_message: response.error_message().unwrap_or("").to_string() })
  }

  /// Import a wildcard certificate over the authenticated management session.
  pub async fn upload_domain_certificate(&self, domain: &str, certificate_pem: &str, private_key_pem: &str) -> Result<EdgeOperationResult> {
    let seq = self.next_seq();
    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = self.session_id.read().await.clone() { builder = builder.session_id(sid); }
    let request = builder.edge_domain_certificate_request(domain, certificate_pem, private_key_pem);
    let data = self.send_request(request, seq, MessageType::EDGE_DOMAIN_CERTIFICATE_RESPONSE).await?;
    let message = crate::protocol::generated::message::root_as_message(&data)
      .map_err(|_| TransportError::Protocol("invalid certificate response".into()))?;
    let response = message.body_as_edge_domain_certificate_response()
      .ok_or_else(|| TransportError::Protocol("missing certificate response".into()))?;
    Ok(EdgeOperationResult { success: response.success(), error_code: 0,
      error_message: response.error_message().unwrap_or("").to_string() })
  }

  /// Edge 上线请求
  pub async fn edge_online(&self) -> Result<EdgeOperationResult> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.edge_online_request();

    let response_data = self
      .send_request(msg, seq, MessageType::EDGE_ONLINE_RESPONSE)
      .await?;
    let response = MessageReader::parse_edge_online_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(EdgeOperationResult {
      success: response.success,
      error_code: response.error_code,
      error_message: response.error_message,
    })
  }

  /// Edge 下线请求
  pub async fn edge_offline(&self) -> Result<EdgeOperationResult> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.edge_offline_request();

    let response_data = self
      .send_request(msg, seq, MessageType::EDGE_OFFLINE_RESPONSE)
      .await?;
    let response = MessageReader::parse_edge_offline_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(EdgeOperationResult {
      success: response.success,
      error_code: response.error_code,
      error_message: response.error_message,
    })
  }

  /// 请求 Edge 状态
  pub async fn request_edge_status(&self) -> Result<EdgeStatusPushData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.edge_status_request(2); // detail_level=2 for full info

    let response_data = self
      .send_request(msg, seq, MessageType::EDGE_STATUS_PUSH)
      .await?;
    let mut response = MessageReader::parse_edge_status_push(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    // Tunnel 流量统计以 transport 本地收发路径为准，覆盖 channel bytes。
    let local_traffic = self.channel_traffic.lock().await.clone();
    let local_channels = self.channels.lock().await.clone();
    let server_total_bytes_in = response.total_bytes_in;
    let server_total_bytes_out = response.total_bytes_out;

    for channel in response.channels.iter_mut() {
      if let Some(local) = local_traffic.get(&channel.channel_id) {
        channel.bytes_in = local.bytes_in;
        channel.bytes_out = local.bytes_out;
      }
    }

    // 当服务端未返回 channel 列表（例如非 owner 视图）时，
    // 使用 transport 本地统计补充 channels，保证 tunnel 维度可用。
    for (channel_id, local) in local_traffic.iter() {
      if response
        .channels
        .iter()
        .any(|ch| ch.channel_id == *channel_id)
      {
        continue;
      }
      if local.bytes_in == 0 && local.bytes_out == 0 {
        continue;
      }

      let local_info = local_channels.get(channel_id);
      response.channels.push(EdgeChannelStatusData {
        channel_id: channel_id.clone(),
        session_id: String::new(),
        user_id: String::new(),
        device_id: String::new(),
        actor_role: 0,
        actor_session_id: String::new(),
        actor_device_id: String::new(),
        domain: String::new(),
        subdomain: String::new(),
        alias_domain: String::new(),
        channel_key: channel_id.clone(),
        protocol: local_info
          .map(|info| info.protocol.clone())
          .unwrap_or_else(|| "tcp".to_string()),
        link_type: local_info
          .map(|info| info.link_type.clone())
          .unwrap_or_else(|| "relay".to_string()),
        remote_endpoint: local_info
          .map(|info| info.remote_endpoint.clone())
          .unwrap_or_default(),
        local_addr: local_info
          .map(|info| info.local_addr.clone())
          .unwrap_or_default(),
        state: "active".to_string(),
        bytes_in: local.bytes_in,
        bytes_out: local.bytes_out,
        connections: 0,
        active_conns: 0,
        domain_status: None,
        alias_domain_status: None,
      });
    }

    if response.channels.is_empty() {
      // 若仍无 channel 维度数据，保留服务端 total，避免展示回落为 0。
      response.total_bytes_in = server_total_bytes_in;
      response.total_bytes_out = server_total_bytes_out;
    } else {
      response.total_bytes_in = response
        .channels
        .iter()
        .fold(0_u64, |acc, item| acc.saturating_add(item.bytes_in));
      response.total_bytes_out = response
        .channels
        .iter()
        .fold(0_u64, |acc, item| acc.saturating_add(item.bytes_out));
    }

    Ok(response)
  }
}
