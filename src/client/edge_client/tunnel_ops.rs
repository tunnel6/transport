use super::tcp_bridge::TcpBridge;
use super::udp_assoc::UdpAssocOps;
use super::{ChannelInfo, ChannelTrafficStats, EdgeClient, DEFAULT_CHANNEL_BUFFER_SIZE};
use crate::client::utils::resolve_local_channel_link_type;
use crate::error::{Result, TransportError};
use crate::protocol::message::{
  TunnelActorContextData, TunnelChannelStartSpecData, TunnelDefinitionData,
  TunnelDeleteResponseData, TunnelStartResponseData, TunnelStatusResponseData,
  TunnelStopResponseData, TunnelSyncResponseData, TunnelUpsertResponseData,
};
use crate::protocol::{MessageBuilder, MessageReader, MessageType};

/// `TunnelOps` 定义 Tunnel 级别控制面操作。
///
/// 职责边界：
/// - Tunnel 状态查询；
/// - 定义同步/写入/删除；
/// - Tunnel 启停及本地资源同步清理。
#[allow(dead_code)]
pub(super) trait TunnelOps {
  async fn request_tunnel_status(&self, tunnel_id: &str) -> Result<TunnelStatusResponseData>;

  async fn request_tunnel_sync(
    &self,
    edge_id: Option<&str>,
    since_revision: u64,
    limit: u32,
    include_deleted: bool,
  ) -> Result<TunnelSyncResponseData>;

  async fn upsert_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    if_match_revision: u64,
    definition: &TunnelDefinitionData,
  ) -> Result<TunnelUpsertResponseData>;

  async fn delete_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    tunnel_id: &str,
    if_match_revision: u64,
  ) -> Result<TunnelDeleteResponseData>;

  async fn start_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
    definition_if_match_revision: Option<u64>,
    definition: Option<&TunnelDefinitionData>,
  ) -> Result<TunnelStartResponseData>;

  async fn stop_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData>;

  async fn join_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
  ) -> Result<TunnelStartResponseData>;

  async fn leave_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData>;
}

impl TunnelOps for EdgeClient {
  async fn request_tunnel_status(&self, tunnel_id: &str) -> Result<TunnelStatusResponseData> {
    EdgeClient::request_tunnel_status(self, tunnel_id).await
  }

  async fn request_tunnel_sync(
    &self,
    edge_id: Option<&str>,
    since_revision: u64,
    limit: u32,
    include_deleted: bool,
  ) -> Result<TunnelSyncResponseData> {
    EdgeClient::request_tunnel_sync(self, edge_id, since_revision, limit, include_deleted).await
  }

  async fn upsert_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    if_match_revision: u64,
    definition: &TunnelDefinitionData,
  ) -> Result<TunnelUpsertResponseData> {
    EdgeClient::upsert_tunnel_definition(self, edge_id, if_match_revision, definition).await
  }

  async fn delete_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    tunnel_id: &str,
    if_match_revision: u64,
  ) -> Result<TunnelDeleteResponseData> {
    EdgeClient::delete_tunnel_definition(self, edge_id, tunnel_id, if_match_revision).await
  }

  async fn start_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
    definition_if_match_revision: Option<u64>,
    definition: Option<&TunnelDefinitionData>,
  ) -> Result<TunnelStartResponseData> {
    EdgeClient::start_tunnel(
      self,
      tunnel_id,
      edge_id,
      mode,
      actor_role,
      actor_session_id,
      actor_device_id,
      channels,
      reconnect,
      definition_if_match_revision,
      definition,
    )
    .await
  }

  async fn stop_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData> {
    EdgeClient::stop_tunnel(
      self,
      tunnel_id,
      edge_id,
      mode,
      actor_role,
      actor_session_id,
      actor_device_id,
      keys,
      reason,
    )
    .await
  }

  async fn join_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
  ) -> Result<TunnelStartResponseData> {
    EdgeClient::join_tunnel(
      self,
      tunnel_id,
      edge_id,
      mode,
      actor_role,
      actor_session_id,
      actor_device_id,
      channels,
      reconnect,
    )
    .await
  }

  async fn leave_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData> {
    EdgeClient::leave_tunnel(
      self,
      tunnel_id,
      edge_id,
      mode,
      actor_role,
      actor_session_id,
      actor_device_id,
      keys,
      reason,
    )
    .await
  }
}

impl EdgeClient {
  fn normalize_tunnel_actor_context(
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
  ) -> Option<TunnelActorContextData> {
    let normalized_role = actor_role.filter(|role| matches!(*role, 1 | 2 | 3));
    let normalized_session_id = actor_session_id
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .map(str::to_string);
    let normalized_device_id = actor_device_id
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .map(str::to_string);

    if normalized_role.is_none()
      && normalized_session_id.is_none()
      && normalized_device_id.is_none()
    {
      return None;
    }

    Some(TunnelActorContextData {
      role: normalized_role.unwrap_or(1),
      session_id: normalized_session_id.unwrap_or_default(),
      device_id: normalized_device_id.unwrap_or_default(),
    })
  }

  pub(crate) fn resolve_stop_result_channel_id(
    tunnel_id: &str,
    channel_id: &str,
    channel_key: &str,
  ) -> Option<String> {
    let normalized_channel_id = channel_id.trim();
    if !normalized_channel_id.is_empty() {
      return Some(normalized_channel_id.to_string());
    }
    let normalized_key = channel_key.trim();
    if normalized_key.is_empty() {
      return None;
    }
    Some(format!("{}:{}", tunnel_id.trim(), normalized_key))
  }

  /// 请求单 Tunnel 状态
  pub async fn request_tunnel_status(&self, tunnel_id: &str) -> Result<TunnelStatusResponseData> {
    let normalized_tunnel_id = tunnel_id.trim();
    if normalized_tunnel_id.is_empty() {
      return Err(TransportError::Protocol(
        "tunnel_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_status_request(normalized_tunnel_id, 2);

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_STATUS_RESPONSE)
      .await?;
    let mut response = MessageReader::parse_tunnel_status_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    let local_traffic = self.channel_traffic.lock().await.clone();
    let mut local_total_in = 0_u64;
    let mut local_total_out = 0_u64;
    for (channel_id, local) in local_traffic.iter() {
      if !(channel_id == normalized_tunnel_id
        || channel_id.starts_with(&format!("{normalized_tunnel_id}:")))
      {
        continue;
      }
      local_total_in = local_total_in.saturating_add(local.bytes_in);
      local_total_out = local_total_out.saturating_add(local.bytes_out);
    }

    if local_total_in > 0 || local_total_out > 0 {
      response.total_bytes_in = local_total_in;
      response.total_bytes_out = local_total_out;
    }

    Ok(response)
  }

  /// 请求 Tunnel 定义增量同步
  pub async fn request_tunnel_sync(
    &self,
    edge_id: Option<&str>,
    since_revision: u64,
    limit: u32,
    include_deleted: bool,
  ) -> Result<TunnelSyncResponseData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_sync_request(edge_id, since_revision, limit, include_deleted);

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_SYNC_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_sync_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(response)
  }

  /// 写入/更新 Tunnel 定义
  pub async fn upsert_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    if_match_revision: u64,
    definition: &TunnelDefinitionData,
  ) -> Result<TunnelUpsertResponseData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_upsert_request(edge_id, if_match_revision, definition);

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_UPSERT_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_upsert_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(response)
  }

  /// 删除 Tunnel 定义（软删除）
  pub async fn delete_tunnel_definition(
    &self,
    edge_id: Option<&str>,
    tunnel_id: &str,
    if_match_revision: u64,
  ) -> Result<TunnelDeleteResponseData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_delete_request(edge_id, tunnel_id, if_match_revision);

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_DELETE_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_delete_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    Ok(response)
  }

  /// 启动 Tunnel（批量 channel）
  pub async fn start_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
    definition_if_match_revision: Option<u64>,
    definition: Option<&TunnelDefinitionData>,
  ) -> Result<TunnelStartResponseData> {
    let normalized_tunnel_id = tunnel_id.trim();
    if normalized_tunnel_id.is_empty() {
      return Err(TransportError::Protocol(
        "tunnel_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();
    let actor = Self::normalize_tunnel_actor_context(actor_role, actor_session_id, actor_device_id);

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id.as_ref() {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_start_request(
      normalized_tunnel_id,
      edge_id,
      mode,
      actor.as_ref(),
      channels,
      reconnect,
      definition_if_match_revision.unwrap_or(0),
      definition,
    );

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_START_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_start_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if response.success || response.summary.succeeded > 0 {
      let mut channels_guard = self.channels.lock().await;
      let mut traffic_guard = self.channel_traffic.lock().await;

      for result in response.channels.iter().filter(|item| item.success) {
        let matched_spec = channels.iter().find(|spec| spec.key == result.key);
        let channel_id = if !result.channel_id.trim().is_empty() {
          result.channel_id.clone()
        } else {
          format!("{}:{}", normalized_tunnel_id, result.key)
        };

        let local_addr = if let Some(spec) = matched_spec {
          let host = if spec.local_host.trim().is_empty() {
            "127.0.0.1"
          } else {
            spec.local_host.trim()
          };
          format!("{}:{}", host, spec.local_port)
        } else {
          String::new()
        };

        let requested_buffer = matched_spec
          .map(|spec| spec.buffer_size as usize)
          .unwrap_or(DEFAULT_CHANNEL_BUFFER_SIZE);
        let negotiated_buffer = if result.negotiated_buffer_size > 0 {
          result.negotiated_buffer_size as usize
        } else {
          requested_buffer
        };
        let protocol = matched_spec
          .map(|spec| spec.protocol.to_lowercase())
          .unwrap_or_else(|| "tcp".to_string());
        let link_type = matched_spec
          .map(|spec| resolve_local_channel_link_type(&spec.transport, &spec.metadata_json))
          .unwrap_or_else(|| "relay".to_string());

        channels_guard.insert(
          channel_id.clone(),
          ChannelInfo {
            local_addr,
            remote_endpoint: result.remote_endpoint.trim().to_string(),
            buffer_size: Self::normalize_buffer_size(negotiated_buffer),
            dynamic_window: true,
            protocol,
            link_type: link_type.clone(),
          },
        );
        traffic_guard
          .entry(channel_id.clone())
          .or_insert_with(ChannelTrafficStats::default);
      }

      drop(channels_guard);
      drop(traffic_guard);
    }

    Ok(response)
  }

  /// 停止 Tunnel（可选 selective keys）
  pub async fn stop_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData> {
    let normalized_tunnel_id = tunnel_id.trim();
    if normalized_tunnel_id.is_empty() {
      return Err(TransportError::Protocol(
        "tunnel_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();
    let actor = Self::normalize_tunnel_actor_context(actor_role, actor_session_id, actor_device_id);

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_stop_request(
      normalized_tunnel_id,
      edge_id,
      mode,
      actor.as_ref(),
      keys,
      reason,
    );

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_STOP_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_stop_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if response.success || response.summary.succeeded > 0 {
      let mut channels_guard = self.channels.lock().await;
      let mut traffic_guard = self.channel_traffic.lock().await;
      let mut success_channel_ids = Vec::new();

      for result in response.channels.iter().filter(|item| item.success) {
        let Some(channel_id) = Self::resolve_stop_result_channel_id(
          normalized_tunnel_id,
          result.channel_id.as_str(),
          result.key.as_str(),
        ) else {
          continue;
        };
        channels_guard.remove(&channel_id);
        traffic_guard.remove(&channel_id);
        success_channel_ids.push(channel_id);
      }
      drop(channels_guard);
      drop(traffic_guard);

      for channel_id in success_channel_ids {
        <Self as TcpBridge>::shutdown_tcp_connections_for_channel(
          self.connections.clone(),
          &channel_id,
          0x02,
        )
        .await;
        <Self as UdpAssocOps>::shutdown_udp_associations_for_channel(
          self.udp_associations.clone(),
          &channel_id,
        )
        .await;
      }
    }

    Ok(response)
  }

  /// 加入 Tunnel 协商（consumer/controller）
  pub async fn join_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
  ) -> Result<TunnelStartResponseData> {
    let normalized_tunnel_id = tunnel_id.trim();
    if normalized_tunnel_id.is_empty() {
      return Err(TransportError::Protocol(
        "tunnel_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();
    let actor = Self::normalize_tunnel_actor_context(actor_role, actor_session_id, actor_device_id);

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id.as_ref() {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_join_request(
      normalized_tunnel_id,
      edge_id,
      mode,
      actor.as_ref(),
      channels,
      reconnect,
    );

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_JOIN_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_join_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if response.success || response.summary.succeeded > 0 {
      let mut channels_guard = self.channels.lock().await;
      let mut traffic_guard = self.channel_traffic.lock().await;

      for result in response.channels.iter().filter(|item| item.success) {
        let matched_spec = channels.iter().find(|spec| spec.key == result.key);
        let channel_id = if !result.channel_id.trim().is_empty() {
          result.channel_id.clone()
        } else {
          format!("{}:{}", normalized_tunnel_id, result.key)
        };

        let local_addr = if let Some(spec) = matched_spec {
          let host = if spec.local_host.trim().is_empty() {
            "127.0.0.1"
          } else {
            spec.local_host.trim()
          };
          format!("{}:{}", host, spec.local_port)
        } else {
          String::new()
        };

        let requested_buffer = matched_spec
          .map(|spec| spec.buffer_size as usize)
          .unwrap_or(DEFAULT_CHANNEL_BUFFER_SIZE);
        let negotiated_buffer = if result.negotiated_buffer_size > 0 {
          result.negotiated_buffer_size as usize
        } else {
          requested_buffer
        };
        let protocol = matched_spec
          .map(|spec| spec.protocol.to_lowercase())
          .unwrap_or_else(|| "tcp".to_string());
        let link_type = matched_spec
          .map(|spec| resolve_local_channel_link_type(&spec.transport, &spec.metadata_json))
          .unwrap_or_else(|| "relay".to_string());

        channels_guard.insert(
          channel_id.clone(),
          ChannelInfo {
            local_addr,
            remote_endpoint: result.remote_endpoint.trim().to_string(),
            buffer_size: Self::normalize_buffer_size(negotiated_buffer),
            dynamic_window: true,
            protocol,
            link_type: link_type.clone(),
          },
        );
        traffic_guard
          .entry(channel_id.clone())
          .or_insert_with(ChannelTrafficStats::default);
      }

      drop(channels_guard);
      drop(traffic_guard);
    }

    Ok(response)
  }

  /// 离开 Tunnel 协商（session-local）
  pub async fn leave_tunnel(
    &self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor_role: Option<u8>,
    actor_session_id: Option<&str>,
    actor_device_id: Option<&str>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Result<TunnelStopResponseData> {
    let normalized_tunnel_id = tunnel_id.trim();
    if normalized_tunnel_id.is_empty() {
      return Err(TransportError::Protocol(
        "tunnel_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();
    let actor = Self::normalize_tunnel_actor_context(actor_role, actor_session_id, actor_device_id);

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.tunnel_leave_request(
      normalized_tunnel_id,
      edge_id,
      mode,
      actor.as_ref(),
      keys,
      reason,
    );

    let response_data = self
      .send_request(msg, seq, MessageType::TUNNEL_LEAVE_RESPONSE)
      .await?;
    let response = MessageReader::parse_tunnel_leave_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))?;

    if response.success || response.summary.succeeded > 0 {
      let mut channels_guard = self.channels.lock().await;
      let mut traffic_guard = self.channel_traffic.lock().await;
      let mut success_channel_ids = Vec::new();

      for result in response.channels.iter().filter(|item| item.success) {
        let Some(channel_id) = Self::resolve_stop_result_channel_id(
          normalized_tunnel_id,
          result.channel_id.as_str(),
          result.key.as_str(),
        ) else {
          continue;
        };
        channels_guard.remove(&channel_id);
        traffic_guard.remove(&channel_id);
        success_channel_ids.push(channel_id);
      }
      drop(channels_guard);
      drop(traffic_guard);

      for channel_id in success_channel_ids {
        <Self as TcpBridge>::shutdown_tcp_connections_for_channel(
          self.connections.clone(),
          &channel_id,
          0x02,
        )
        .await;
        <Self as UdpAssocOps>::shutdown_udp_associations_for_channel(
          self.udp_associations.clone(),
          &channel_id,
        )
        .await;
      }
    }

    Ok(response)
  }
}
