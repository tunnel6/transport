use super::EdgeClient;
use crate::error::{Result, TransportError};
use crate::protocol::message::{
  WGCreateInviteResponseData, WGCreateNetworkResponseData, WGDeleteNetworkResponseData,
  WGGetNetworkResponseData, WGJoinNetworkResponseData, WGLeaveNetworkResponseData,
  WGListAvailableDevicesResponseData, WGListNetworksResponseData, WGNetworkRuntimeResponseData,
  WGUpdateMemberResponseData, WGUpdateNetworkCIDRResponseData,
  WGUpdateNetworkRelayModeResponseData,
};
use crate::protocol::{MessageBuilder, MessageReader, MessageType};

#[allow(dead_code)]
pub(super) trait WGNetworkOps {
  async fn request_wg_list_networks(
    &self,
    include_deleted: bool,
  ) -> Result<WGListNetworksResponseData>;
  async fn request_wg_list_available_devices(
    &self,
    network_id: &str,
  ) -> Result<WGListAvailableDevicesResponseData>;
  async fn request_wg_get_network(&self, network_id: &str) -> Result<WGGetNetworkResponseData>;
  async fn request_wg_network_runtime(
    &self,
    network_id: &str,
  ) -> Result<WGNetworkRuntimeResponseData>;
  async fn create_wg_network(
    &self,
    network_id: &str,
    name: &str,
    cidr: &str,
    relay_mode: u8,
    description: &str,
    owner_user_id: &str,
    owner_username: &str,
  ) -> Result<WGCreateNetworkResponseData>;
  async fn join_wg_network(
    &self,
    network_id: &str,
    client_id: &str,
    public_key: &str,
    hostname: &str,
    invite_token: &str,
  ) -> Result<WGJoinNetworkResponseData>;
  async fn leave_wg_network(
    &self,
    network_id: &str,
    member_id: &str,
    temporary: bool,
  ) -> Result<WGLeaveNetworkResponseData>;
  async fn delete_wg_network(&self, network_id: &str) -> Result<WGDeleteNetworkResponseData>;
  async fn update_wg_network_cidr(
    &self,
    network_id: &str,
    new_cidr: &str,
  ) -> Result<WGUpdateNetworkCIDRResponseData>;
  async fn update_wg_network_relay_mode(
    &self,
    network_id: &str,
    relay_mode: u8,
  ) -> Result<WGUpdateNetworkRelayModeResponseData>;
  async fn update_wg_member(
    &self,
    network_id: &str,
    member_id: &str,
    new_ip: &str,
    new_hostname: &str,
  ) -> Result<WGUpdateMemberResponseData>;
}

impl WGNetworkOps for EdgeClient {
  async fn request_wg_list_networks(
    &self,
    include_deleted: bool,
  ) -> Result<WGListNetworksResponseData> {
    EdgeClient::request_wg_list_networks(self, include_deleted).await
  }

  async fn request_wg_list_available_devices(
    &self,
    network_id: &str,
  ) -> Result<WGListAvailableDevicesResponseData> {
    EdgeClient::request_wg_list_available_devices(self, network_id).await
  }

  async fn request_wg_get_network(&self, network_id: &str) -> Result<WGGetNetworkResponseData> {
    EdgeClient::request_wg_get_network(self, network_id).await
  }

  async fn request_wg_network_runtime(
    &self,
    network_id: &str,
  ) -> Result<WGNetworkRuntimeResponseData> {
    EdgeClient::request_wg_network_runtime(self, network_id).await
  }

  async fn create_wg_network(
    &self,
    network_id: &str,
    name: &str,
    cidr: &str,
    relay_mode: u8,
    description: &str,
    owner_user_id: &str,
    owner_username: &str,
  ) -> Result<WGCreateNetworkResponseData> {
    EdgeClient::create_wg_network(
      self,
      network_id,
      name,
      cidr,
      relay_mode,
      description,
      owner_user_id,
      owner_username,
    )
    .await
  }

  async fn join_wg_network(
    &self,
    network_id: &str,
    client_id: &str,
    public_key: &str,
    hostname: &str,
    invite_token: &str,
  ) -> Result<WGJoinNetworkResponseData> {
    EdgeClient::join_wg_network(
      self,
      network_id,
      client_id,
      public_key,
      hostname,
      invite_token,
    )
    .await
  }

  async fn leave_wg_network(
    &self,
    network_id: &str,
    member_id: &str,
    temporary: bool,
  ) -> Result<WGLeaveNetworkResponseData> {
    EdgeClient::leave_wg_network(self, network_id, member_id, temporary).await
  }

  async fn delete_wg_network(&self, network_id: &str) -> Result<WGDeleteNetworkResponseData> {
    EdgeClient::delete_wg_network(self, network_id).await
  }

  async fn update_wg_network_cidr(
    &self,
    network_id: &str,
    new_cidr: &str,
  ) -> Result<WGUpdateNetworkCIDRResponseData> {
    EdgeClient::update_wg_network_cidr(self, network_id, new_cidr).await
  }

  async fn update_wg_network_relay_mode(
    &self,
    network_id: &str,
    relay_mode: u8,
  ) -> Result<WGUpdateNetworkRelayModeResponseData> {
    EdgeClient::update_wg_network_relay_mode(self, network_id, relay_mode).await
  }

  async fn update_wg_member(
    &self,
    network_id: &str,
    member_id: &str,
    new_ip: &str,
    new_hostname: &str,
  ) -> Result<WGUpdateMemberResponseData> {
    EdgeClient::update_wg_member(self, network_id, member_id, new_ip, new_hostname).await
  }
}

impl EdgeClient {
  pub async fn request_wg_list_networks(
    &self,
    include_deleted: bool,
  ) -> Result<WGListNetworksResponseData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_list_networks_request(include_deleted);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_LIST_NETWORKS_ACK)
      .await?;
    MessageReader::parse_wg_list_networks_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn request_wg_list_available_devices(
    &self,
    network_id: &str,
  ) -> Result<WGListAvailableDevicesResponseData> {
    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_list_available_devices_request(network_id);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_LIST_AVAILABLE_DEVICES_ACK)
      .await?;
    MessageReader::parse_wg_list_available_devices_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn request_wg_get_network(&self, network_id: &str) -> Result<WGGetNetworkResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_get_network_request(normalized_network_id);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_GET_NETWORK_ACK)
      .await?;
    MessageReader::parse_wg_get_network_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn request_wg_network_runtime(
    &self,
    network_id: &str,
  ) -> Result<WGNetworkRuntimeResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_network_runtime_request(normalized_network_id);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_NETWORK_RUNTIME_RESPONSE)
      .await?;
    MessageReader::parse_wg_network_runtime_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn create_wg_network(
    &self,
    network_id: &str,
    name: &str,
    cidr: &str,
    relay_mode: u8,
    description: &str,
    owner_user_id: &str,
    owner_username: &str,
  ) -> Result<WGCreateNetworkResponseData> {
    let normalized_network_id = network_id.trim();
    let normalized_name = name.trim();
    let normalized_cidr = cidr.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }
    if normalized_name.is_empty() {
      return Err(TransportError::Protocol("name is required".to_string()));
    }
    if normalized_cidr.is_empty() {
      return Err(TransportError::Protocol("cidr is required".to_string()));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_create_network_request(
      normalized_network_id,
      normalized_name,
      normalized_cidr,
      relay_mode,
      description.trim(),
      owner_user_id,
      owner_username,
    );

    let response_data = self
      .send_request(msg, seq, MessageType::WG_CREATE_NETWORK_ACK)
      .await?;
    MessageReader::parse_wg_create_network_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn join_wg_network(
    &self,
    network_id: &str,
    client_id: &str,
    public_key: &str,
    hostname: &str,
    invite_token: &str,
  ) -> Result<WGJoinNetworkResponseData> {
    let normalized_network_id = network_id.trim();
    let normalized_client_id = client_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }
    if normalized_client_id.is_empty() {
      return Err(TransportError::Protocol(
        "client_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_join_network_request(
      normalized_network_id,
      normalized_client_id,
      public_key.trim(),
      hostname.trim(),
      invite_token.trim(),
    );

    let response_data = self
      .send_request(msg, seq, MessageType::WG_JOIN_NETWORK_ACK)
      .await?;
    MessageReader::parse_wg_join_network_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  /// 创建邀请 token（仅 network owner 可调用）
  pub async fn create_wg_invite(
    &self,
    network_id: &str,
    expires_in_secs: u32,
    max_uses: u32,
  ) -> Result<WGCreateInviteResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_create_invite_request(normalized_network_id, expires_in_secs, max_uses);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_CREATE_INVITE_ACK)
      .await?;
    MessageReader::parse_wg_create_invite_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn leave_wg_network(
    &self,
    network_id: &str,
    member_id: &str,
    temporary: bool,
  ) -> Result<WGLeaveNetworkResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_leave_network_request(normalized_network_id, member_id.trim(), temporary);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_LEAVE_NETWORK_ACK)
      .await?;
    MessageReader::parse_wg_leave_network_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn delete_wg_network(&self, network_id: &str) -> Result<WGDeleteNetworkResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_delete_network_request(normalized_network_id);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_DELETE_NETWORK_ACK)
      .await?;
    MessageReader::parse_wg_delete_network_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn update_wg_network_cidr(
    &self,
    network_id: &str,
    new_cidr: &str,
  ) -> Result<WGUpdateNetworkCIDRResponseData> {
    let normalized_network_id = network_id.trim();
    let normalized_cidr = new_cidr.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }
    if normalized_cidr.is_empty() {
      return Err(TransportError::Protocol("new_cidr is required".to_string()));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_update_network_cidr_request(normalized_network_id, normalized_cidr);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_UPDATE_NETWORK_CIDR_ACK)
      .await?;
    MessageReader::parse_wg_update_network_cidr_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn update_wg_network_relay_mode(
    &self,
    network_id: &str,
    relay_mode: u8,
  ) -> Result<WGUpdateNetworkRelayModeResponseData> {
    let normalized_network_id = network_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_update_network_relay_mode_request(normalized_network_id, relay_mode);

    let response_data = self
      .send_request(msg, seq, MessageType::WG_UPDATE_NETWORK_RELAY_MODE_ACK)
      .await?;
    MessageReader::parse_wg_update_network_relay_mode_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }

  pub async fn update_wg_member(
    &self,
    network_id: &str,
    member_id: &str,
    new_ip: &str,
    new_hostname: &str,
  ) -> Result<WGUpdateMemberResponseData> {
    let normalized_network_id = network_id.trim();
    let normalized_member_id = member_id.trim();
    if normalized_network_id.is_empty() {
      return Err(TransportError::Protocol(
        "network_id is required".to_string(),
      ));
    }
    if normalized_member_id.is_empty() {
      return Err(TransportError::Protocol(
        "member_id is required".to_string(),
      ));
    }
    if new_ip.trim().is_empty() && new_hostname.trim().is_empty() {
      return Err(TransportError::Protocol(
        "at least one of new_ip or new_hostname is required".to_string(),
      ));
    }

    let seq = self.next_seq();
    let session_id = self.session_id.read().await.clone();

    let mut builder = MessageBuilder::new().seq(seq);
    if let Some(sid) = session_id {
      builder = builder.session_id(sid);
    }
    let msg = builder.wg_update_member_request(
      normalized_network_id,
      normalized_member_id,
      new_ip.trim(),
      new_hostname.trim(),
    );

    let response_data = self
      .send_request(msg, seq, MessageType::WG_UPDATE_MEMBER_ACK)
      .await?;
    MessageReader::parse_wg_update_member_response(&response_data)
      .map_err(|e| TransportError::Protocol(e.to_string()))
  }
}
