//! 高级消息 API 封装
//!
//! 提供更友好的消息构建和读取接口
//!
//! 客户端角色：
//! - Request: 只构建，不解析
//! - Response: 只解析，不构建

use flatbuffers::{FlatBufferBuilder, WIPOffset};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "wg_path.rs"]
mod wg_path;

use super::generated::message::{
  self,
  // Auth
  AuthRequest,
  AuthRequestArgs,
  // Cert
  CertRequest,
  CertRequestArgs,
  // Data
  DataPacket,
  DataPacketArgs,
  // Log
  EdgeLogRequest,
  EdgeLogRequestArgs,
  EdgeOfflineRequest,
  EdgeOfflineRequestArgs,
  // Edge Control
  EdgeOnlineRequest,
  EdgeOnlineRequestArgs,
  // Edge Status
  EdgeStatusRequest,
  EdgeStatusRequestArgs,
  HTTPHeader,
  HTTPHeaderArgs,
  // Heartbeat
  Heartbeat,
  HeartbeatArgs,
  // ICE
  ICEPunchResult,
  ICEPunchResultArgs,
  ICEQuicConnected,
  ICEQuicConnectedArgs,
  Message,
  MessageArgs,
  MessageBody,
  MessageHeader,
  MessageHeaderArgs,
  MessageType,
  // Push (HTTP Proxy)
  PushResponse,
  PushResponseArgs,
  // Tunnel metadata sync
  TunnelActorContext,
  TunnelActorContextArgs,
  TunnelActorRole,
  TunnelChannelStartSpec,
  TunnelChannelStartSpecArgs,
  TunnelDefinitionInfo,
  TunnelDefinitionInfoArgs,
  TunnelDeleteRequest,
  TunnelDeleteRequestArgs,
  TunnelJoinRequest,
  TunnelJoinRequestArgs,
  TunnelLeaveRequest,
  TunnelLeaveRequestArgs,
  TunnelStartMode,
  TunnelStartRequest,
  TunnelStartRequestArgs,
  TunnelStatusRequest,
  TunnelStatusRequestArgs,
  TunnelStopRequest,
  TunnelStopRequestArgs,
  TunnelSyncRequest,
  TunnelSyncRequestArgs,
  TunnelUpsertRequest,
  TunnelUpsertRequestArgs,
  WGCreateInviteRequest,
  WGCreateInviteRequestArgs,
  WGCreateNetworkRequest,
  WGCreateNetworkRequestArgs,
  WGDeleteNetworkRequest,
  WGDeleteNetworkRequestArgs,
  WGGatherInfo,
  WGGatherInfoArgs,
  WGGetNetworkRequest,
  WGGetNetworkRequestArgs,
  WGJoinNetworkRequest,
  WGJoinNetworkRequestArgs,
  WGLeaveNetworkRequest,
  WGLeaveNetworkRequestArgs,
  WGListAvailableDevicesRequest,
  WGListAvailableDevicesRequestArgs,
  WGListNetworksRequest,
  WGListNetworksRequestArgs,
  WGNetworkRuntimeRequest,
  WGNetworkRuntimeRequestArgs,
  WGPunchInfo,
  WGPunchInfoArgs,
  WGUpdateMemberRequest,
  WGUpdateMemberRequestArgs,
  WGUpdateNetworkCIDRRequest,
  WGUpdateNetworkCIDRRequestArgs,
  WGUpdateNetworkRelayModeRequest,
  WGUpdateNetworkRelayModeRequestArgs,
};

// ==================== 响应解析结果类型 ====================

/// 认证响应结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthResponseData {
  pub success: bool,
  pub session_id: String,
  pub server_version: String,
  pub error_code: u32,
  pub error_message: String,
  pub server_time: u64,
  pub negotiated_protocol_major: u16,
  pub negotiated_protocol_minor: u16,
  pub accepted_features: Vec<String>,
  pub rejected_features: Vec<String>,
  pub compatibility_level: u8,
  pub reason_code: u16,
}

/// 心跳响应结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HeartbeatAckData {
  pub server_time: u64,
}

/// Edge 上线响应结果
#[derive(Debug, Clone)]
pub struct EdgeOnlineResponseData {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// Edge 下线响应结果
#[derive(Debug, Clone)]
pub struct EdgeOfflineResponseData {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// 日志响应结果
#[derive(Debug, Clone)]
pub struct EdgeLogResponseData {
  pub success: bool,
  pub error_message: String,
}

/// 日志推送数据
#[derive(Debug, Clone)]
pub struct EdgeLogPushData {
  pub log_lines: Vec<String>,
}

/// 域名状态信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeDomainStatusData {
  pub dns_status: u8,
  pub cert_status: u8,
  pub error: String,
  pub cert_last_error: String,
  pub updated_at: u64,
}

/// DNS-01 挑战信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct DNS01ChallengeData {
  pub record_name: String,
  pub record_value: String,
  pub domain: String,
  pub created_at: u64,
  pub last_error: String,
  pub updated_at: u64,
}

/// 域名引导记录
#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainRecordData {
  pub record_type: u8,
  pub record_name: String,
  pub record_value: String,
  pub ttl: u32,
  pub source: String,
}

/// 统一域名运行态
#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainRuntimeData {
  pub owner_view: bool,
  pub state: u8,
  pub required_records: Vec<DomainRecordData>,
  pub pending_reason_code: String,
  pub last_error: String,
  pub cname_status: u8,
  pub cert_status: u8,
  pub updated_at: u64,
}

/// Channel 维度域名状态信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeChannelStatusData {
  pub channel_id: String,
  pub session_id: String,
  pub user_id: String,
  pub device_id: String,
  pub actor_role: u8,
  pub actor_session_id: String,
  pub actor_device_id: String,
  pub domain: String,
  pub subdomain: String,
  pub alias_domain: String,
  pub channel_key: String,
  pub protocol: String,
  pub link_type: String,
  pub remote_endpoint: String,
  pub local_addr: String,
  pub state: String,
  pub bytes_in: u64,
  pub bytes_out: u64,
  pub connections: u32,
  pub active_conns: i32,
  pub domain_status: Option<EdgeDomainStatusData>,
  pub alias_domain_status: Option<EdgeDomainStatusData>,
}

/// Actual port configuration reported by the Edge. Absent on older servers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgePortUsageData {
  pub tcp_used: i32,
  pub tcp_total: i32,
  pub tcp_range: String,
  pub udp_used: i32,
  pub udp_total: i32,
  pub udp_range: String,
  pub http_port: u16,
  pub https_port: u16,
}

/// Edge 状态推送数据
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeStatusPushData {
  pub port_usage: Option<EdgePortUsageData>,
  pub edge_id: String,
  pub online: bool,
  pub uptime: u64,
  pub timestamp: u64,
  pub supported_protocols: Vec<String>,
  pub active_sessions: i32,
  pub total_bytes_in: u64,
  pub total_bytes_out: u64,
  pub is_owner_view: bool,
  pub channels: Vec<EdgeChannelStatusData>,
  pub dns01_challenges: Vec<DNS01ChallengeData>,
  pub cname_status: u8,
  pub assigned_domain_status: Option<EdgeDomainStatusData>,
  pub custom_domain_status: Option<EdgeDomainStatusData>,
  pub domain_runtime: Option<DomainRuntimeData>,
  pub wireguard_relay_runtime_ready: bool,
}

/// Tunnel 状态响应数据（仅单 tunnel）
#[derive(Debug, Clone)]
pub struct TunnelStatusResponseData {
  pub success: bool,
  pub tunnel_id: String,
  pub edge_id: String,
  pub online: bool,
  pub uptime: u64,
  pub timestamp: u64,
  pub total_bytes_in: u64,
  pub total_bytes_out: u64,
  pub channels: Vec<EdgeChannelStatusData>,
  pub dns01_challenges: Vec<DNS01ChallengeData>,
  pub cname_status: u8,
  pub custom_domain_status: Option<EdgeDomainStatusData>,
  pub domain_runtime: Option<DomainRuntimeData>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel 定义信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct TunnelDefinitionData {
  pub tunnel_id: String,
  pub edge_id: String,
  pub owner_user_id: String,
  pub name: String,
  pub app_id: String,
  pub protocol: String,
  pub intent_json: String,
  pub config_json: String,
  pub runtime_json: String,
  pub state: String,
  pub actor_role: u8,
  pub actor_session_id: String,
  pub actor_device_id: String,
  pub version: u64,
  pub revision: u64,
  pub deleted: bool,
  pub created_at: u64,
  pub updated_at: u64,
}

/// Tunnel 增量同步响应
#[derive(Debug, Clone)]
pub struct TunnelSyncResponseData {
  pub success: bool,
  pub full_snapshot: bool,
  pub next_revision: u64,
  pub has_more: bool,
  pub definitions: Vec<TunnelDefinitionData>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel Upsert 响应
#[derive(Debug, Clone)]
pub struct TunnelUpsertResponseData {
  pub success: bool,
  pub conflict: bool,
  pub next_revision: u64,
  pub definition: Option<TunnelDefinitionData>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel Delete 响应
#[derive(Debug, Clone)]
pub struct TunnelDeleteResponseData {
  pub success: bool,
  pub conflict: bool,
  pub tunnel_id: String,
  pub next_revision: u64,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel 启停 actor 信息
#[derive(Debug, Clone)]
pub struct TunnelActorContextData {
  pub role: u8,
  pub device_id: String,
  pub session_id: String,
}

/// Tunnel start 请求中的 channel 规格
#[derive(Debug, Clone)]
pub struct TunnelChannelStartSpecData {
  pub key: String,
  pub protocol: String,
  pub local_host: String,
  pub local_port: u16,
  pub remote_port: u16,
  pub subdomain: String,
  pub alias_domain: String,
  pub buffer_size: u32,
  pub transport: String,
  pub eager_connect_remote: bool,
  pub metadata_json: String,
}

/// Tunnel start 逐 channel 结果
#[derive(Debug, Clone)]
pub struct TunnelChannelStartResultData {
  pub key: String,
  pub channel_id: String,
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
  pub remote_endpoint: String,
  pub alias_domain: String,
  pub custom_domain: String,
  pub assigned_domain: String,
  pub negotiated_buffer_size: u32,
}

/// Tunnel stop 逐 channel 结果
#[derive(Debug, Clone)]
pub struct TunnelChannelStopResultData {
  pub key: String,
  pub channel_id: String,
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel 操作汇总
#[derive(Debug, Clone)]
pub struct TunnelOperationSummaryData {
  pub requested: u32,
  pub succeeded: u32,
  pub failed: u32,
}

/// Tunnel 运行态快照（Edge authoritative）
#[derive(Debug, Clone)]
pub struct TunnelRuntimeSnapshotData {
  pub tunnel_id: String,
  pub state: String,
  pub runtime_json: String,
  pub updated_at: u64,
}

/// Tunnel start 响应
#[derive(Debug, Clone)]
pub struct TunnelStartResponseData {
  pub success: bool,
  pub mode: u8,
  pub tunnel_id: String,
  pub edge_id: String,
  pub summary: TunnelOperationSummaryData,
  pub channels: Vec<TunnelChannelStartResultData>,
  pub runtime_snapshot: Option<TunnelRuntimeSnapshotData>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel stop 响应
#[derive(Debug, Clone)]
pub struct TunnelStopResponseData {
  pub success: bool,
  pub mode: u8,
  pub tunnel_id: String,
  pub edge_id: String,
  pub summary: TunnelOperationSummaryData,
  pub channels: Vec<TunnelChannelStopResultData>,
  pub runtime_snapshot: Option<TunnelRuntimeSnapshotData>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 网络摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WGNetworkSummaryData {
  pub network_id: String,
  pub owner_user_id: String,
  pub name: String,
  pub subnet: String,
  pub lifecycle_status: u8,
  pub runtime_health: u8,
  pub member_count: u32,
  pub online_member_count: u32,
  pub self_joined: bool,
  pub created_at: u64,
  pub updated_at: u64,
  pub coordinator_edge_id: String,
}

/// WG 网络详情
#[derive(Debug, Clone, Serialize, Default)]
pub struct WGNetworkDetailData {
  pub network_id: String,
  pub owner_user_id: String,
  pub name: String,
  pub description: String,
  pub subnet: String,
  pub relay_mode: u8,
  pub lifecycle_status: u8,
  pub runtime_health: u8,
  pub self_joined: bool,
  pub self_member_id: String,
  pub self_device_id: String,
  pub member_count: u32,
  pub online_member_count: u32,
  pub created_at: u64,
  pub updated_at: u64,
  pub coordinator_edge_id: String,
}

/// WG 网络成员
#[derive(Debug, Clone, Serialize, Default)]
pub struct WGNetworkMemberData {
  pub member_id: String,
  pub network_id: String,
  pub user_id: String,
  pub device_id: String,
  pub hostname: String,
  pub assigned_ip: String,
  pub public_key: String,
  pub public_key_fingerprint: String,
  pub membership_status: u8,
  pub presence_status: u8,
  pub is_current_device: bool,
  pub joined_at: u64,
  pub last_seen_at: u64,
  pub updated_at: u64,
  pub is_relay_node: bool,
  pub observed_endpoint: String,
  pub observed_at: u64,
  /// Edge-issued identity generation; empty for legacy/ineligible members.
  pub membership_generation: String,
}

/// WG relay 节点信息
#[derive(Debug, Clone, Serialize)]
pub struct WGRelayNodeInfoData {
  pub member_id: String,
  pub public_key: String,
  pub endpoint: String,
  pub assigned_ip: String,
  pub listen_port: u32,
  pub peer_endpoints: Vec<WGRelayPeerEndpointInfoData>,
}

/// WG relay 为单个 client peer 分配的独立 UDP endpoint
#[derive(Debug, Clone, Serialize)]
pub struct WGRelayPeerEndpointInfoData {
  pub public_key: String,
  pub assigned_ip: String,
  pub endpoint: String,
  pub listen_port: u32,
}

/// WG peer endpoint 观测
#[derive(Debug, Clone, Serialize)]
pub struct WGPeerEndpointObservationData {
  pub member_id: String,
  pub device_id: String,
  pub endpoint: String,
  pub public_addr: String,
  pub nat_type: String,
  pub nat_type_code: u8,
  pub updated_at: u64,
}

/// WG peer session 运行态
#[derive(Debug, Clone, Serialize)]
pub struct WGPeerSessionRuntimeData {
  pub session_id: String,
  pub network_id: String,
  pub initiator_member_id: String,
  pub target_member_id: String,
  pub status: u8,
  pub path_type: u8,
  pub last_error: String,
  pub observations: Vec<WGPeerEndpointObservationData>,
  pub started_at: u64,
  pub updated_at: u64,
}

/// WG LAN peer endpoint (same-NAT direct path optimization)
#[derive(Debug, Clone, Serialize)]
pub struct WGLANPeerEndpointData {
  pub public_key: String,
  pub lan_endpoint: String,
  /// Multi-NIC candidate LAN endpoints (IP:PORT). Client tries each in order.
  pub lan_endpoint_candidates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WGPathVersionData {
  pub network_id: String,
  pub member_a_id: String,
  pub member_b_id: String,
  pub coordinator_edge_id: String,
  pub authority_epoch: String,
  pub pair_revision: String,
  pub network_policy_revision: String,
  pub attempt_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WGPathReportData {
  pub version: Option<WGPathVersionData>,
  pub member_id: String,
  /// Exact command acknowledged by this report; empty for legacy snapshots.
  #[serde(default)]
  pub command_id: String,
  pub kind: u32,
  pub error: u32,
  pub actual_path: u32,
  pub actual_owner_public_key: String,
  pub actual_allowed_ips: Vec<String>,
  pub actual_endpoint: String,
  pub applied_version: Option<WGPathVersionData>,
  pub handshake_at: String,
  pub business_sent: u32,
  pub business_replies: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WGPathModeSettingData {
  pub mode: u32,
  pub decision_id: String,
  pub reason: u32,
  pub requested_by_member_id: String,
  pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WGPathPairRuntimeData {
  /// Native-only command from the authenticated snapshot; never accepted from UI JSON.
  #[serde(skip)]
  pub plan: Option<Box<message::WGPathPlanT>>,
  pub version: Option<WGPathVersionData>,
  pub phase: u32,
  pub target_path: u32,
  pub committed_path: u32,
  pub endpoint_for_a: String,
  pub endpoint_for_b: String,
  pub report_a: Option<WGPathReportData>,
  pub report_b: Option<WGPathReportData>,
  pub last_error: u32,
  pub last_error_message: String,
  #[serde(default)]
  pub mode_setting: Option<WGPathModeSettingData>,
  #[serde(default)]
  pub mode_saved_a: bool,
  #[serde(default)]
  pub mode_saved_b: bool,
  /// Plan command identity; empty when the pair carries no active command.
  #[serde(default)]
  pub command_id: String,
}

/// WG 网络运行时快照
#[derive(Debug, Clone, Serialize)]
pub struct WGNetworkRuntimeSnapshotData {
  pub path_pairs: Vec<WGPathPairRuntimeData>,
  pub network: WGNetworkDetailData,
  pub members: Vec<WGNetworkMemberData>,
  pub peer_sessions: Vec<WGPeerSessionRuntimeData>,
  pub relay_node: Option<WGRelayNodeInfoData>,
  pub lan_peer_endpoints: Vec<WGLANPeerEndpointData>,
  pub revision: u64,
  pub collected_at: u64,
  /// Edge-owned generation for revision; separate from path authority epoch.
  pub revision_epoch: String,
  /// Empty until the authenticated Edge has an active coordination owner.
  pub path_authority_epoch: String,
  pub network_policy_revision: u64,
}

/// WG 创建网络响应
#[derive(Debug, Clone, Serialize)]
pub struct WGCreateNetworkResponseData {
  pub success: bool,
  pub network_id: String,
  pub status: u8,
  pub error_code: u32,
  pub error_message: String,
  pub suggested_cidrs: Vec<String>,
}

/// WG 加入网络响应
#[derive(Debug, Clone, Serialize)]
pub struct WGJoinNetworkResponseData {
  pub success: bool,
  pub member_id: String,
  pub assigned_ip: String,
  pub status: u8,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 创建邀请 token 响应
#[derive(Debug, Clone, Serialize)]
pub struct WGCreateInviteResponseData {
  pub success: bool,
  pub invite_token: String,
  pub expires_at: u64,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 离开网络响应
#[derive(Debug, Clone, Serialize)]
pub struct WGLeaveNetworkResponseData {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 列表响应
#[derive(Debug, Clone, Serialize)]
pub struct WGListNetworksResponseData {
  pub success: bool,
  pub revision: u64,
  pub networks: Vec<WGNetworkSummaryData>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 可加入网络的在线设备
#[derive(Debug, Clone, Serialize)]
pub struct WGAvailableDeviceData {
  pub client_id: String,
  pub device_id: String,
  pub hostname: String,
  pub last_active: u64,
}

/// WG 可用设备列表响应
#[derive(Debug, Clone, Serialize)]
pub struct WGListAvailableDevicesResponseData {
  pub success: bool,
  pub network_id: String,
  pub devices: Vec<WGAvailableDeviceData>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 详情响应
#[derive(Debug, Clone, Serialize)]
pub struct WGGetNetworkResponseData {
  pub success: bool,
  pub snapshot: Option<WGNetworkRuntimeSnapshotData>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 删除网络响应
#[derive(Debug, Clone, Serialize)]
pub struct WGDeleteNetworkResponseData {
  pub success: bool,
  pub network_id: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 修改网络 CIDR 响应
#[derive(Debug, Clone, Serialize)]
pub struct WGUpdateNetworkCIDRResponseData {
  pub success: bool,
  pub network_id: String,
  pub new_cidr: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 修改网络中继模式响应
#[derive(Debug, Clone, Serialize)]
pub struct WGUpdateNetworkRelayModeResponseData {
  pub success: bool,
  pub network_id: String,
  pub relay_mode: u8,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 更新成员信息响应
#[derive(Debug, Clone, Serialize)]
pub struct WGUpdateMemberResponseData {
  pub success: bool,
  pub network_id: String,
  pub member_id: String,
  pub new_ip: String,
  pub new_hostname: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG runtime 响应
#[derive(Debug, Clone, Serialize)]
pub struct WGNetworkRuntimeResponseData {
  pub success: bool,
  pub snapshot: Option<WGNetworkRuntimeSnapshotData>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel 事件推送
#[derive(Debug, Clone, serde::Serialize)]
pub struct TunnelEventPushData {
  pub action: u8,
  pub next_revision: u64,
  pub definition: Option<TunnelDefinitionData>,
}

/// WG Network 事件推送（Edge → Client）
#[derive(Debug, Clone, Serialize)]
pub struct WGNetworkEventPushData {
  pub action: u8,
  pub network_id: String,
  pub next_revision: u64,
  /// Edge-owned generation paired with next_revision.
  pub revision_epoch: String,
  pub snapshot: Option<WGNetworkRuntimeSnapshotData>,
}

/// ICE Start 推送（Edge → Client）
#[derive(Debug, Clone)]
pub struct IceStartData {
  pub ice_session_id: String,
  pub tunnel_id: String,
  pub token: String,
  pub ice_pwd: String,
  pub edge_udp_addr: String,
  pub edge_udp_addr_alt: String,
  pub gather_timeout_ms: u32,
}

/// ICE Punch 推送（Edge → Client）
#[derive(Debug, Clone)]
pub struct IcePunchData {
  pub ice_session_id: String,
  pub target_addr: String,
  pub token: String,
  pub ice_pwd: String,
  pub attempts: u32,
  pub interval_ms: u32,
  pub start_delay_ms: u32,
  pub extra_target_addrs: Vec<String>,
}

/// ICE QUIC Start 推送（Edge → Client）
#[derive(Debug, Clone)]
pub struct IceQuicStartData {
  pub ice_session_id: String,
  pub role: u8,
  pub peer_addr: String,
  pub alpn: String,
  pub connect_timeout_ms: u32,
}

/// ICE State Change 推送（Edge → Client）
#[derive(Debug, Clone)]
pub struct IceStateChangeData {
  pub ice_session_id: String,
  pub tunnel_id: String,
  pub state: String,
  pub strategy: u8,
  pub error: String,
}

/// 证书签发响应结果
#[derive(Debug, Clone)]
pub struct CertResponseData {
  pub success: bool,
  pub certificate: Vec<u8>,
  pub certificate_chain: Vec<u8>, // 新增：证书链（包含叶子证书 + 中间 CA）
  pub ca_certificate: Vec<u8>,
  pub expires_at: u64,
  pub serial_number: String,
  pub error_code: u32,
  pub error_message: String,
}

/// 错误响应结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ErrorData {
  pub code: u32,
  pub message: String,
  pub details: String,
}

/// HTTP 头
#[derive(Debug, Clone)]
pub struct HttpHeader {
  pub key: String,
  pub value: String,
}

/// Push 请求数据（Edge 推送的 HTTP 请求）
#[derive(Debug, Clone)]
pub struct PushRequestData {
  pub request_id: String,
  pub channel_id: String,
  pub method: String,
  pub path: String,
  pub query: String,
  pub headers: Vec<HttpHeader>,
  pub body: Vec<u8>,
  //  pub remote_addr: String,
}

/// Data Packet 数据（TCP 透明代理）
#[derive(Debug, Clone)]
pub struct DataPacketData {
  pub channel_id: String,
  pub connection_id: String,
  //  pub seq: u32,
  pub data: Vec<u8>,
  pub flags: u8,
}

/// 解析后的消息体
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ParsedResponse {
  AuthResponse(AuthResponseData),
  CertResponse(CertResponseData),
  HeartbeatAck(HeartbeatAckData),
  DataPacket(DataPacketData),
  PushRequest(PushRequestData),
  EdgeOnlineResponse(EdgeOnlineResponseData),
  EdgeOfflineResponse(EdgeOfflineResponseData),
  EdgeLogResponse(EdgeLogResponseData),
  EdgeLogPush(EdgeLogPushData),
  EdgeStatusPush(EdgeStatusPushData),
  TunnelStatusResponse(TunnelStatusResponseData),
  TunnelSyncResponse(TunnelSyncResponseData),
  TunnelUpsertResponse(TunnelUpsertResponseData),
  TunnelDeleteResponse(TunnelDeleteResponseData),
  TunnelStartResponse(TunnelStartResponseData),
  TunnelJoinResponse(TunnelStartResponseData),
  TunnelStopResponse(TunnelStopResponseData),
  TunnelLeaveResponse(TunnelStopResponseData),
  TunnelEventPush(TunnelEventPushData),
  WGCreateNetworkResponse(WGCreateNetworkResponseData),
  WGJoinNetworkResponse(WGJoinNetworkResponseData),
  WGCreateInviteResponse(WGCreateInviteResponseData),
  WGLeaveNetworkResponse(WGLeaveNetworkResponseData),
  WGListNetworksResponse(WGListNetworksResponseData),
  WGListAvailableDevicesResponse(WGListAvailableDevicesResponseData),
  WGGetNetworkResponse(WGGetNetworkResponseData),
  WGDeleteNetworkResponse(WGDeleteNetworkResponseData),
  WGNetworkRuntimeResponse(WGNetworkRuntimeResponseData),
  WGUpdateNetworkCIDRResponse(WGUpdateNetworkCIDRResponseData),
  WGUpdateNetworkRelayModeResponse(WGUpdateNetworkRelayModeResponseData),
  WGUpdateMemberResponse(WGUpdateMemberResponseData),
  WGNetworkEventPush(WGNetworkEventPushData),
  IceStart(IceStartData),
  IcePunch(IcePunchData),
  IceQuicStart(IceQuicStartData),
  IceStateChange(IceStateChangeData),
  Error(ErrorData),
  Unknown(u16),
}

/// 消息构建器
///
/// 提供链式 API 构建各类消息
pub struct MessageBuilder<'a> {
  builder: FlatBufferBuilder<'a>,
  seq: u32,
  session_id: Option<String>,
}

impl<'a> MessageBuilder<'a> {
  /// 创建新的消息构建器
  pub fn new() -> Self {
    Self {
      builder: FlatBufferBuilder::with_capacity(1024),
      seq: 0,
      session_id: None,
    }
  }

  /// 设置序列号
  pub fn seq(mut self, seq: u32) -> Self {
    self.seq = seq;
    self
  }

  /// 设置 session ID
  pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
    self.session_id = Some(session_id.into());
    self
  }

  /// 获取当前时间戳（毫秒）
  fn current_timestamp() -> u64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_millis() as u64)
      .unwrap_or(0)
  }

  fn tunnel_start_mode_from_code(mode: u8) -> TunnelStartMode {
    match mode {
      1 => TunnelStartMode::BEST_EFFORT,
      _ => TunnelStartMode::ALL_OR_NOTHING,
    }
  }

  fn wg_relay_mode_from_code(mode: u8) -> message::WGRelayMode {
    match mode {
      0 => message::WGRelayMode::DISABLED,
      2 => message::WGRelayMode::FORCE,
      _ => message::WGRelayMode::OPTIONAL,
    }
  }

  /// 构建消息头
  fn build_header(&mut self, msg_type: MessageType) -> WIPOffset<MessageHeader<'a>> {
    let session_id = self
      .session_id
      .as_ref()
      .map(|s| self.builder.create_string(s));

    MessageHeader::create(
      &mut self.builder,
      &MessageHeaderArgs {
        type_: msg_type,
        seq: self.seq,
        timestamp: Self::current_timestamp(),
        session_id,
      },
    )
  }

  /// 完成构建并返回字节数据
  fn finish(
    mut self,
    header: WIPOffset<MessageHeader<'a>>,
    body_type: MessageBody,
    body: Option<WIPOffset<flatbuffers::UnionWIPOffset>>,
  ) -> Vec<u8> {
    let msg = Message::create(
      &mut self.builder,
      &MessageArgs {
        header: Some(header),
        body_type,
        body,
      },
    );
    self.builder.finish(msg, Some(message::MESSAGE_IDENTIFIER));
    self.builder.finished_data().to_vec()
  }

  // ==================== Auth ====================

  /// 构建认证请求
  pub fn auth_request(
    mut self,
    device_id: &str,
    hostname: &str,
    client_version: &str,
    capabilities: &[&str],
    protocol_major: u16,
    protocol_minor: u16,
    required_features: &[&str],
    requested_features: &[&str],
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::AUTH_REQUEST);

    let device_id = self.builder.create_string(device_id);
    let hostname = self.builder.create_string(hostname);
    let client_version = self.builder.create_string(client_version);
    let caps: Vec<_> = capabilities
      .iter()
      .map(|c| self.builder.create_string(c))
      .collect();
    let capabilities = self.builder.create_vector(&caps);
    let required_features_offsets: Vec<_> = required_features
      .iter()
      .map(|f| self.builder.create_string(f))
      .collect();
    let required_features = if required_features_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&required_features_offsets))
    };
    let requested_features_offsets: Vec<_> = requested_features
      .iter()
      .map(|f| self.builder.create_string(f))
      .collect();
    let requested_features = if requested_features_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&requested_features_offsets))
    };

    let body = AuthRequest::create(
      &mut self.builder,
      &AuthRequestArgs {
        user_id: None, // The server derives identity from the mTLS certificate.
        device_id: Some(device_id),
        hostname: Some(hostname),
        client_version: Some(client_version),
        capabilities: Some(capabilities),
        protocol_major,
        protocol_minor,
        required_features,
        requested_features,
      },
    );

    self.finish(
      header,
      MessageBody::AuthRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Cert ====================

  /// 构建证书签发请求
  pub fn cert_request(
    mut self,
    token: &str,
    device_id: &str,
    csr: &[u8],
    scopes: &[String],
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::CERT_REQUEST);

    let token = self.builder.create_string(token);
    let device_id = self.builder.create_string(device_id);
    let csr = self.builder.create_vector(csr);
    let scopes = if scopes.is_empty() {
      None
    } else {
      let scope_offsets: Vec<_> = scopes
        .iter()
        .map(|s| self.builder.create_string(s.as_str()))
        .collect();
      Some(self.builder.create_vector(&scope_offsets))
    };

    let body = CertRequest::create(
      &mut self.builder,
      &CertRequestArgs {
        token: Some(token),
        device_id: Some(device_id),
        csr: Some(csr),
        scopes,
      },
    );

    self.finish(
      header,
      MessageBody::CertRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Heartbeat ====================

  /// 构建心跳请求
  pub fn heartbeat(mut self) -> Vec<u8> {
    let header = self.build_header(MessageType::HEARTBEAT);

    let body = Heartbeat::create(
      &mut self.builder,
      &HeartbeatArgs {
        client_time: Self::current_timestamp(),
      },
    );

    self.finish(header, MessageBody::Heartbeat, Some(body.as_union_value()))
  }

  /// 构建 Tunnel 启动请求
  pub fn tunnel_start_request(
    mut self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor: Option<&TunnelActorContextData>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
    definition_if_match_revision: u64,
    definition: Option<&TunnelDefinitionData>,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_START_REQUEST);

    let tunnel_id = self.builder.create_string(tunnel_id);
    let edge_id = edge_id.map(|s| self.builder.create_string(s));

    let actor = actor.map(|value| {
      let device_id = self.builder.create_string(&value.device_id);
      let session_id = self.builder.create_string(&value.session_id);
      TunnelActorContext::create(
        &mut self.builder,
        &TunnelActorContextArgs {
          role: TunnelActorRole(value.role),
          device_id: Some(device_id),
          session_id: Some(session_id),
        },
      )
    });

    let channel_offsets: Vec<_> = channels
      .iter()
      .map(|spec| {
        let key = self.builder.create_string(&spec.key);
        let protocol = self.builder.create_string(&spec.protocol);
        let local_host = self.builder.create_string(&spec.local_host);
        let alias_domain = self.builder.create_string(&spec.alias_domain);
        let transport = self.builder.create_string(&spec.transport);
        let metadata_json = self.builder.create_string(&spec.metadata_json);
        let subdomain = self.builder.create_string(&spec.subdomain);
        TunnelChannelStartSpec::create(
          &mut self.builder,
          &TunnelChannelStartSpecArgs {
            key: Some(key),
            protocol: Some(protocol),
            local_host: Some(local_host),
            local_port: spec.local_port,
            remote_port: spec.remote_port,
            alias_domain: Some(alias_domain),
            buffer_size: spec.buffer_size,
            transport: Some(transport),
            eager_connect_remote: spec.eager_connect_remote,
            metadata_json: Some(metadata_json),
            subdomain: Some(subdomain),
          },
        )
      })
      .collect();
    let channels = if channel_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&channel_offsets))
    };

    let definition_offset = definition.map(|def| {
      let def_tunnel_id = self.builder.create_string(&def.tunnel_id);
      let def_edge_id = self.builder.create_string(&def.edge_id);
      let owner_user_id = self.builder.create_string(&def.owner_user_id);
      let name = self.builder.create_string(&def.name);
      let app_id = self.builder.create_string(&def.app_id);
      let protocol = self.builder.create_string(&def.protocol);
      let intent_json = self.builder.create_string(&def.intent_json);
      let config_json = self.builder.create_string(&def.config_json);
      let runtime_json = self.builder.create_string(&def.runtime_json);
      let state = self.builder.create_string(&def.state);
      let actor_session_id = if def.actor_session_id.trim().is_empty() {
        None
      } else {
        Some(self.builder.create_string(&def.actor_session_id))
      };
      let actor_device_id = if def.actor_device_id.trim().is_empty() {
        None
      } else {
        Some(self.builder.create_string(&def.actor_device_id))
      };

      TunnelDefinitionInfo::create(
        &mut self.builder,
        &TunnelDefinitionInfoArgs {
          tunnel_id: Some(def_tunnel_id),
          edge_id: Some(def_edge_id),
          owner_user_id: Some(owner_user_id),
          name: Some(name),
          app_id: Some(app_id),
          protocol: Some(protocol),
          intent_json: Some(intent_json),
          config_json: Some(config_json),
          runtime_json: Some(runtime_json),
          state: Some(state),
          actor_role: TunnelActorRole(def.actor_role),
          actor_session_id,
          actor_device_id,
          version: def.version,
          revision: def.revision,
          deleted: def.deleted,
          created_at: def.created_at,
          updated_at: def.updated_at,
        },
      )
    });

    let body = TunnelStartRequest::create(
      &mut self.builder,
      &TunnelStartRequestArgs {
        tunnel_id: Some(tunnel_id),
        edge_id,
        mode: Self::tunnel_start_mode_from_code(mode),
        actor,
        channels,
        reconnect,
        definition_if_match_revision,
        definition: definition_offset,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelStartRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Tunnel 停止请求
  pub fn tunnel_stop_request(
    mut self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor: Option<&TunnelActorContextData>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_STOP_REQUEST);

    let tunnel_id = self.builder.create_string(tunnel_id);
    let edge_id = edge_id.map(|s| self.builder.create_string(s));
    let reason = reason.map(|s| self.builder.create_string(s));

    let actor = actor.map(|value| {
      let device_id = self.builder.create_string(&value.device_id);
      let session_id = self.builder.create_string(&value.session_id);
      TunnelActorContext::create(
        &mut self.builder,
        &TunnelActorContextArgs {
          role: TunnelActorRole(value.role),
          device_id: Some(device_id),
          session_id: Some(session_id),
        },
      )
    });

    let key_offsets: Vec<_> = keys
      .iter()
      .map(|key| self.builder.create_string(key))
      .collect();
    let keys = if key_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&key_offsets))
    };

    let body = TunnelStopRequest::create(
      &mut self.builder,
      &TunnelStopRequestArgs {
        tunnel_id: Some(tunnel_id),
        edge_id,
        mode: Self::tunnel_start_mode_from_code(mode),
        actor,
        keys,
        reason,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelStopRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Tunnel 加入协商请求（consumer/controller）
  pub fn tunnel_join_request(
    mut self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor: Option<&TunnelActorContextData>,
    channels: &[TunnelChannelStartSpecData],
    reconnect: bool,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_JOIN_REQUEST);

    let tunnel_id = self.builder.create_string(tunnel_id);
    let edge_id = edge_id.map(|s| self.builder.create_string(s));

    let actor = actor.map(|value| {
      let device_id = self.builder.create_string(&value.device_id);
      let session_id = self.builder.create_string(&value.session_id);
      TunnelActorContext::create(
        &mut self.builder,
        &TunnelActorContextArgs {
          role: TunnelActorRole(value.role),
          device_id: Some(device_id),
          session_id: Some(session_id),
        },
      )
    });

    let channel_offsets: Vec<_> = channels
      .iter()
      .map(|spec| {
        let key = self.builder.create_string(&spec.key);
        let protocol = self.builder.create_string(&spec.protocol);
        let local_host = self.builder.create_string(&spec.local_host);
        let alias_domain = self.builder.create_string(&spec.alias_domain);
        let transport = self.builder.create_string(&spec.transport);
        let metadata_json = self.builder.create_string(&spec.metadata_json);
        let subdomain = self.builder.create_string(&spec.subdomain);
        TunnelChannelStartSpec::create(
          &mut self.builder,
          &TunnelChannelStartSpecArgs {
            key: Some(key),
            protocol: Some(protocol),
            local_host: Some(local_host),
            local_port: spec.local_port,
            remote_port: spec.remote_port,
            alias_domain: Some(alias_domain),
            buffer_size: spec.buffer_size,
            transport: Some(transport),
            eager_connect_remote: spec.eager_connect_remote,
            metadata_json: Some(metadata_json),
            subdomain: Some(subdomain),
          },
        )
      })
      .collect();
    let channels = if channel_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&channel_offsets))
    };

    let body = TunnelJoinRequest::create(
      &mut self.builder,
      &TunnelJoinRequestArgs {
        tunnel_id: Some(tunnel_id),
        edge_id,
        mode: Self::tunnel_start_mode_from_code(mode),
        actor,
        channels,
        reconnect,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelJoinRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Tunnel 离开协商请求（session-local）
  pub fn tunnel_leave_request(
    mut self,
    tunnel_id: &str,
    edge_id: Option<&str>,
    mode: u8,
    actor: Option<&TunnelActorContextData>,
    keys: &[String],
    reason: Option<&str>,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_LEAVE_REQUEST);

    let tunnel_id = self.builder.create_string(tunnel_id);
    let edge_id = edge_id.map(|s| self.builder.create_string(s));
    let reason = reason.map(|s| self.builder.create_string(s));

    let actor = actor.map(|value| {
      let device_id = self.builder.create_string(&value.device_id);
      let session_id = self.builder.create_string(&value.session_id);
      TunnelActorContext::create(
        &mut self.builder,
        &TunnelActorContextArgs {
          role: TunnelActorRole(value.role),
          device_id: Some(device_id),
          session_id: Some(session_id),
        },
      )
    });

    let key_offsets: Vec<_> = keys
      .iter()
      .map(|key| self.builder.create_string(key))
      .collect();
    let keys = if key_offsets.is_empty() {
      None
    } else {
      Some(self.builder.create_vector(&key_offsets))
    };

    let body = TunnelLeaveRequest::create(
      &mut self.builder,
      &TunnelLeaveRequestArgs {
        tunnel_id: Some(tunnel_id),
        edge_id,
        mode: Self::tunnel_start_mode_from_code(mode),
        actor,
        keys,
        reason,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelLeaveRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Data Packet ====================

  /// 构建 Data Packet（TCP 透明代理）
  pub fn data_packet(
    mut self,
    channel_id: &str,
    connection_id: &str,
    seq: u32,
    data: &[u8],
    flags: u8,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::DATA_PACKET);

    let channel_id = self.builder.create_string(channel_id);
    let connection_id = self.builder.create_string(connection_id);
    let data_vec = self.builder.create_vector(data);

    let body = DataPacket::create(
      &mut self.builder,
      &DataPacketArgs {
        channel_id: Some(channel_id),
        connection_id: Some(connection_id),
        seq,
        data: Some(data_vec),
        flags,
      },
    );

    self.finish(header, MessageBody::DataPacket, Some(body.as_union_value()))
  }

  // ==================== Edge Control ====================

  pub fn edge_config_request(mut self, config_json: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::EDGE_CONFIG_REQUEST);
    let config = self.builder.create_string(config_json);
    let body = message::EdgeConfigRequest::create(
      &mut self.builder,
      &message::EdgeConfigRequestArgs { config_json: Some(config) },
    );
    self.finish(
      header,
      MessageBody::EdgeConfigRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Edge 上线请求
  pub fn edge_online_request(mut self) -> Vec<u8> {
    let header = self.build_header(MessageType::EDGE_ONLINE_REQUEST);

    let body = EdgeOnlineRequest::create(&mut self.builder, &EdgeOnlineRequestArgs {});

    self.finish(
      header,
      MessageBody::EdgeOnlineRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Edge 下线请求
  pub fn edge_offline_request(mut self) -> Vec<u8> {
    let header = self.build_header(MessageType::EDGE_OFFLINE_REQUEST);

    let body = EdgeOfflineRequest::create(&mut self.builder, &EdgeOfflineRequestArgs {});

    self.finish(
      header,
      MessageBody::EdgeOfflineRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Log ====================

  /// 构建日志请求
  pub fn edge_log_request(mut self, subscribe: bool, tail_lines: i32) -> Vec<u8> {
    let header = self.build_header(MessageType::EDGE_LOG_REQUEST);

    let body = EdgeLogRequest::create(
      &mut self.builder,
      &EdgeLogRequestArgs {
        subscribe,
        tail_lines,
      },
    );

    self.finish(
      header,
      MessageBody::EdgeLogRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Edge Status ====================

  /// 构建 Edge 状态请求
  pub fn edge_status_request(mut self, detail_level: u8) -> Vec<u8> {
    let header = self.build_header(MessageType::EDGE_STATUS_REQUEST);

    let body =
      EdgeStatusRequest::create(&mut self.builder, &EdgeStatusRequestArgs { detail_level });

    self.finish(
      header,
      MessageBody::EdgeStatusRequest,
      Some(body.as_union_value()),
    )
  }

  /// Import an Edge domain certificate on the authenticated owner session.
  pub fn edge_domain_certificate_request(mut self, domain: &str, certificate_pem: &str, private_key_pem: &str) -> Vec<u8> {
    use message::{EdgeDomainCertificateRequest, EdgeDomainCertificateRequestArgs};
    let header = self.build_header(MessageType::EDGE_DOMAIN_CERTIFICATE_REQUEST);
    let domain = self.builder.create_string(domain);
    let certificate_pem = self.builder.create_string(certificate_pem);
    let private_key_pem = self.builder.create_string(private_key_pem);
    let body = EdgeDomainCertificateRequest::create(&mut self.builder, &EdgeDomainCertificateRequestArgs {
      domain: Some(domain), certificate_pem: Some(certificate_pem), private_key_pem: Some(private_key_pem),
    });
    self.finish(header, MessageBody::EdgeDomainCertificateRequest, Some(body.as_union_value()))
  }

  /// 构建 Tunnel 状态请求（单 tunnel）
  pub fn tunnel_status_request(mut self, tunnel_id: &str, detail_level: u8) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_STATUS_REQUEST);
    let tunnel_id = self.builder.create_string(tunnel_id);
    let body = TunnelStatusRequest::create(
      &mut self.builder,
      &TunnelStatusRequestArgs {
        tunnel_id: Some(tunnel_id),
        detail_level,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelStatusRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== Tunnel Metadata ====================

  /// 构建 Tunnel 增量同步请求
  pub fn tunnel_sync_request(
    mut self,
    edge_id: Option<&str>,
    since_revision: u64,
    limit: u32,
    include_deleted: bool,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_SYNC_REQUEST);

    let edge_id = edge_id.map(|s| self.builder.create_string(s));
    let body = TunnelSyncRequest::create(
      &mut self.builder,
      &TunnelSyncRequestArgs {
        edge_id,
        since_revision,
        limit,
        include_deleted,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelSyncRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Tunnel 写入请求
  pub fn tunnel_upsert_request(
    mut self,
    edge_id: Option<&str>,
    if_match_revision: u64,
    definition: &TunnelDefinitionData,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_UPSERT_REQUEST);

    let edge_id = edge_id.map(|s| self.builder.create_string(s));
    let tunnel_id = self.builder.create_string(&definition.tunnel_id);
    let def_edge_id = self.builder.create_string(&definition.edge_id);
    let owner_user_id = self.builder.create_string(&definition.owner_user_id);
    let name = self.builder.create_string(&definition.name);
    let app_id = self.builder.create_string(&definition.app_id);
    let protocol = self.builder.create_string(&definition.protocol);
    let intent_json = self.builder.create_string(&definition.intent_json);
    let config_json = self.builder.create_string(&definition.config_json);
    let runtime_json = self.builder.create_string(&definition.runtime_json);
    let state = self.builder.create_string(&definition.state);
    let actor_session_id = if definition.actor_session_id.trim().is_empty() {
      None
    } else {
      Some(self.builder.create_string(&definition.actor_session_id))
    };
    let actor_device_id = if definition.actor_device_id.trim().is_empty() {
      None
    } else {
      Some(self.builder.create_string(&definition.actor_device_id))
    };

    let definition_offset = TunnelDefinitionInfo::create(
      &mut self.builder,
      &TunnelDefinitionInfoArgs {
        tunnel_id: Some(tunnel_id),
        edge_id: Some(def_edge_id),
        owner_user_id: Some(owner_user_id),
        name: Some(name),
        app_id: Some(app_id),
        protocol: Some(protocol),
        intent_json: Some(intent_json),
        config_json: Some(config_json),
        runtime_json: Some(runtime_json),
        state: Some(state),
        actor_role: TunnelActorRole(definition.actor_role),
        actor_session_id,
        actor_device_id,
        version: definition.version,
        revision: definition.revision,
        deleted: definition.deleted,
        created_at: definition.created_at,
        updated_at: definition.updated_at,
      },
    );

    let body = TunnelUpsertRequest::create(
      &mut self.builder,
      &TunnelUpsertRequestArgs {
        edge_id,
        if_match_revision,
        definition: Some(definition_offset),
      },
    );

    self.finish(
      header,
      MessageBody::TunnelUpsertRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 Tunnel 删除请求
  pub fn tunnel_delete_request(
    mut self,
    edge_id: Option<&str>,
    tunnel_id: &str,
    if_match_revision: u64,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::TUNNEL_DELETE_REQUEST);

    let edge_id = edge_id.map(|s| self.builder.create_string(s));
    let tunnel_id = self.builder.create_string(tunnel_id);
    let body = TunnelDeleteRequest::create(
      &mut self.builder,
      &TunnelDeleteRequestArgs {
        edge_id,
        tunnel_id: Some(tunnel_id),
        if_match_revision,
      },
    );

    self.finish(
      header,
      MessageBody::TunnelDeleteRequest,
      Some(body.as_union_value()),
    )
  }

  // ==================== WireGuard Networks ====================

  /// 构建 WG 网络列表请求
  pub fn wg_list_networks_request(mut self, include_deleted: bool) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_LIST_NETWORKS);

    let body = WGListNetworksRequest::create(
      &mut self.builder,
      &WGListNetworksRequestArgs { include_deleted },
    );

    self.finish(
      header,
      MessageBody::WGListNetworksRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 网络详情请求
  pub fn wg_get_network_request(mut self, network_id: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_GET_NETWORK);
    let network_id = self.builder.create_string(network_id);

    let body = WGGetNetworkRequest::create(
      &mut self.builder,
      &WGGetNetworkRequestArgs {
        network_id: Some(network_id),
      },
    );

    self.finish(
      header,
      MessageBody::WGGetNetworkRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 网络 runtime 请求
  pub fn wg_network_runtime_request(mut self, network_id: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_NETWORK_RUNTIME_REQUEST);
    let network_id = self.builder.create_string(network_id);

    let body = WGNetworkRuntimeRequest::create(
      &mut self.builder,
      &WGNetworkRuntimeRequestArgs {
        network_id: Some(network_id),
      },
    );

    self.finish(
      header,
      MessageBody::WGNetworkRuntimeRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 列出可加入网络的在线设备请求
  pub fn wg_list_available_devices_request(mut self, network_id: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_LIST_AVAILABLE_DEVICES);
    let network_id = self.builder.create_string(network_id);

    let body = WGListAvailableDevicesRequest::create(
      &mut self.builder,
      &WGListAvailableDevicesRequestArgs {
        network_id: Some(network_id),
      },
    );

    self.finish(
      header,
      MessageBody::WGListAvailableDevicesRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 创建网络请求
  pub fn wg_create_network_request(
    mut self,
    network_id: &str,
    name: &str,
    cidr: &str,
    relay_mode: u8,
    description: &str,
    owner_user_id: &str,
    owner_username: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_CREATE_NETWORK);
    let network_id = self.builder.create_string(network_id);
    let name = self.builder.create_string(name);
    let cidr = self.builder.create_string(cidr);
    let description = self.builder.create_string(description);
    let owner_user_id = self.builder.create_string(owner_user_id);
    let owner_username = self.builder.create_string(owner_username);

    let body = WGCreateNetworkRequest::create(
      &mut self.builder,
      &WGCreateNetworkRequestArgs {
        network_id: Some(network_id),
        name: Some(name),
        cidr: Some(cidr),
        relay_mode: Self::wg_relay_mode_from_code(relay_mode),
        description: Some(description),
        owner_user_id: Some(owner_user_id),
        owner_username: Some(owner_username),
      },
    );

    self.finish(
      header,
      MessageBody::WGCreateNetworkRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 加入网络请求
  pub fn wg_join_network_request(
    mut self,
    network_id: &str,
    client_id: &str,
    public_key: &str,
    hostname: &str,
    invite_token: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_JOIN_NETWORK);
    let network_id = self.builder.create_string(network_id);
    let client_id = self.builder.create_string(client_id);
    let public_key = self.builder.create_string(public_key);
    let hostname = self.builder.create_string(hostname);
    let invite_token = if invite_token.is_empty() {
      None
    } else {
      Some(self.builder.create_string(invite_token))
    };

    let body = WGJoinNetworkRequest::create(
      &mut self.builder,
      &WGJoinNetworkRequestArgs {
        network_id: Some(network_id),
        client_id: Some(client_id),
        public_key: Some(public_key),
        hostname: Some(hostname),
        invite_token,
      },
    );

    self.finish(
      header,
      MessageBody::WGJoinNetworkRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 创建邀请 token 请求
  pub fn wg_create_invite_request(
    mut self,
    network_id: &str,
    expires_in_secs: u32,
    max_uses: u32,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_CREATE_INVITE);
    let network_id = self.builder.create_string(network_id);

    let body = WGCreateInviteRequest::create(
      &mut self.builder,
      &WGCreateInviteRequestArgs {
        network_id: Some(network_id),
        expires_in_secs,
        max_uses,
      },
    );

    self.finish(
      header,
      MessageBody::WGCreateInviteRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 离开网络请求
  pub fn wg_leave_network_request(
    mut self,
    network_id: &str,
    member_id: &str,
    temporary: bool,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_LEAVE_NETWORK);
    let network_id = self.builder.create_string(network_id);
    let member_id = self.builder.create_string(member_id);

    let body = WGLeaveNetworkRequest::create(
      &mut self.builder,
      &WGLeaveNetworkRequestArgs {
        network_id: Some(network_id),
        member_id: Some(member_id),
        temporary: temporary,
      },
    );

    self.finish(
      header,
      MessageBody::WGLeaveNetworkRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG 删除网络请求
  pub fn wg_delete_network_request(mut self, network_id: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_DELETE_NETWORK);
    let network_id = self.builder.create_string(network_id);

    let body = WGDeleteNetworkRequest::create(
      &mut self.builder,
      &WGDeleteNetworkRequestArgs {
        network_id: Some(network_id),
      },
    );

    self.finish(
      header,
      MessageBody::WGDeleteNetworkRequest,
      Some(body.as_union_value()),
    )
  }

  pub fn wg_update_network_cidr_request(mut self, network_id: &str, new_cidr: &str) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_UPDATE_NETWORK_CIDR);
    let network_id = self.builder.create_string(network_id);
    let new_cidr = self.builder.create_string(new_cidr);

    let body = WGUpdateNetworkCIDRRequest::create(
      &mut self.builder,
      &WGUpdateNetworkCIDRRequestArgs {
        network_id: Some(network_id),
        new_cidr: Some(new_cidr),
      },
    );

    self.finish(
      header,
      MessageBody::WGUpdateNetworkCIDRRequest,
      Some(body.as_union_value()),
    )
  }

  pub fn wg_update_network_relay_mode_request(
    mut self,
    network_id: &str,
    relay_mode: u8,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_UPDATE_NETWORK_RELAY_MODE);
    let network_id = self.builder.create_string(network_id);

    let body = WGUpdateNetworkRelayModeRequest::create(
      &mut self.builder,
      &WGUpdateNetworkRelayModeRequestArgs {
        network_id: Some(network_id),
        relay_mode: Self::wg_relay_mode_from_code(relay_mode),
      },
    );

    self.finish(
      header,
      MessageBody::WGUpdateNetworkRelayModeRequest,
      Some(body.as_union_value()),
    )
  }

  pub fn wg_update_member_request(
    mut self,
    network_id: &str,
    member_id: &str,
    new_ip: &str,
    new_hostname: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_UPDATE_MEMBER);
    let network_id = self.builder.create_string(network_id);
    let member_id = self.builder.create_string(member_id);
    let new_ip = self.builder.create_string(new_ip);
    let new_hostname = self.builder.create_string(new_hostname);

    let body = WGUpdateMemberRequest::create(
      &mut self.builder,
      &WGUpdateMemberRequestArgs {
        network_id: Some(network_id),
        member_id: Some(member_id),
        new_ip: Some(new_ip),
        new_hostname: Some(new_hostname),
      },
    );

    self.finish(
      header,
      MessageBody::WGUpdateMemberRequest,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG Gather Info 响应（Client → Edge）
  pub fn wg_gather_info_response(
    mut self,
    session_id: &str,
    client_id: &str,
    local_addrs: &[String],
    public_addr: &str,
    nat_type: u8,
    local_wg_endpoint: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_GATHER_INFO);
    let session_id = self.builder.create_string(session_id);
    let client_id = self.builder.create_string(client_id);
    let public_addr = self.builder.create_string(public_addr);
    let local_addr_offsets: Vec<_> = local_addrs
      .iter()
      .map(|s| self.builder.create_string(s))
      .collect();
    let local_addrs_vec = self.builder.create_vector(&local_addr_offsets);
    let local_wg_endpoint_offset = if local_wg_endpoint.is_empty() {
      None
    } else {
      Some(self.builder.create_string(local_wg_endpoint))
    };

    let body = WGGatherInfo::create(
      &mut self.builder,
      &WGGatherInfoArgs {
        session_id: Some(session_id),
        client_id: Some(client_id),
        local_addrs: Some(local_addrs_vec),
        public_addr: Some(public_addr),
        nat_type,
        local_wg_endpoint: local_wg_endpoint_offset,
      },
    );

    self.finish(
      header,
      MessageBody::WGGatherInfo,
      Some(body.as_union_value()),
    )
  }

  /// 构建 WG Punch Info 响应（Client → Edge）
  pub fn wg_punch_info_response(
    mut self,
    session_id: &str,
    client_id: &str,
    success: bool,
    connected_addr: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::WG_PUNCH_INFO);
    let session_id = self.builder.create_string(session_id);
    let client_id = self.builder.create_string(client_id);
    let connected_addr = self.builder.create_string(connected_addr);

    let body = WGPunchInfo::create(
      &mut self.builder,
      &WGPunchInfoArgs {
        session_id: Some(session_id),
        client_id: Some(client_id),
        punch_addrs: None,
        success,
        connected_addr: Some(connected_addr),
      },
    );

    self.finish(
      header,
      MessageBody::WGPunchInfo,
      Some(body.as_union_value()),
    )
  }

  // ==================== Push Response ====================

  /// 构建 Push 响应（处理 HTTP 请求后返回）
  pub fn push_response(
    mut self,
    request_id: &str,
    status_code: u16,
    headers: &[(String, String)],
    body: &[u8],
    error: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::PUSH_RESPONSE);

    let request_id = self.builder.create_string(request_id);
    let error = self.builder.create_string(error);
    let body_vec = self.builder.create_vector(body);

    // 构建 headers
    let header_offsets: Vec<_> = headers
      .iter()
      .map(|(k, v)| {
        let key = self.builder.create_string(k);
        let value = self.builder.create_string(v);
        HTTPHeader::create(
          &mut self.builder,
          &HTTPHeaderArgs {
            key: Some(key),
            value: Some(value),
          },
        )
      })
      .collect();
    let headers_vec = self.builder.create_vector(&header_offsets);

    let body = PushResponse::create(
      &mut self.builder,
      &PushResponseArgs {
        request_id: Some(request_id),
        status_code,
        headers: Some(headers_vec),
        body: Some(body_vec),
        error: Some(error),
      },
    );

    self.finish(
      header,
      MessageBody::PushResponse,
      Some(body.as_union_value()),
    )
  }

  // ==================== ICE ====================

  pub fn ice_punch_result(
    mut self,
    ice_session_id: &str,
    success: bool,
    peer_observed_addr: &str,
    attempts_sent: u32,
    first_recv_at: u64,
    failure_reason: &str,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::ICE_PUNCH_RESULT);

    let ice_session_id = self.builder.create_string(ice_session_id);
    let peer_observed_addr = self.builder.create_string(peer_observed_addr);
    let failure_reason = self.builder.create_string(failure_reason);

    let body = ICEPunchResult::create(
      &mut self.builder,
      &ICEPunchResultArgs {
        ice_session_id: Some(ice_session_id),
        success,
        peer_observed_addr: Some(peer_observed_addr),
        attempts_sent,
        first_recv_at,
        failure_reason: Some(failure_reason),
      },
    );

    self.finish(
      header,
      MessageBody::ICEPunchResult,
      Some(body.as_union_value()),
    )
  }

  pub fn ice_quic_connected(
    mut self,
    ice_session_id: &str,
    connection_id: &str,
    local_addr: &str,
    peer_addr: &str,
    rtt_ms: u32,
  ) -> Vec<u8> {
    let header = self.build_header(MessageType::ICE_QUIC_CONNECTED);

    let ice_session_id = self.builder.create_string(ice_session_id);
    let connection_id = self.builder.create_string(connection_id);
    let local_addr = self.builder.create_string(local_addr);
    let peer_addr = self.builder.create_string(peer_addr);

    let body = ICEQuicConnected::create(
      &mut self.builder,
      &ICEQuicConnectedArgs {
        ice_session_id: Some(ice_session_id),
        connection_id: Some(connection_id),
        local_addr: Some(local_addr),
        peer_addr: Some(peer_addr),
        rtt_ms,
      },
    );

    self.finish(
      header,
      MessageBody::ICEQuicConnected,
      Some(body.as_union_value()),
    )
  }
}

impl Default for MessageBuilder<'_> {
  fn default() -> Self {
    Self::new()
  }
}

fn parse_tunnel_definition_info(def: message::TunnelDefinitionInfo<'_>) -> TunnelDefinitionData {
  TunnelDefinitionData {
    tunnel_id: def.tunnel_id().unwrap_or("").to_string(),
    edge_id: def.edge_id().unwrap_or("").to_string(),
    owner_user_id: def.owner_user_id().unwrap_or("").to_string(),
    name: def.name().unwrap_or("").to_string(),
    app_id: def.app_id().unwrap_or("").to_string(),
    protocol: def.protocol().unwrap_or("").to_string(),
    intent_json: def.intent_json().unwrap_or("").to_string(),
    config_json: def.config_json().unwrap_or("").to_string(),
    runtime_json: def.runtime_json().unwrap_or("").to_string(),
    state: def.state().unwrap_or("").to_string(),
    actor_role: def.actor_role().0,
    actor_session_id: def.actor_session_id().unwrap_or("").to_string(),
    actor_device_id: def.actor_device_id().unwrap_or("").to_string(),
    version: def.version(),
    revision: def.revision(),
    deleted: def.deleted(),
    created_at: def.created_at(),
    updated_at: def.updated_at(),
  }
}

fn parse_tunnel_operation_summary(
  summary: Option<message::TunnelOperationSummary<'_>>,
) -> TunnelOperationSummaryData {
  if let Some(value) = summary {
    TunnelOperationSummaryData {
      requested: value.requested(),
      succeeded: value.succeeded(),
      failed: value.failed(),
    }
  } else {
    TunnelOperationSummaryData {
      requested: 0,
      succeeded: 0,
      failed: 0,
    }
  }
}

fn parse_tunnel_runtime_snapshot(
  snapshot: Option<message::TunnelRuntimeSnapshot<'_>>,
) -> Option<TunnelRuntimeSnapshotData> {
  snapshot.map(|value| TunnelRuntimeSnapshotData {
    tunnel_id: value.tunnel_id().unwrap_or("").to_string(),
    state: value.state().unwrap_or("").to_string(),
    runtime_json: value.runtime_json().unwrap_or("").to_string(),
    updated_at: value.updated_at(),
  })
}

fn parse_wg_network_summary_info(info: message::WGNetworkSummaryInfo<'_>) -> WGNetworkSummaryData {
  WGNetworkSummaryData {
    network_id: info.network_id().unwrap_or("").to_string(),
    owner_user_id: info.owner_user_id().unwrap_or("").to_string(),
    name: info.name().unwrap_or("").to_string(),
    subnet: info.subnet().unwrap_or("").to_string(),
    lifecycle_status: info.lifecycle_status().0,
    runtime_health: info.runtime_health().0,
    member_count: info.member_count(),
    online_member_count: info.online_member_count(),
    self_joined: info.self_joined(),
    created_at: info.created_at(),
    updated_at: info.updated_at(),
    coordinator_edge_id: info.coordinator_edge_id().unwrap_or("").to_string(),
  }
}

fn parse_wg_network_detail_info(info: message::WGNetworkDetailInfo<'_>) -> WGNetworkDetailData {
  WGNetworkDetailData {
    network_id: info.network_id().unwrap_or("").to_string(),
    owner_user_id: info.owner_user_id().unwrap_or("").to_string(),
    name: info.name().unwrap_or("").to_string(),
    description: info.description().unwrap_or("").to_string(),
    subnet: info.subnet().unwrap_or("").to_string(),
    relay_mode: info.relay_mode().0,
    lifecycle_status: info.lifecycle_status().0,
    runtime_health: info.runtime_health().0,
    self_joined: info.self_joined(),
    self_member_id: info.self_member_id().unwrap_or("").to_string(),
    self_device_id: info.self_device_id().unwrap_or("").to_string(),
    member_count: info.member_count(),
    online_member_count: info.online_member_count(),
    created_at: info.created_at(),
    updated_at: info.updated_at(),
    coordinator_edge_id: info.coordinator_edge_id().unwrap_or("").to_string(),
  }
}

fn parse_wg_network_member_info(info: message::WGNetworkMemberInfo<'_>) -> WGNetworkMemberData {
  WGNetworkMemberData {
    member_id: info.member_id().unwrap_or("").to_string(),
    network_id: info.network_id().unwrap_or("").to_string(),
    user_id: info.user_id().unwrap_or("").to_string(),
    device_id: info.device_id().unwrap_or("").to_string(),
    hostname: info.hostname().unwrap_or("").to_string(),
    assigned_ip: info.assigned_ip().unwrap_or("").to_string(),
    public_key: info.public_key().unwrap_or("").to_string(),
    public_key_fingerprint: info.public_key_fingerprint().unwrap_or("").to_string(),
    membership_status: info.membership_status().0,
    presence_status: info.presence_status().0,
    is_current_device: info.is_current_device(),
    joined_at: info.joined_at(),
    last_seen_at: info.last_seen_at(),
    updated_at: info.updated_at(),
    is_relay_node: info.is_relay_node(),
    observed_endpoint: info.observed_endpoint().unwrap_or("").to_string(),
    observed_at: info.observed_at(),
    membership_generation: info.membership_generation().unwrap_or("").to_string(),
  }
}

fn parse_wg_relay_node_info(info: message::WGRelayNodeInfo<'_>) -> WGRelayNodeInfoData {
  let mut peer_endpoints = Vec::new();
  if let Some(items) = info.peer_endpoints() {
    for i in 0..items.len() {
      let peer = items.get(i);
      peer_endpoints.push(WGRelayPeerEndpointInfoData {
        public_key: peer.public_key().unwrap_or("").to_string(),
        assigned_ip: peer.assigned_ip().unwrap_or("").to_string(),
        endpoint: peer.endpoint().unwrap_or("").to_string(),
        listen_port: peer.listen_port(),
      });
    }
  }
  WGRelayNodeInfoData {
    member_id: info.member_id().unwrap_or("").to_string(),
    public_key: info.public_key().unwrap_or("").to_string(),
    endpoint: info.endpoint().unwrap_or("").to_string(),
    assigned_ip: info.assigned_ip().unwrap_or("").to_string(),
    listen_port: info.listen_port(),
    peer_endpoints,
  }
}

fn parse_wg_peer_endpoint_observation_info(
  info: message::WGPeerEndpointObservationInfo<'_>,
) -> WGPeerEndpointObservationData {
  WGPeerEndpointObservationData {
    member_id: info.member_id().unwrap_or("").to_string(),
    device_id: info.device_id().unwrap_or("").to_string(),
    endpoint: info.endpoint().unwrap_or("").to_string(),
    public_addr: info.public_addr().unwrap_or("").to_string(),
    nat_type: info.nat_type().unwrap_or("").to_string(),
    nat_type_code: info.nat_type_code(),
    updated_at: info.updated_at(),
  }
}

fn parse_wg_peer_session_runtime_info(
  info: message::WGPeerSessionRuntimeInfo<'_>,
) -> WGPeerSessionRuntimeData {
  let mut observations = Vec::new();
  if let Some(items) = info.observations() {
    for i in 0..items.len() {
      observations.push(parse_wg_peer_endpoint_observation_info(items.get(i)));
    }
  }

  WGPeerSessionRuntimeData {
    session_id: info.session_id().unwrap_or("").to_string(),
    network_id: info.network_id().unwrap_or("").to_string(),
    initiator_member_id: info.initiator_member_id().unwrap_or("").to_string(),
    target_member_id: info.target_member_id().unwrap_or("").to_string(),
    status: info.status().0,
    path_type: info.path_type().0,
    last_error: info.last_error().unwrap_or("").to_string(),
    observations,
    started_at: info.started_at(),
    updated_at: info.updated_at(),
  }
}


fn parse_path_version(v: message::WGPathVersion<'_>) -> WGPathVersionData {
  WGPathVersionData {
    network_id: v.network_id().unwrap_or("").into(),
    member_a_id: v.member_a_id().unwrap_or("").into(),
    member_b_id: v.member_b_id().unwrap_or("").into(),
    coordinator_edge_id: v.coordinator_edge_id().unwrap_or("").into(),
    authority_epoch: v.authority_epoch().unwrap_or("").into(),
    pair_revision: v.pair_revision().to_string(),
    network_policy_revision: v.network_policy_revision().to_string(),
    attempt_id: v.attempt_id().unwrap_or("").into(),
  }
}

fn parse_path_report(r: message::WGPathReport<'_>) -> WGPathReportData {
  WGPathReportData {
    version: r.version().map(parse_path_version),
    member_id: r.member_id().unwrap_or("").into(),
    command_id: r.command_id().unwrap_or("").into(),
    kind: r.kind().0 as u32,
    error: r.error().0 as u32,
    actual_path: r.actual_path().0 as u32,
    actual_owner_public_key: r.actual_owner_public_key().unwrap_or("").into(),
    actual_allowed_ips: r.actual_allowed_ips().map(|ips| ips.iter().map(str::to_owned).collect()).unwrap_or_default(),
    actual_endpoint: r.actual_endpoint().unwrap_or("").into(),
    applied_version: r.applied_version().map(parse_path_version),
    handshake_at: r.handshake_at().to_string(),
    business_sent: r.business().map(|b| b.sent()).unwrap_or_default(),
    business_replies: r.business().map(|b| b.replies()).unwrap_or_default(),
  }
}

fn parse_path_pair(p: message::WGPathPairRuntimeInfo<'_>) -> WGPathPairRuntimeData {
  let plan = p.plan();
  WGPathPairRuntimeData {
    plan: plan.map(|p| Box::new(p.unpack())),
    version: plan.and_then(|p| p.version()).map(parse_path_version),
    phase: plan.map(|p| p.phase().0 as u32).unwrap_or_default(),
    target_path: plan.map(|p| p.target_path().0 as u32).unwrap_or_default(),
    committed_path: plan.map(|p| p.committed_path().0 as u32).unwrap_or_default(),
    endpoint_for_a: plan.and_then(|p| p.endpoint_for_a()).unwrap_or("").into(),
    endpoint_for_b: plan.and_then(|p| p.endpoint_for_b()).unwrap_or("").into(),
    report_a: p.report_a().map(parse_path_report),
    report_b: p.report_b().map(parse_path_report),
    last_error: p.last_error().0 as u32,
    last_error_message: p.last_error_message().unwrap_or("").into(),
    mode_setting: plan.and_then(|p| p.mode_setting()).map(|m| WGPathModeSettingData {
      mode: m.mode().0 as u32,
      decision_id: m.decision_id().unwrap_or("").into(),
      reason: m.reason().0 as u32,
      requested_by_member_id: m.requested_by_member_id().unwrap_or("").into(),
      request_id: m.request_id().unwrap_or("").into(),
    }),
    mode_saved_a: p.mode_saved_a(),
    mode_saved_b: p.mode_saved_b(),
    command_id: plan.and_then(|p| p.command_id()).unwrap_or("").into(),
  }
}

fn parse_wg_network_runtime_snapshot(
  snapshot: Option<message::WGNetworkRuntimeSnapshotInfo<'_>>,
) -> Option<WGNetworkRuntimeSnapshotData> {
  snapshot.map(|value| {
    let network =
      value
        .network()
        .map(parse_wg_network_detail_info)
        .unwrap_or(WGNetworkDetailData {
          network_id: String::new(),
          owner_user_id: String::new(),
          name: String::new(),
          description: String::new(),
          subnet: String::new(),
          relay_mode: 0,
          lifecycle_status: 0,
          runtime_health: 0,
          self_joined: false,
          self_member_id: String::new(),
          self_device_id: String::new(),
          member_count: 0,
          online_member_count: 0,
          created_at: 0,
          updated_at: 0,
          coordinator_edge_id: String::new(),
        });

    let mut members = Vec::new();
    if let Some(items) = value.members() {
      for i in 0..items.len() {
        members.push(parse_wg_network_member_info(items.get(i)));
      }
    }

    let mut peer_sessions = Vec::new();
    if let Some(items) = value.peer_sessions() {
      for i in 0..items.len() {
        peer_sessions.push(parse_wg_peer_session_runtime_info(items.get(i)));
      }
    }

    let relay_node = value.relay_node().map(parse_wg_relay_node_info);

    let mut lan_peer_endpoints = Vec::new();
    if let Some(items) = value.lan_peer_endpoints() {
      for i in 0..items.len() {
        let item = items.get(i);
        let mut candidates = Vec::new();
        if let Some(c) = item.lan_endpoint_candidates() {
          for j in 0..c.len() {
            candidates.push(c.get(j).to_string());
          }
        }
        lan_peer_endpoints.push(WGLANPeerEndpointData {
          public_key: item.public_key().unwrap_or("").to_string(),
          lan_endpoint: item.lan_endpoint().unwrap_or("").to_string(),
          lan_endpoint_candidates: candidates,
        });
      }
    }

    WGNetworkRuntimeSnapshotData {
      network,
      members,
      peer_sessions,
      relay_node,
      lan_peer_endpoints,
      revision: value.revision(),
      collected_at: value.collected_at(),
      revision_epoch: value.revision_epoch().unwrap_or("").to_string(),
      path_authority_epoch: value.path_authority_epoch().unwrap_or("").to_string(),
      network_policy_revision: value.network_policy_revision(),
      path_pairs: value.path_pairs().map(|items| items.iter().map(parse_path_pair).collect()).unwrap_or_default(),
    }
  })
}

/// 消息读取器
///
/// 提供便捷的响应消息解析接口
pub struct MessageReader;

impl MessageReader {
  /// 从字节数据解析消息
  pub fn parse(data: &[u8]) -> Result<Message<'_>, &'static str> {
    if data.len() < 4 {
      return Err("data too short");
    }
    message::root_as_message(data).map_err(|_| "invalid flatbuffer")
  }

  /// 获取消息类型
  pub fn get_type(data: &[u8]) -> Result<MessageType, &'static str> {
    let msg = Self::parse(data)?;
    msg.header().map(|h| h.type_()).ok_or("missing header")
  }

  /// 获取序列号
  pub fn get_seq(data: &[u8]) -> Result<u32, &'static str> {
    let msg = Self::parse(data)?;
    msg.header().map(|h| h.seq()).ok_or("missing header")
  }

  /// 获取 session ID
  #[allow(dead_code)]
  pub fn get_session_id(data: &[u8]) -> Result<Option<&str>, &'static str> {
    let msg = Self::parse(data)?;
    Ok(msg.header().and_then(|h| h.session_id()))
  }

  /// 解析响应消息体
  pub fn parse_response(data: &[u8]) -> Result<ParsedResponse, &'static str> {
    let msg = Self::parse(data)?;
    let msg_type = msg.header().map(|h| h.type_()).ok_or("missing header")?;

    match msg_type {
      MessageType::AUTH_RESPONSE => {
        let body = msg
          .body_as_auth_response()
          .ok_or("invalid auth response body")?;
        let mut compatibility_level = body.compatibility_level().0;
        let mut reason_code = body.reason_code().0;
        if body.success()
          && compatibility_level == message::CompatibilityLevel::COMPAT_UNKNOWN.0
          && reason_code == message::CompatibilityReasonCode::REASON_UNKNOWN.0
        {
          // Legacy edge does not return negotiation fields; classify as degraded fallback.
          compatibility_level = message::CompatibilityLevel::COMPAT_DEGRADED.0;
          reason_code = message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK.0;
        }
        Ok(ParsedResponse::AuthResponse(AuthResponseData {
          success: body.success(),
          session_id: body.session_id().unwrap_or("").to_string(),
          server_version: body.server_version().unwrap_or("").to_string(),
          error_code: body.error_code(),
          error_message: body.error_message().unwrap_or("").to_string(),
          server_time: body.server_time(),
          negotiated_protocol_major: body.negotiated_protocol_major(),
          negotiated_protocol_minor: body.negotiated_protocol_minor(),
          accepted_features: body
            .accepted_features()
            .map(|list| list.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
          rejected_features: body
            .rejected_features()
            .map(|list| list.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
          compatibility_level,
          reason_code,
        }))
      }
      MessageType::CERT_RESPONSE => {
        let body = msg
          .body_as_cert_response()
          .ok_or("invalid cert response body")?;
        Ok(ParsedResponse::CertResponse(CertResponseData {
          success: body.success(),
          certificate: body
            .certificate()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
          certificate_chain: body
            .certificate_chain()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(), // 读取证书链
          ca_certificate: body
            .ca_certificate()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
          expires_at: body.expires_at(),
          serial_number: body.serial_number().unwrap_or("").to_string(),
          error_code: body.error_code(),
          error_message: body.error_message().unwrap_or("").to_string(),
        }))
      }
      MessageType::HEARTBEAT_ACK => {
        let body = msg
          .body_as_heartbeat_ack()
          .ok_or("invalid heartbeat ack body")?;
        Ok(ParsedResponse::HeartbeatAck(HeartbeatAckData {
          server_time: body.server_time(),
        }))
      }
      MessageType::DATA_PACKET => {
        let body = msg
          .body_as_data_packet()
          .ok_or("invalid data packet body")?;
        Ok(ParsedResponse::DataPacket(DataPacketData {
          channel_id: body.channel_id().unwrap_or("").to_string(),
          connection_id: body.connection_id().unwrap_or("").to_string(),
          data: body.data().map(|v| v.bytes().to_vec()).unwrap_or_default(),
          flags: body.flags(),
        }))
      }
      MessageType::EDGE_ONLINE_RESPONSE => {
        let body = msg
          .body_as_edge_online_response()
          .ok_or("invalid edge online response body")?;
        Ok(ParsedResponse::EdgeOnlineResponse(EdgeOnlineResponseData {
          success: body.success(),
          error_code: body.error_code(),
          error_message: body.error_message().unwrap_or("").to_string(),
        }))
      }
      MessageType::EDGE_OFFLINE_RESPONSE => {
        let body = msg
          .body_as_edge_offline_response()
          .ok_or("invalid edge offline response body")?;
        Ok(ParsedResponse::EdgeOfflineResponse(
          EdgeOfflineResponseData {
            success: body.success(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::EDGE_LOG_RESPONSE => {
        let body = msg
          .body_as_edge_log_response()
          .ok_or("invalid edge log response body")?;
        Ok(ParsedResponse::EdgeLogResponse(EdgeLogResponseData {
          success: body.success(),
          error_message: body.error_message().unwrap_or("").to_string(),
        }))
      }
      MessageType::EDGE_LOG_PUSH => {
        let body = msg
          .body_as_edge_log_push()
          .ok_or("invalid edge log push body")?;
        let mut log_lines = Vec::new();
        if let Some(lines) = body.log_lines() {
          for i in 0..lines.len() {
            log_lines.push(lines.get(i).to_string());
          }
        }
        Ok(ParsedResponse::EdgeLogPush(EdgeLogPushData { log_lines }))
      }
      MessageType::EDGE_STATUS_PUSH => {
        let body = msg
          .body_as_edge_status_push()
          .ok_or("invalid edge status push body")?;
        let stats = body.stats();
        let mut supported_protocols = Vec::new();
        if let Some(protos) = body.supported_protocols() {
          for i in 0..protos.len() {
            supported_protocols.push(protos.get(i).to_string());
          }
        }
        // EdgeStatusPush no longer carries channel list on wire.
        // Keep an empty list here; upper layers may merge local channel runtime.
        let channels = Vec::new();
        let mut dns01_challenges = Vec::new();
        if let Some(challenges) = body.dns01_challenges() {
          for i in 0..challenges.len() {
            let ch = challenges.get(i);
            dns01_challenges.push(DNS01ChallengeData {
              record_name: ch.record_name().unwrap_or("").to_string(),
              record_value: ch.record_value().unwrap_or("").to_string(),
              domain: ch.domain().unwrap_or("").to_string(),
              created_at: ch.created_at(),
              last_error: ch.last_error().unwrap_or("").to_string(),
              updated_at: ch.updated_at(),
            });
          }
        }
        let assigned_domain_status = body.assigned_domain_status().map(|s| EdgeDomainStatusData {
          dns_status: s.dns_status(),
          cert_status: s.cert_status(),
          error: s.error().unwrap_or("").to_string(),
          cert_last_error: s.cert_last_error().unwrap_or("").to_string(),
          updated_at: s.updated_at(),
        });
        let custom_domain_status = body.custom_domain_status().map(|s| EdgeDomainStatusData {
          dns_status: s.dns_status(),
          cert_status: s.cert_status(),
          error: s.error().unwrap_or("").to_string(),
          cert_last_error: s.cert_last_error().unwrap_or("").to_string(),
          updated_at: s.updated_at(),
        });
        let domain_runtime = body.domain_runtime().map(|rt| {
          let mut required_records = Vec::new();
          if let Some(records) = rt.required_records() {
            for i in 0..records.len() {
              let rec = records.get(i);
              required_records.push(DomainRecordData {
                record_type: rec.record_type().0,
                record_name: rec.record_name().unwrap_or("").to_string(),
                record_value: rec.record_value().unwrap_or("").to_string(),
                ttl: rec.ttl(),
                source: rec.source().unwrap_or("").to_string(),
              });
            }
          }
          DomainRuntimeData {
            owner_view: rt.owner_view(),
            state: rt.state().0,
            required_records,
            pending_reason_code: rt.pending_reason_code().unwrap_or("").to_string(),
            last_error: rt.last_error().unwrap_or("").to_string(),
            cname_status: rt.cname_status(),
            cert_status: rt.cert_status(),
            updated_at: rt.updated_at(),
          }
        });
        let wireguard_relay_runtime_ready = body.wireguard_relay_runtime_ready();
        Ok(ParsedResponse::EdgeStatusPush(EdgeStatusPushData {
          port_usage: body.port_usage().map(|ports| EdgePortUsageData {
            tcp_used: ports.tcp_used(), tcp_total: ports.tcp_total(),
            tcp_range: ports.tcp_range().unwrap_or("").to_string(),
            udp_used: ports.udp_used(), udp_total: ports.udp_total(),
            udp_range: ports.udp_range().unwrap_or("").to_string(),
            http_port: ports.http_port(), https_port: ports.https_port(),
          }),
          edge_id: body.edge_id().unwrap_or("").to_string(),
          online: body.online(),
          uptime: body.uptime(),
          timestamp: body.timestamp(),
          supported_protocols,
          active_sessions: body.active_sessions(),
          total_bytes_in: stats.map(|s| s.total_bytes_in()).unwrap_or(0),
          total_bytes_out: stats.map(|s| s.total_bytes_out()).unwrap_or(0),
          is_owner_view: body.is_owner_view(),
          channels,
          dns01_challenges,
          cname_status: body.cname_status(),
          assigned_domain_status,
          custom_domain_status,
          domain_runtime,
          wireguard_relay_runtime_ready,
        }))
      }
      MessageType::TUNNEL_STATUS_RESPONSE => {
        let body = msg
          .body_as_tunnel_status_response()
          .ok_or("invalid tunnel status response body")?;
        let mut channels = Vec::new();
        if let Some(channel_items) = body.channels() {
          for i in 0..channel_items.len() {
            let ch = channel_items.get(i);
            let active_conns = ch.active_conns();
            let domain_status = ch.domain_status().map(|s| EdgeDomainStatusData {
              dns_status: s.dns_status(),
              cert_status: s.cert_status(),
              error: s.error().unwrap_or("").to_string(),
              cert_last_error: s.cert_last_error().unwrap_or("").to_string(),
              updated_at: s.updated_at(),
            });
            let alias_domain_status = ch.alias_domain_status().map(|s| EdgeDomainStatusData {
              dns_status: s.dns_status(),
              cert_status: s.cert_status(),
              error: s.error().unwrap_or("").to_string(),
              cert_last_error: s.cert_last_error().unwrap_or("").to_string(),
              updated_at: s.updated_at(),
            });
            channels.push(EdgeChannelStatusData {
              channel_id: ch.id().unwrap_or("").to_string(),
              session_id: ch.session_id().unwrap_or("").to_string(),
              user_id: ch.user_id().unwrap_or("").to_string(),
              device_id: ch.device_id().unwrap_or("").to_string(),
              actor_role: ch.actor_role().0,
              actor_session_id: ch.actor_session_id().unwrap_or("").to_string(),
              actor_device_id: ch.actor_device_id().unwrap_or("").to_string(),
              domain: ch.domain().unwrap_or("").to_string(),
              subdomain: ch.subdomain().unwrap_or("").to_string(),
              alias_domain: ch.alias_domain().unwrap_or("").to_string(),
              channel_key: ch.channel_key().unwrap_or("").to_string(),
              protocol: ch.protocol().unwrap_or("").to_string(),
              link_type: ch.link_type().unwrap_or("").to_string(),
              remote_endpoint: ch.remote_endpoint().unwrap_or("").to_string(),
              local_addr: ch.local_addr().unwrap_or("").to_string(),
              state: ch.state().unwrap_or("").to_string(),
              bytes_in: ch.bytes_in(),
              bytes_out: ch.bytes_out(),
              connections: active_conns.max(0) as u32,
              active_conns,
              domain_status,
              alias_domain_status,
            });
          }
        }
        let mut dns01_challenges = Vec::new();
        if let Some(challenges) = body.dns01_challenges() {
          for i in 0..challenges.len() {
            let ch = challenges.get(i);
            dns01_challenges.push(DNS01ChallengeData {
              record_name: ch.record_name().unwrap_or("").to_string(),
              record_value: ch.record_value().unwrap_or("").to_string(),
              domain: ch.domain().unwrap_or("").to_string(),
              created_at: ch.created_at(),
              last_error: ch.last_error().unwrap_or("").to_string(),
              updated_at: ch.updated_at(),
            });
          }
        }
        let custom_domain_status = body.custom_domain_status().map(|s| EdgeDomainStatusData {
          dns_status: s.dns_status(),
          cert_status: s.cert_status(),
          error: s.error().unwrap_or("").to_string(),
          cert_last_error: s.cert_last_error().unwrap_or("").to_string(),
          updated_at: s.updated_at(),
        });
        let domain_runtime = body.domain_runtime().map(|rt| {
          let mut required_records = Vec::new();
          if let Some(records) = rt.required_records() {
            for i in 0..records.len() {
              let rec = records.get(i);
              required_records.push(DomainRecordData {
                record_type: rec.record_type().0,
                record_name: rec.record_name().unwrap_or("").to_string(),
                record_value: rec.record_value().unwrap_or("").to_string(),
                ttl: rec.ttl(),
                source: rec.source().unwrap_or("").to_string(),
              });
            }
          }
          DomainRuntimeData {
            owner_view: rt.owner_view(),
            state: rt.state().0,
            required_records,
            pending_reason_code: rt.pending_reason_code().unwrap_or("").to_string(),
            last_error: rt.last_error().unwrap_or("").to_string(),
            cname_status: rt.cname_status(),
            cert_status: rt.cert_status(),
            updated_at: rt.updated_at(),
          }
        });
        Ok(ParsedResponse::TunnelStatusResponse(
          TunnelStatusResponseData {
            success: body.success(),
            tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
            edge_id: body.edge_id().unwrap_or("").to_string(),
            online: body.online(),
            uptime: body.uptime(),
            timestamp: body.timestamp(),
            total_bytes_in: body.total_bytes_in(),
            total_bytes_out: body.total_bytes_out(),
            channels,
            dns01_challenges,
            cname_status: body.cname_status(),
            custom_domain_status,
            domain_runtime,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_SYNC_RESPONSE => {
        let body = msg
          .body_as_tunnel_sync_response()
          .ok_or("invalid tunnel sync response body")?;
        let mut definitions = Vec::new();
        if let Some(items) = body.definitions() {
          for i in 0..items.len() {
            definitions.push(parse_tunnel_definition_info(items.get(i)));
          }
        }
        Ok(ParsedResponse::TunnelSyncResponse(TunnelSyncResponseData {
          success: body.success(),
          full_snapshot: body.full_snapshot(),
          next_revision: body.next_revision(),
          has_more: body.has_more(),
          definitions,
          error_code: body.error_code(),
          error_message: body.error_message().unwrap_or("").to_string(),
        }))
      }
      MessageType::TUNNEL_UPSERT_RESPONSE => {
        let body = msg
          .body_as_tunnel_upsert_response()
          .ok_or("invalid tunnel upsert response body")?;
        Ok(ParsedResponse::TunnelUpsertResponse(
          TunnelUpsertResponseData {
            success: body.success(),
            conflict: body.conflict(),
            next_revision: body.next_revision(),
            definition: body.definition().map(parse_tunnel_definition_info),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_DELETE_RESPONSE => {
        let body = msg
          .body_as_tunnel_delete_response()
          .ok_or("invalid tunnel delete response body")?;
        Ok(ParsedResponse::TunnelDeleteResponse(
          TunnelDeleteResponseData {
            success: body.success(),
            conflict: body.conflict(),
            tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
            next_revision: body.next_revision(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_START_RESPONSE => {
        let body = msg
          .body_as_tunnel_start_response()
          .ok_or("invalid tunnel start response body")?;
        let summary = parse_tunnel_operation_summary(body.summary());
        let runtime_snapshot = parse_tunnel_runtime_snapshot(body.runtime_snapshot());
        let mut channels = Vec::new();
        if let Some(items) = body.channels() {
          for i in 0..items.len() {
            let item = items.get(i);
            channels.push(TunnelChannelStartResultData {
              key: item.key().unwrap_or("").to_string(),
              channel_id: item.channel_id().unwrap_or("").to_string(),
              success: item.success(),
              error_code: item.error_code(),
              error_message: item.error_message().unwrap_or("").to_string(),
              remote_endpoint: item.remote_endpoint().unwrap_or("").to_string(),
              alias_domain: item.alias_domain().unwrap_or("").to_string(),
              custom_domain: item.custom_domain().unwrap_or("").to_string(),
              assigned_domain: item.assigned_domain().unwrap_or("").to_string(),
              negotiated_buffer_size: item.negotiated_buffer_size(),
            });
          }
        }
        Ok(ParsedResponse::TunnelStartResponse(
          TunnelStartResponseData {
            success: body.success(),
            mode: body.mode().0,
            tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
            edge_id: body.edge_id().unwrap_or("").to_string(),
            summary,
            channels,
            runtime_snapshot,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_JOIN_RESPONSE => {
        let body = msg
          .body_as_tunnel_join_response()
          .ok_or("invalid tunnel join response body")?;
        let summary = parse_tunnel_operation_summary(body.summary());
        let runtime_snapshot = parse_tunnel_runtime_snapshot(body.runtime_snapshot());
        let mut channels = Vec::new();
        if let Some(items) = body.channels() {
          for i in 0..items.len() {
            let item = items.get(i);
            channels.push(TunnelChannelStartResultData {
              key: item.key().unwrap_or("").to_string(),
              channel_id: item.channel_id().unwrap_or("").to_string(),
              success: item.success(),
              error_code: item.error_code(),
              error_message: item.error_message().unwrap_or("").to_string(),
              remote_endpoint: item.remote_endpoint().unwrap_or("").to_string(),
              alias_domain: item.alias_domain().unwrap_or("").to_string(),
              custom_domain: item.custom_domain().unwrap_or("").to_string(),
              assigned_domain: item.assigned_domain().unwrap_or("").to_string(),
              negotiated_buffer_size: item.negotiated_buffer_size(),
            });
          }
        }
        Ok(ParsedResponse::TunnelJoinResponse(
          TunnelStartResponseData {
            success: body.success(),
            mode: body.mode().0,
            tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
            edge_id: body.edge_id().unwrap_or("").to_string(),
            summary,
            channels,
            runtime_snapshot,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_STOP_RESPONSE => {
        let body = msg
          .body_as_tunnel_stop_response()
          .ok_or("invalid tunnel stop response body")?;
        let summary = parse_tunnel_operation_summary(body.summary());
        let runtime_snapshot = parse_tunnel_runtime_snapshot(body.runtime_snapshot());
        let mut channels = Vec::new();
        if let Some(items) = body.channels() {
          for i in 0..items.len() {
            let item = items.get(i);
            channels.push(TunnelChannelStopResultData {
              key: item.key().unwrap_or("").to_string(),
              channel_id: item.channel_id().unwrap_or("").to_string(),
              success: item.success(),
              error_code: item.error_code(),
              error_message: item.error_message().unwrap_or("").to_string(),
            });
          }
        }
        Ok(ParsedResponse::TunnelStopResponse(TunnelStopResponseData {
          success: body.success(),
          mode: body.mode().0,
          tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
          edge_id: body.edge_id().unwrap_or("").to_string(),
          summary,
          channels,
          runtime_snapshot,
          error_code: body.error_code(),
          error_message: body.error_message().unwrap_or("").to_string(),
        }))
      }
      MessageType::TUNNEL_LEAVE_RESPONSE => {
        let body = msg
          .body_as_tunnel_leave_response()
          .ok_or("invalid tunnel leave response body")?;
        let summary = parse_tunnel_operation_summary(body.summary());
        let runtime_snapshot = parse_tunnel_runtime_snapshot(body.runtime_snapshot());
        let mut channels = Vec::new();
        if let Some(items) = body.channels() {
          for i in 0..items.len() {
            let item = items.get(i);
            channels.push(TunnelChannelStopResultData {
              key: item.key().unwrap_or("").to_string(),
              channel_id: item.channel_id().unwrap_or("").to_string(),
              success: item.success(),
              error_code: item.error_code(),
              error_message: item.error_message().unwrap_or("").to_string(),
            });
          }
        }
        Ok(ParsedResponse::TunnelLeaveResponse(
          TunnelStopResponseData {
            success: body.success(),
            mode: body.mode().0,
            tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
            edge_id: body.edge_id().unwrap_or("").to_string(),
            summary,
            channels,
            runtime_snapshot,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::TUNNEL_EVENT_PUSH => {
        let body = msg
          .body_as_tunnel_event_push()
          .ok_or("invalid tunnel event push body")?;
        Ok(ParsedResponse::TunnelEventPush(TunnelEventPushData {
          action: body.action().0,
          next_revision: body.next_revision(),
          definition: body.definition().map(parse_tunnel_definition_info),
        }))
      }
      MessageType::WG_CREATE_NETWORK_ACK => {
        let body = msg
          .body_as_wgcreate_network_response()
          .ok_or("invalid WG_CREATE_NETWORK_ACK body")?;
        let suggested_cidrs = body
          .suggested_cidrs()
          .map(|v| v.iter().map(|s| s.to_string()).collect())
          .unwrap_or_default();
        Ok(ParsedResponse::WGCreateNetworkResponse(
          WGCreateNetworkResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            status: body.status().0,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
            suggested_cidrs,
          },
        ))
      }
      MessageType::WG_JOIN_NETWORK_ACK => {
        let body = msg
          .body_as_wgjoin_network_response()
          .ok_or("invalid WG_JOIN_NETWORK_ACK body")?;
        Ok(ParsedResponse::WGJoinNetworkResponse(
          WGJoinNetworkResponseData {
            success: body.success(),
            member_id: body.member_id().unwrap_or("").to_string(),
            assigned_ip: body.assigned_ip().unwrap_or("").to_string(),
            status: body.status().0,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_CREATE_INVITE_ACK => {
        let body = msg
          .body_as_wgcreate_invite_response()
          .ok_or("invalid WG_CREATE_INVITE_ACK body")?;
        Ok(ParsedResponse::WGCreateInviteResponse(
          WGCreateInviteResponseData {
            success: body.success(),
            invite_token: body.invite_token().unwrap_or("").to_string(),
            expires_at: body.expires_at(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_LEAVE_NETWORK_ACK => {
        let body = msg
          .body_as_wgleave_network_response()
          .ok_or("invalid WG_LEAVE_NETWORK_ACK body")?;
        Ok(ParsedResponse::WGLeaveNetworkResponse(
          WGLeaveNetworkResponseData {
            success: body.success(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_LIST_NETWORKS_ACK => {
        let body = msg
          .body_as_wglist_networks_response()
          .ok_or("invalid WG_LIST_NETWORKS_ACK body")?;
        let mut networks = Vec::new();
        if let Some(items) = body.networks() {
          for i in 0..items.len() {
            networks.push(parse_wg_network_summary_info(items.get(i)));
          }
        }
        Ok(ParsedResponse::WGListNetworksResponse(
          WGListNetworksResponseData {
            success: body.success(),
            revision: body.revision(),
            networks,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_LIST_AVAILABLE_DEVICES_ACK => {
        let body = msg
          .body_as_wglist_available_devices_response()
          .ok_or("invalid WG_LIST_AVAILABLE_DEVICES_ACK body")?;
        let mut devices = Vec::new();
        if let Some(items) = body.devices() {
          for i in 0..items.len() {
            let d = items.get(i);
            devices.push(WGAvailableDeviceData {
              client_id: d.client_id().unwrap_or("").to_string(),
              device_id: d.device_id().unwrap_or("").to_string(),
              hostname: d.hostname().unwrap_or("").to_string(),
              last_active: d.last_active(),
            });
          }
        }
        Ok(ParsedResponse::WGListAvailableDevicesResponse(
          WGListAvailableDevicesResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            devices,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_GET_NETWORK_ACK => {
        let body = msg
          .body_as_wgget_network_response()
          .ok_or("invalid WG_GET_NETWORK_ACK body")?;
        Ok(ParsedResponse::WGGetNetworkResponse(
          WGGetNetworkResponseData {
            success: body.success(),
            snapshot: parse_wg_network_runtime_snapshot(body.snapshot()),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_DELETE_NETWORK_ACK => {
        let body = msg
          .body_as_wgdelete_network_response()
          .ok_or("invalid WG_DELETE_NETWORK_ACK body")?;
        Ok(ParsedResponse::WGDeleteNetworkResponse(
          WGDeleteNetworkResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_UPDATE_NETWORK_CIDR_ACK => {
        let body = msg
          .body_as_wgupdate_network_cidrresponse()
          .ok_or("invalid WG_UPDATE_NETWORK_CIDR_ACK body")?;
        Ok(ParsedResponse::WGUpdateNetworkCIDRResponse(
          WGUpdateNetworkCIDRResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            new_cidr: body.new_cidr().unwrap_or("").to_string(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_UPDATE_NETWORK_RELAY_MODE_ACK => {
        let body = msg
          .body_as_wgupdate_network_relay_mode_response()
          .ok_or("invalid WG_UPDATE_NETWORK_RELAY_MODE_ACK body")?;
        Ok(ParsedResponse::WGUpdateNetworkRelayModeResponse(
          WGUpdateNetworkRelayModeResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            relay_mode: body.relay_mode().0,
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_UPDATE_MEMBER_ACK => {
        let body = msg
          .body_as_wgupdate_member_response()
          .ok_or("invalid WG_UPDATE_MEMBER_ACK body")?;
        Ok(ParsedResponse::WGUpdateMemberResponse(
          WGUpdateMemberResponseData {
            success: body.success(),
            network_id: body.network_id().unwrap_or("").to_string(),
            member_id: body.member_id().unwrap_or("").to_string(),
            new_ip: body.new_ip().unwrap_or("").to_string(),
            new_hostname: body.new_hostname().unwrap_or("").to_string(),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_NETWORK_RUNTIME_RESPONSE => {
        let body = msg
          .body_as_wgnetwork_runtime_response()
          .ok_or("invalid WG_NETWORK_RUNTIME_RESPONSE body")?;
        Ok(ParsedResponse::WGNetworkRuntimeResponse(
          WGNetworkRuntimeResponseData {
            success: body.success(),
            snapshot: parse_wg_network_runtime_snapshot(body.snapshot()),
            error_code: body.error_code(),
            error_message: body.error_message().unwrap_or("").to_string(),
          },
        ))
      }
      MessageType::WG_NETWORK_EVENT_PUSH => {
        let body = msg
          .body_as_wgnetwork_event_push()
          .ok_or("invalid WG_NETWORK_EVENT_PUSH body")?;
        Ok(ParsedResponse::WGNetworkEventPush(WGNetworkEventPushData {
          action: body.action().0,
          network_id: body.network_id().unwrap_or("").to_string(),
          next_revision: body.next_revision(),
          revision_epoch: body.revision_epoch().unwrap_or("").to_string(),
          snapshot: parse_wg_network_runtime_snapshot(body.snapshot()),
        }))
      }
      MessageType::PUSH_REQUEST => {
        let body = msg
          .body_as_push_request()
          .ok_or("invalid push request body")?;
        let mut headers = Vec::new();
        if let Some(h) = body.headers() {
          for i in 0..h.len() {
            let header = h.get(i);
            headers.push(HttpHeader {
              key: header.key().unwrap_or("").to_string(),
              value: header.value().unwrap_or("").to_string(),
            });
          }
        }
        Ok(ParsedResponse::PushRequest(PushRequestData {
          request_id: body.request_id().unwrap_or("").to_string(),
          channel_id: body.channel_id().unwrap_or("").to_string(),
          method: body.method().unwrap_or("").to_string(),
          path: body.path().unwrap_or("").to_string(),
          query: body.query().unwrap_or("").to_string(),
          headers,
          body: body.body().map(|v| v.bytes().to_vec()).unwrap_or_default(),
        }))
      }
      MessageType::ERROR => {
        let body = msg.body_as_error().ok_or("invalid error body")?;
        Ok(ParsedResponse::Error(ErrorData {
          code: body.code().0,
          message: body.message().unwrap_or("").to_string(),
          details: body.details().unwrap_or("").to_string(),
        }))
      }
      MessageType::ICE_START => {
        let body = msg.body_as_icestart().ok_or("invalid ICE_START body")?;
        Ok(ParsedResponse::IceStart(IceStartData {
          ice_session_id: body.ice_session_id().unwrap_or("").to_string(),
          tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
          token: body.token().unwrap_or("").to_string(),
          ice_pwd: body.ice_pwd().unwrap_or("").to_string(),
          edge_udp_addr: body.edge_udp_addr().unwrap_or("").to_string(),
          edge_udp_addr_alt: body.edge_udp_addr_alt().unwrap_or("").to_string(),
          gather_timeout_ms: body.gather_timeout_ms(),
        }))
      }
      MessageType::ICE_PUNCH => {
        let body = msg.body_as_icepunch().ok_or("invalid ICE_PUNCH body")?;
        let mut extra_target_addrs = Vec::new();
        if let Some(addrs) = body.extra_target_addrs() {
          for i in 0..addrs.len() {
            extra_target_addrs.push(addrs.get(i).to_string());
          }
        }
        Ok(ParsedResponse::IcePunch(IcePunchData {
          ice_session_id: body.ice_session_id().unwrap_or("").to_string(),
          target_addr: body.target_addr().unwrap_or("").to_string(),
          token: body.token().unwrap_or("").to_string(),
          ice_pwd: body.ice_pwd().unwrap_or("").to_string(),
          attempts: body.attempts(),
          interval_ms: body.interval_ms(),
          start_delay_ms: body.start_delay_ms(),
          extra_target_addrs,
        }))
      }
      MessageType::ICE_QUIC_START => {
        let body = msg
          .body_as_icequic_start()
          .ok_or("invalid ICE_QUIC_START body")?;
        Ok(ParsedResponse::IceQuicStart(IceQuicStartData {
          ice_session_id: body.ice_session_id().unwrap_or("").to_string(),
          role: body.role().0,
          peer_addr: body.peer_addr().unwrap_or("").to_string(),
          alpn: body.alpn().unwrap_or("").to_string(),
          connect_timeout_ms: body.connect_timeout_ms(),
        }))
      }
      MessageType::ICE_STATE => {
        let body = msg
          .body_as_icestate_change()
          .ok_or("invalid ICE_STATE body")?;
        Ok(ParsedResponse::IceStateChange(IceStateChangeData {
          ice_session_id: body.ice_session_id().unwrap_or("").to_string(),
          tunnel_id: body.tunnel_id().unwrap_or("").to_string(),
          state: body.state().unwrap_or("").to_string(),
          strategy: body.strategy().0,
          error: body.error().unwrap_or("").to_string(),
        }))
      }
      _ => Ok(ParsedResponse::Unknown(msg_type.0)),
    }
  }

  /// 解析认证响应
  pub fn parse_auth_response(data: &[u8]) -> Result<AuthResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::AuthResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(AuthResponseData {
        success: false,
        session_id: String::new(),
        server_version: String::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
        server_time: 0,
        negotiated_protocol_major: 1,
        negotiated_protocol_minor: 0,
        accepted_features: Vec::new(),
        rejected_features: Vec::new(),
        compatibility_level: message::CompatibilityLevel::COMPAT_INCOMPATIBLE.0,
        reason_code: message::CompatibilityReasonCode::REASON_UNKNOWN.0,
      }),
      _ => Err("not an auth response"),
    }
  }

  /// 解析证书签发响应
  pub fn parse_cert_response(data: &[u8]) -> Result<CertResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::CertResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(CertResponseData {
        success: false,
        certificate: Vec::new(),
        certificate_chain: Vec::new(),
        ca_certificate: Vec::new(),
        expires_at: 0,
        serial_number: String::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a cert response"),
    }
  }

  /// 解析心跳响应
  #[allow(dead_code)]
  pub fn parse_heartbeat_ack(data: &[u8]) -> Result<HeartbeatAckData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::HeartbeatAck(r) => Ok(r),
      _ => Err("not a heartbeat ack"),
    }
  }

  /// 解析 Edge 上线响应
  pub fn parse_edge_online_response(data: &[u8]) -> Result<EdgeOnlineResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::EdgeOnlineResponse(r) => Ok(r),
      _ => Err("not an edge online response"),
    }
  }

  /// 解析 Edge 下线响应
  pub fn parse_edge_offline_response(data: &[u8]) -> Result<EdgeOfflineResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::EdgeOfflineResponse(r) => Ok(r),
      _ => Err("not an edge offline response"),
    }
  }

  /// 解析 Edge 日志响应
  pub fn parse_edge_log_response(data: &[u8]) -> Result<EdgeLogResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::EdgeLogResponse(r) => Ok(r),
      _ => Err("not an edge log response"),
    }
  }

  /// 解析 Edge 日志推送
  pub fn parse_edge_log_push(data: &[u8]) -> Result<EdgeLogPushData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::EdgeLogPush(r) => Ok(r),
      _ => Err("not an edge log push"),
    }
  }

  /// 解析 Edge 状态推送
  pub fn parse_edge_status_push(data: &[u8]) -> Result<EdgeStatusPushData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::EdgeStatusPush(r) => Ok(r),
      _ => Err("not an edge status push"),
    }
  }

  /// 解析 Tunnel 状态响应
  pub fn parse_tunnel_status_response(
    data: &[u8],
  ) -> Result<TunnelStatusResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelStatusResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelStatusResponseData {
        success: false,
        tunnel_id: String::new(),
        edge_id: String::new(),
        online: false,
        uptime: 0,
        timestamp: 0,
        total_bytes_in: 0,
        total_bytes_out: 0,
        channels: Vec::new(),
        dns01_challenges: Vec::new(),
        cname_status: 0,
        custom_domain_status: None,
        domain_runtime: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel status response"),
    }
  }

  /// 解析 Tunnel 同步响应
  pub fn parse_tunnel_sync_response(data: &[u8]) -> Result<TunnelSyncResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelSyncResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelSyncResponseData {
        success: false,
        full_snapshot: false,
        next_revision: 0,
        has_more: false,
        definitions: Vec::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel sync response"),
    }
  }

  /// 解析 Tunnel upsert 响应
  pub fn parse_tunnel_upsert_response(
    data: &[u8],
  ) -> Result<TunnelUpsertResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelUpsertResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelUpsertResponseData {
        success: false,
        conflict: false,
        next_revision: 0,
        definition: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel upsert response"),
    }
  }

  /// 解析 Tunnel delete 响应
  pub fn parse_tunnel_delete_response(
    data: &[u8],
  ) -> Result<TunnelDeleteResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelDeleteResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelDeleteResponseData {
        success: false,
        conflict: false,
        tunnel_id: String::new(),
        next_revision: 0,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel delete response"),
    }
  }

  /// 解析 Tunnel start 响应
  pub fn parse_tunnel_start_response(data: &[u8]) -> Result<TunnelStartResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelStartResponse(r) | ParsedResponse::TunnelJoinResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelStartResponseData {
        success: false,
        mode: TunnelStartMode::ALL_OR_NOTHING.0,
        tunnel_id: String::new(),
        edge_id: String::new(),
        summary: TunnelOperationSummaryData {
          requested: 0,
          succeeded: 0,
          failed: 0,
        },
        channels: Vec::new(),
        runtime_snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel start response"),
    }
  }

  /// 解析 Tunnel stop 响应
  pub fn parse_tunnel_stop_response(data: &[u8]) -> Result<TunnelStopResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelStopResponse(r) | ParsedResponse::TunnelLeaveResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelStopResponseData {
        success: false,
        mode: TunnelStartMode::ALL_OR_NOTHING.0,
        tunnel_id: String::new(),
        edge_id: String::new(),
        summary: TunnelOperationSummaryData {
          requested: 0,
          succeeded: 0,
          failed: 0,
        },
        channels: Vec::new(),
        runtime_snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel stop response"),
    }
  }

  /// 解析 Tunnel join 响应
  pub fn parse_tunnel_join_response(data: &[u8]) -> Result<TunnelStartResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelJoinResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelStartResponseData {
        success: false,
        mode: TunnelStartMode::ALL_OR_NOTHING.0,
        tunnel_id: String::new(),
        edge_id: String::new(),
        summary: TunnelOperationSummaryData {
          requested: 0,
          succeeded: 0,
          failed: 0,
        },
        channels: Vec::new(),
        runtime_snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel join response"),
    }
  }

  /// 解析 Tunnel leave 响应
  pub fn parse_tunnel_leave_response(data: &[u8]) -> Result<TunnelStopResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelLeaveResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(TunnelStopResponseData {
        success: false,
        mode: TunnelStartMode::ALL_OR_NOTHING.0,
        tunnel_id: String::new(),
        edge_id: String::new(),
        summary: TunnelOperationSummaryData {
          requested: 0,
          succeeded: 0,
          failed: 0,
        },
        channels: Vec::new(),
        runtime_snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a tunnel leave response"),
    }
  }

  /// 解析 WG 列表响应
  pub fn parse_wg_list_networks_response(
    data: &[u8],
  ) -> Result<WGListNetworksResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGListNetworksResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGListNetworksResponseData {
        success: false,
        revision: 0,
        networks: Vec::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG list networks response"),
    }
  }

  /// 解析 WG 可用设备列表响应
  pub fn parse_wg_list_available_devices_response(
    data: &[u8],
  ) -> Result<WGListAvailableDevicesResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGListAvailableDevicesResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGListAvailableDevicesResponseData {
        success: false,
        network_id: String::new(),
        devices: Vec::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG list available devices response"),
    }
  }

  /// 解析 WG 详情响应
  pub fn parse_wg_get_network_response(
    data: &[u8],
  ) -> Result<WGGetNetworkResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGGetNetworkResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGGetNetworkResponseData {
        success: false,
        snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG get network response"),
    }
  }

  /// 解析 WG runtime 响应
  pub fn parse_wg_network_runtime_response(
    data: &[u8],
  ) -> Result<WGNetworkRuntimeResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGNetworkRuntimeResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGNetworkRuntimeResponseData {
        success: false,
        snapshot: None,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG network runtime response"),
    }
  }

  /// 解析 WG 创建响应
  pub fn parse_wg_create_network_response(
    data: &[u8],
  ) -> Result<WGCreateNetworkResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGCreateNetworkResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGCreateNetworkResponseData {
        success: false,
        network_id: String::new(),
        status: 0,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
        suggested_cidrs: Vec::new(),
      }),
      _ => Err("not a WG create network response"),
    }
  }

  /// 解析 WG 加入响应
  pub fn parse_wg_join_network_response(
    data: &[u8],
  ) -> Result<WGJoinNetworkResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGJoinNetworkResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGJoinNetworkResponseData {
        success: false,
        member_id: String::new(),
        assigned_ip: String::new(),
        status: 0,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG join network response"),
    }
  }

  /// 解析 WG 创建邀请 token 响应
  pub fn parse_wg_create_invite_response(
    data: &[u8],
  ) -> Result<WGCreateInviteResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGCreateInviteResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGCreateInviteResponseData {
        success: false,
        invite_token: String::new(),
        expires_at: 0,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG create invite response"),
    }
  }

  /// 解析 WG 离开响应
  pub fn parse_wg_leave_network_response(
    data: &[u8],
  ) -> Result<WGLeaveNetworkResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGLeaveNetworkResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGLeaveNetworkResponseData {
        success: false,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG leave network response"),
    }
  }

  /// 解析 WG 删除响应
  pub fn parse_wg_delete_network_response(
    data: &[u8],
  ) -> Result<WGDeleteNetworkResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGDeleteNetworkResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGDeleteNetworkResponseData {
        success: false,
        network_id: String::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG delete network response"),
    }
  }

  pub fn parse_wg_update_network_cidr_response(
    data: &[u8],
  ) -> Result<WGUpdateNetworkCIDRResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGUpdateNetworkCIDRResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGUpdateNetworkCIDRResponseData {
        success: false,
        network_id: String::new(),
        new_cidr: String::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG update network CIDR response"),
    }
  }

  pub fn parse_wg_update_network_relay_mode_response(
    data: &[u8],
  ) -> Result<WGUpdateNetworkRelayModeResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGUpdateNetworkRelayModeResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGUpdateNetworkRelayModeResponseData {
        success: false,
        network_id: String::new(),
        relay_mode: 0,
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG update network relay mode response"),
    }
  }

  pub fn parse_wg_update_member_response(
    data: &[u8],
  ) -> Result<WGUpdateMemberResponseData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGUpdateMemberResponse(r) => Ok(r),
      ParsedResponse::Error(r) => Ok(WGUpdateMemberResponseData {
        success: false,
        network_id: String::new(),
        member_id: String::new(),
        new_ip: String::new(),
        new_hostname: String::new(),
        error_code: r.code,
        error_message: if r.details.is_empty() {
          r.message
        } else {
          format!("{}: {}", r.message, r.details)
        },
      }),
      _ => Err("not a WG update member response"),
    }
  }

  /// 解析 Tunnel 事件推送
  pub fn parse_tunnel_event_push(data: &[u8]) -> Result<TunnelEventPushData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::TunnelEventPush(r) => Ok(r),
      _ => Err("not a tunnel event push"),
    }
  }

  pub fn parse_wg_network_event_push(data: &[u8]) -> Result<WGNetworkEventPushData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::WGNetworkEventPush(r) => Ok(r),
      _ => Err("not a wg network event push"),
    }
  }

  pub fn parse_ice_start(data: &[u8]) -> Result<IceStartData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::IceStart(r) => Ok(r),
      _ => Err("not an ICE_START"),
    }
  }

  pub fn parse_ice_punch(data: &[u8]) -> Result<IcePunchData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::IcePunch(r) => Ok(r),
      _ => Err("not an ICE_PUNCH"),
    }
  }

  pub fn parse_ice_quic_start(data: &[u8]) -> Result<IceQuicStartData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::IceQuicStart(r) => Ok(r),
      _ => Err("not an ICE_QUIC_START"),
    }
  }

  pub fn parse_ice_state_change(data: &[u8]) -> Result<IceStateChangeData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::IceStateChange(r) => Ok(r),
      _ => Err("not an ICE_STATE"),
    }
  }

  /// 解析 Data Packet
  pub fn parse_data_packet(data: &[u8]) -> Result<DataPacketData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::DataPacket(r) => Ok(r),
      _ => Err("not a data packet"),
    }
  }

  /// 解析错误响应
  #[allow(dead_code)]
  pub fn parse_error(data: &[u8]) -> Result<ErrorData, &'static str> {
    match Self::parse_response(data)? {
      ParsedResponse::Error(r) => Ok(r),
      _ => Err("not an error"),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn edge_config_requests_preserve_session_sequence_and_explicit_zero() {
    assert_eq!(MessageType::EDGE_CONFIG_REQUEST.0, 0x600B);
    assert_eq!(MessageType::EDGE_CONFIG_RESPONSE.0, 0x600C);
    assert_eq!(MessageBody::EdgeDomainCertificateResponse.0, 83);
    assert_eq!(MessageBody::EdgeConfigRequest.0, 84);
    assert_eq!(MessageBody::EdgeConfigResponse.0, 85);
    for config in ["", r#"{"tunnel":{"limits":{"max_total":0}}}"#] {
      let bytes = MessageBuilder::new().seq(42).session_id("owner-session")
        .edge_config_request(config);
      let wire = message::root_as_message(&bytes).unwrap();
      let header = wire.header().unwrap();
      assert_eq!(header.type_(), MessageType::EDGE_CONFIG_REQUEST);
      assert_eq!(header.seq(), 42);
      assert_eq!(header.session_id(), Some("owner-session"));
      assert_eq!(wire.body_as_edge_config_request().unwrap().config_json(), Some(config));
    }
  }

  #[test]
  fn edge_status_ports_survive_flatbuffers_and_json_without_defaults() {
    for with_ports in [true, false] {
      let mut builder = FlatBufferBuilder::new();
      let wire = message::MessageT {
        header: Some(Box::new(message::MessageHeaderT {
          type_: message::MessageType::EDGE_STATUS_PUSH, ..Default::default()
        })),
        body: message::MessageBodyT::EdgeStatusPush(Box::new(message::EdgeStatusPushT {
          edge_id: Some("edge-ports".into()), online: true,
          port_usage: with_ports.then(|| Box::new(message::PortUsageInfoT {
            http_port: 18080, https_port: 0, tcp_used: 2, tcp_total: 1001,
            tcp_range: Some("22000-23000".into()), udp_range: Some("24000-25000".into()),
            ..Default::default()
          })), ..Default::default()
        })),
      };
      let root = wire.pack(&mut builder);
      builder.finish(root, None);
      let parsed = MessageReader::parse_edge_status_push(builder.finished_data()).unwrap();
      let json = serde_json::to_value(&parsed).unwrap();
      if with_ports {
        let ports = parsed.port_usage.unwrap();
        assert_eq!(ports.http_port, 18080);
        assert_eq!(ports.https_port, 0);
        assert_eq!(ports.tcp_range, "22000-23000");
        assert_eq!(json["port_usage"]["udp_range"], "24000-25000");
      } else {
        assert!(parsed.port_usage.is_none());
        assert!(json["port_usage"].is_null());
      }
    }
  }

  #[test]
  fn wg_path_pairs_preserve_raw_evidence_and_lossless_versions() {
    let v = message::WGPathVersionT {
      network_id: Some("net".into()), member_a_id: Some("a".into()), member_b_id: Some("b".into()),
      authority_epoch: Some("epoch".into()), pair_revision: u64::MAX,
      network_policy_revision: u64::MAX, ..Default::default()
    };
    let mut b = FlatBufferBuilder::new();
    let wire = message::WGNetworkRuntimeSnapshotInfoT {
      revision_epoch: Some("stream-epoch".into()),
      path_authority_epoch: Some("epoch".into()), network_policy_revision: u64::MAX,
      path_pairs: Some(vec![message::WGPathPairRuntimeInfoT {
        plan: Some(Box::new(message::WGPathPlanT {
          version: Some(Box::new(v.clone())), phase: message::WGPathPhase::VERIFY,
          target_path: message::WGPathType::DIRECT, ..Default::default()
        })),
        report_a: Some(Box::new(message::WGPathReportT {
          version: Some(Box::new(v.clone())), member_id: Some("a".into()),
          command_id: Some("apply-command-42".into()),
          kind: message::WGPathReportKind::APPLIED, handshake_at: u64::MAX,
          actual_path: message::WGPathType::DIRECT, actual_endpoint: Some("192.0.2.2:51820".into()),
          applied_version: Some(Box::new(v)), ..Default::default()
        })), ..Default::default()
      }]), ..Default::default()
    };
    let root = wire.pack(&mut b);
    b.finish(root, None);
    let raw = flatbuffers::root::<message::WGNetworkRuntimeSnapshotInfo<'_>>(b.finished_data()).unwrap();
    let parsed = parse_wg_network_runtime_snapshot(Some(raw)).unwrap();
    let pair = &parsed.path_pairs[0];
    assert_eq!(pair.version.as_ref().unwrap().pair_revision, u64::MAX.to_string());
    assert_eq!(parsed.revision_epoch, "stream-epoch");
    assert_eq!(pair.version.as_ref().unwrap().network_policy_revision, u64::MAX.to_string());
    let report = pair.report_a.as_ref().unwrap();
    assert_eq!(report.kind, message::WGPathReportKind::APPLIED.0 as u32);
    assert_eq!(report.command_id, "apply-command-42");
    assert_eq!(report.handshake_at, u64::MAX.to_string());
    assert_eq!(report.business_replies, 0);
    assert!(pair.report_b.is_none());
    assert!(serde_json::to_string(pair).unwrap().contains("18446744073709551615"));
  }

  #[test]
  fn wg_bootstrap_snapshot_preserves_versions_and_legacy_absence() {
    for present in [false, true] {
      let mut b = FlatBufferBuilder::new();
      let wire = message::WGNetworkRuntimeSnapshotInfoT {
        network: Some(Box::new(message::WGNetworkDetailInfoT {
          network_id: Some("net".into()),
          coordinator_edge_id: Some("edge".into()),
          ..Default::default()
        })),
        members: Some(vec![message::WGNetworkMemberInfoT {
          member_id: Some("self".into()),
          membership_generation: present.then(|| "membership".into()),
          ..Default::default()
        }]),
        path_authority_epoch: present.then(|| "epoch".into()),
        network_policy_revision: if present { u64::MAX } else { 0 },
        ..Default::default()
      };
      let root = wire.pack(&mut b);
      b.finish(root, None);
      let raw =
        flatbuffers::root::<message::WGNetworkRuntimeSnapshotInfo<'_>>(b.finished_data()).unwrap();
      let parsed = parse_wg_network_runtime_snapshot(Some(raw)).unwrap();
      assert!(parsed.path_pairs.is_empty());
      assert_eq!(parsed.network.network_id, "net");
      assert_eq!(
        parsed.members[0].membership_generation,
        if present { "membership" } else { "" }
      );
      assert_eq!(
        parsed.path_authority_epoch,
        if present { "epoch" } else { "" }
      );
      assert_eq!(
        parsed.network_policy_revision,
        if present { u64::MAX } else { 0 }
      );
    }
  }
  use flatbuffers::FlatBufferBuilder;

  fn build_error_response(
    code: message::ErrorCode,
    message_text: &str,
    details_text: &str,
  ) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();

    let msg_offset = builder.create_string(message_text);
    let details_offset = builder.create_string(details_text);
    let session_id_offset = builder.create_string("");

    let error = message::Error::create(
      &mut builder,
      &message::ErrorArgs {
        code,
        message: Some(msg_offset),
        details: Some(details_offset),
      },
    );

    let header = MessageHeader::create(
      &mut builder,
      &MessageHeaderArgs {
        type_: MessageType::ERROR,
        seq: 0,
        timestamp: 0,
        session_id: Some(session_id_offset),
      },
    );

    let message = Message::create(
      &mut builder,
      &MessageArgs {
        header: Some(header),
        body_type: MessageBody::Error,
        body: Some(error.as_union_value()),
      },
    );

    builder.finish(message, None);
    builder.finished_data().to_vec()
  }

  #[test]
  fn test_heartbeat_roundtrip() {
    let data = MessageBuilder::new()
      .seq(123)
      .session_id("test-session")
      .heartbeat();

    let msg_type = MessageReader::get_type(&data).unwrap();
    assert_eq!(msg_type, MessageType::HEARTBEAT);

    let seq = MessageReader::get_seq(&data).unwrap();
    assert_eq!(seq, 123);

    let session_id = MessageReader::get_session_id(&data).unwrap();
    assert_eq!(session_id, Some("test-session"));
  }

  #[test]
  fn test_edge_online_request() {
    let data = MessageBuilder::new().seq(1).edge_online_request();

    let msg_type = MessageReader::get_type(&data).unwrap();
    assert_eq!(msg_type, MessageType::EDGE_ONLINE_REQUEST);
  }

  #[test]
  fn test_edge_offline_request() {
    let data = MessageBuilder::new().seq(2).edge_offline_request();

    let msg_type = MessageReader::get_type(&data).unwrap();
    assert_eq!(msg_type, MessageType::EDGE_OFFLINE_REQUEST);
  }

  #[test]
  fn test_parse_cert_response_from_error_message() {
    let data = build_error_response(
      message::ErrorCode::INTERNAL_ERROR,
      "certificate signing failed",
      "sign certificate failed: edge: get node failed",
    );

    let response = MessageReader::parse_cert_response(&data).unwrap();

    assert!(!response.success);
    assert!(response.certificate.is_empty());
    assert!(response.certificate_chain.is_empty());
    assert!(response.ca_certificate.is_empty());
    assert_eq!(response.expires_at, 0);
    assert_eq!(response.serial_number, "");
    assert_eq!(response.error_code, message::ErrorCode::INTERNAL_ERROR.0);
    assert_eq!(
      response.error_message,
      "certificate signing failed: sign certificate failed: edge: get node failed"
    );
  }
}

#[cfg(test)]
mod unified_enrollment_tests {
  use super::*;

  #[test]
  fn token_is_the_only_enrollment_credential_on_wire() {
    for token in ["invite:secret", "pair:secret", "oauth:github:secret", "public:"] {
      let bytes = MessageBuilder::new().cert_request(token, "device-a", b"csr", &[]);
      let message = message::root_as_message(&bytes).unwrap();
      let request = message.body_as_cert_request().unwrap();
      assert_eq!(request.token(), Some(token));
      assert_eq!(request.device_id(), Some("device-a"));
      assert_eq!(request._tab.vtable().get(14), 0);
      assert_eq!(request._tab.vtable().get(4), 0);
      assert_eq!(request._tab.vtable().get(6), 0);
    }
  }

  #[test]
  fn authentication_has_no_caller_supplied_user_identity() {
    let bytes = MessageBuilder::new().auth_request("device-a", "host", "1", &[], 1, 0, &[], &[]);
    let message = message::root_as_message(&bytes).unwrap();
    let request = message.body_as_auth_request().unwrap();
    assert_eq!(request.user_id(), None);
    assert_eq!(request.device_id(), Some("device-a"));
  }
}
