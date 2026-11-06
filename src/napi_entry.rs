// NAPI bindings entry point — only compiled with "napi-bindings" feature.
// This file is included by lib.rs via `mod napi_entry`.

// Sibling module references (needed because this is a child module of the crate root)
use crate::client;
use crate::ice;

use napi::bindgen_prelude::Buffer;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use serde_json::json;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;

// 使用 napi 的 Result 和 Error
type Result<T> = napi::Result<T>;
use napi::Error;

// 全局 Tokio 运行时，用于支持同步函数中的 spawn
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

// 获取或创建全局运行时
fn get_runtime() -> &'static tokio::runtime::Runtime {
  RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"))
}

// 移除 ANSI 转义码（终端颜色控制字符）
fn strip_ansi_codes(s: &str) -> String {
  let mut result = String::with_capacity(s.len());
  let mut chars = s.chars();

  while let Some(ch) = chars.next() {
    if ch == '\x1b' || ch == '\u{1b}' {
      // 跳过 ESC 后的控制序列
      // 常见格式: ESC [ ... m (颜色) 或 ESC [ ... ~ (其他)
      if let Some('[') = chars.next() {
        // 跳过直到找到结束字符 (m, H, J, K, 等)
        for next_ch in chars.by_ref() {
          if next_ch.is_ascii_alphabetic() {
            break;
          }
        }
      }
    } else {
      result.push(ch);
    }
  }

  result
}

// ==================== 证书申请 ====================

/// 证书申请结果
#[napi(object)]
pub struct JsCertResult {
  /// 客户端证书 (PEM)
  pub certificate: Buffer,
  /// 证书链 (PEM) - 包含叶子证书 + 中间 CA
  pub certificate_chain: Buffer,
  /// 私钥 (PEM)
  pub private_key: Buffer,
  /// CA 证书链 (PEM)
  pub ca_certificate: Buffer,
  /// 过期时间戳（毫秒）
  pub expires_at: f64,
  /// 证书序列号
  pub serial_number: String,
}

/// 申请客户端证书
///
/// Request a device certificate using one prefixed enrollment token.
#[napi]
pub async fn request_certificate(
  host: String,
  port: u16,
  server_name: Option<String>,
  ca_cert: Buffer,
  token: String,
  device_id: String,
  edge_id: Option<String>,
  scopes: Option<Vec<String>>,
) -> Result<JsCertResult> {
  let config = client::edge_client::EdgeClientConfig {
    host,
    port,
    ca_cert: ca_cert.to_vec(),
    client_cert: None,
    client_key: None,
    heartbeat_interval_secs: 30,
    quic_keepalive_secs: 15,
    quic_idle_timeout_secs: 300,
    edge_id,
    server_name,
  };

  let edge_client = client::EdgeClient::new(config);

  let result = edge_client
    .request_certificate(
      &token,
      &device_id,
      scopes.as_deref().unwrap_or(&[]),
    )
    .await
    .map_err(|e| Error::from_reason(e.to_string()))?;

  Ok(JsCertResult {
    certificate: Buffer::from(result.certificate),
    certificate_chain: Buffer::from(result.certificate_chain), // 新增：证书链
    private_key: Buffer::from(result.private_key),
    ca_certificate: Buffer::from(result.ca_certificate),
    expires_at: result.expires_at as f64,
    serial_number: result.serial_number,
  })
}

// ==================== EdgeClient NAPI 类 ====================

/// Edge 客户端配置
#[napi(object)]
pub struct JsEdgeClientConfig {
  pub host: String,
  pub port: u16,
  pub ca_cert: Buffer,
  pub client_cert: Buffer,
  pub client_key: Buffer,
  pub heartbeat_interval_secs: Option<u32>,
  pub quic_keepalive_secs: Option<u32>,
  pub quic_idle_timeout_secs: Option<u32>,
  pub edge_id: Option<String>,
  pub server_name: Option<String>,
}

/// 认证参数
#[napi(object)]
pub struct JsAuthParams {
  pub device_id: String,
  pub hostname: Option<String>,
  pub client_version: String,
  pub capabilities: Vec<String>,
  pub protocol_major: Option<u32>,
  pub protocol_minor: Option<u32>,
  pub required_features: Option<Vec<String>>,
  pub requested_features: Option<Vec<String>>,
}

/// 认证结果
#[napi(object)]
pub struct JsAuthResult {
  pub success: bool,
  pub session_id: String,
  pub server_version: String,
  pub error_code: u32,
  pub error_message: String,
  pub negotiated_protocol_major: u32,
  pub negotiated_protocol_minor: u32,
  pub accepted_features: Vec<String>,
  pub rejected_features: Vec<String>,
  pub compatibility_level: u32,
  pub reason_code: u32,
}

/// Edge 操作结果
#[napi(object)]
pub struct JsEdgeResult {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// DNS-01 挑战信息
#[napi(object)]
pub struct JsDns01Challenge {
  pub record_name: String,
  pub record_value: String,
  pub domain: String,
  pub created_at: f64,
  pub last_error: String,
  pub updated_at: f64,
}

/// 域名引导记录
#[napi(object)]
pub struct JsDomainRecord {
  pub record_type: u32,
  pub record_name: String,
  pub record_value: String,
  pub ttl: u32,
  pub source: String,
}

/// 统一域名运行态
#[napi(object)]
pub struct JsDomainRuntime {
  pub owner_view: bool,
  pub state: u32,
  pub required_records: Vec<JsDomainRecord>,
  pub pending_reason_code: String,
  pub last_error: String,
  pub cname_status: u32,
  pub cert_status: u32,
  pub updated_at: f64,
}

/// 域名状态信息（DNS + 证书）
#[napi(object)]
pub struct JsDomainStatus {
  pub dns_status: u32,
  pub cert_status: u32,
  pub error: String,
  pub cert_last_error: String,
  pub updated_at: f64,
}

/// Channel 维度域名状态信息
#[napi(object)]
pub struct JsEdgeChannelStatus {
  pub channel_id: String,
  pub session_id: String,
  pub user_id: String,
  pub device_id: String,
  pub actor_role: u32,
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
  pub bytes_in: f64,
  pub bytes_out: f64,
  pub connections: u32,
  pub active_conns: i32,
  pub domain_status: Option<JsDomainStatus>,
  pub alias_domain_status: Option<JsDomainStatus>,
}

/// Edge 状态结果
#[napi(object)]
pub struct JsEdgeStatusResult {
  pub edge_id: String,
  pub online: bool,
  pub uptime: f64,
  pub timestamp: f64,
  pub supported_protocols: Vec<String>,
  pub active_sessions: i32,
  pub total_bytes_in: f64,
  pub total_bytes_out: f64,
  pub is_owner_view: bool,
  pub channels: Vec<JsEdgeChannelStatus>,
  pub dns01_challenges: Vec<JsDns01Challenge>,
  pub cname_status: u32,
  pub assigned_domain_status: Option<JsDomainStatus>,
  pub custom_domain_status: Option<JsDomainStatus>,
  pub domain_runtime: Option<JsDomainRuntime>,
}

/// Tunnel 状态结果（单 tunnel）
#[napi(object)]
pub struct JsTunnelStatusResult {
  pub success: bool,
  pub tunnel_id: String,
  pub edge_id: String,
  pub online: bool,
  pub uptime: f64,
  pub timestamp: f64,
  pub total_bytes_in: f64,
  pub total_bytes_out: f64,
  pub channels: Vec<JsEdgeChannelStatus>,
  pub dns01_challenges: Vec<JsDns01Challenge>,
  pub cname_status: u32,
  pub custom_domain_status: Option<JsDomainStatus>,
  pub domain_runtime: Option<JsDomainRuntime>,
  pub error_code: u32,
  pub error_message: String,
}

/// 日志订阅结果
#[napi(object)]
pub struct JsLogSubscriptionResult {
  pub success: bool,
  pub error_message: String,
}

/// Tunnel 定义对象
#[napi(object)]
pub struct JsTunnelDefinition {
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
  pub actor_role: u32,
  pub actor_session_id: String,
  pub actor_device_id: String,
  pub version: f64,
  pub revision: f64,
  pub deleted: bool,
  pub created_at: f64,
  pub updated_at: f64,
}

/// Tunnel 增量同步结果
#[napi(object)]
pub struct JsTunnelSyncResult {
  pub success: bool,
  pub full_snapshot: bool,
  pub next_revision: f64,
  pub has_more: bool,
  pub definitions: Vec<JsTunnelDefinition>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel upsert 结果
#[napi(object)]
pub struct JsTunnelUpsertResult {
  pub success: bool,
  pub conflict: bool,
  pub next_revision: f64,
  pub definition: Option<JsTunnelDefinition>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel delete 结果
#[napi(object)]
pub struct JsTunnelDeleteResult {
  pub success: bool,
  pub conflict: bool,
  pub tunnel_id: String,
  pub next_revision: f64,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel start/stop actor 上下文
#[napi(object)]
pub struct JsTunnelActorContext {
  pub role: u32,
  pub session_id: String,
  pub device_id: String,
}

/// Tunnel start channel 规格
#[napi(object)]
pub struct JsTunnelChannelStartSpec {
  pub key: String,
  pub protocol: String,
  pub local_host: Option<String>,
  pub local_port: u32,
  pub remote_port: Option<u32>,
  pub subdomain: Option<String>,
  pub alias_domain: Option<String>,
  pub buffer_size: Option<u32>,
  pub transport: Option<String>,
  pub eager_connect_remote: Option<bool>,
  pub metadata_json: Option<String>,
}

/// Tunnel 操作汇总
#[napi(object)]
pub struct JsTunnelOperationSummary {
  pub requested: u32,
  pub succeeded: u32,
  pub failed: u32,
}

/// Tunnel 运行态快照
#[napi(object)]
pub struct JsTunnelRuntimeSnapshot {
  pub tunnel_id: String,
  pub state: String,
  pub runtime_json: String,
  pub updated_at: f64,
}

/// Tunnel start 单 channel 结果
#[napi(object)]
pub struct JsTunnelChannelStartResult {
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

/// Tunnel stop 单 channel 结果
#[napi(object)]
pub struct JsTunnelChannelStopResult {
  pub key: String,
  pub channel_id: String,
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel start 结果
#[napi(object)]
pub struct JsTunnelStartResult {
  pub success: bool,
  pub mode: u32,
  pub tunnel_id: String,
  pub edge_id: String,
  pub summary: JsTunnelOperationSummary,
  pub channels: Vec<JsTunnelChannelStartResult>,
  pub runtime_snapshot: Option<JsTunnelRuntimeSnapshot>,
  pub error_code: u32,
  pub error_message: String,
}

/// Tunnel stop 结果
#[napi(object)]
pub struct JsTunnelStopResult {
  pub success: bool,
  pub mode: u32,
  pub tunnel_id: String,
  pub edge_id: String,
  pub summary: JsTunnelOperationSummary,
  pub channels: Vec<JsTunnelChannelStopResult>,
  pub runtime_snapshot: Option<JsTunnelRuntimeSnapshot>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 网络摘要
#[napi(object)]
pub struct JsWGNetworkSummary {
  pub network_id: String,
  pub owner_user_id: String,
  pub name: String,
  pub subnet: String,
  pub lifecycle_status: u32,
  pub runtime_health: u32,
  pub member_count: u32,
  pub online_member_count: u32,
  pub self_joined: bool,
  pub created_at: f64,
  pub updated_at: f64,
  pub coordinator_edge_id: String,
}

/// WG 网络详情
#[napi(object)]
pub struct JsWGNetworkDetail {
  pub network_id: String,
  pub owner_user_id: String,
  pub name: String,
  pub description: String,
  pub subnet: String,
  pub relay_mode: u32,
  pub lifecycle_status: u32,
  pub runtime_health: u32,
  pub self_joined: bool,
  pub self_member_id: String,
  pub self_device_id: String,
  pub member_count: u32,
  pub online_member_count: u32,
  pub created_at: f64,
  pub updated_at: f64,
  pub coordinator_edge_id: String,
}

/// WG 网络成员
#[napi(object)]
pub struct JsWGNetworkMember {
  pub member_id: String,
  pub network_id: String,
  pub user_id: String,
  pub device_id: String,
  pub hostname: String,
  pub assigned_ip: String,
  pub public_key: String,
  pub public_key_fingerprint: String,
  pub membership_status: u32,
  pub presence_status: u32,
  pub is_current_device: bool,
  pub joined_at: f64,
  pub last_seen_at: f64,
  pub updated_at: f64,
  pub is_relay_node: bool,
  pub observed_endpoint: String,
  pub observed_at: f64,
  pub membership_generation: String,
}

/// WG relay 节点信息
#[napi(object)]
pub struct JsWGRelayNodeInfo {
  pub member_id: String,
  pub public_key: String,
  pub endpoint: String,
  pub assigned_ip: String,
  pub listen_port: u32,
  pub peer_endpoints: Vec<JsWgRelayPeerEndpointInfo>,
}

/// WG relay 为单个 client peer 分配的独立 UDP endpoint
#[napi(object)]
pub struct JsWgRelayPeerEndpointInfo {
  pub public_key: String,
  pub assigned_ip: String,
  pub endpoint: String,
  pub listen_port: u32,
}

/// WG peer endpoint 观测
#[napi(object)]
pub struct JsWGPeerEndpointObservation {
  pub member_id: String,
  pub device_id: String,
  pub endpoint: String,
  pub public_addr: String,
  pub nat_type: String,
  pub nat_type_code: u32,
  pub updated_at: f64,
}

/// WG peer session 运行态
#[napi(object)]
pub struct JsWGPeerSessionRuntime {
  pub session_id: String,
  pub network_id: String,
  pub initiator_member_id: String,
  pub target_member_id: String,
  pub status: u32,
  pub path_type: u32,
  pub last_error: String,
  pub observations: Vec<JsWGPeerEndpointObservation>,
  pub started_at: f64,
  pub updated_at: f64,
}

/// WG LAN peer endpoint (same-NAT direct path optimization)
#[napi(object)]
pub struct JsWGLANPeerEndpoint {
  pub public_key: String,
  pub lan_endpoint: String,
  pub lan_endpoint_candidates: Vec<String>,
}

#[napi(object)]
pub struct JsWGPathVersion {
  pub network_id: String,
  pub member_a_id: String,
  pub member_b_id: String,
  pub coordinator_edge_id: String,
  pub authority_epoch: String,
  pub pair_revision: String,
  pub network_policy_revision: String,
  pub attempt_id: String,
}

#[napi(object)]
pub struct JsWGPathReport {
  pub version: Option<JsWGPathVersion>,
  pub member_id: String,
  pub command_id: String,
  pub kind: u32,
  pub error: u32,
  pub actual_path: u32,
  pub actual_owner_public_key: String,
  pub actual_allowed_ips: Vec<String>,
  pub actual_endpoint: String,
  pub applied_version: Option<JsWGPathVersion>,
  pub handshake_at: String,
  pub business_sent: u32,
  pub business_replies: u32,
}

#[napi(object)]
pub struct JsWGPathPairRuntime {
  pub version: Option<JsWGPathVersion>,
  pub phase: u32,
  pub target_path: u32,
  pub committed_path: u32,
  pub endpoint_for_a: String,
  pub endpoint_for_b: String,
  pub report_a: Option<JsWGPathReport>,
  pub report_b: Option<JsWGPathReport>,
  pub last_error: u32,
  pub last_error_message: String,
}

/// WG 运行时快照
#[napi(object)]
pub struct JsWGNetworkRuntimeSnapshot {
  pub path_pairs: Vec<JsWGPathPairRuntime>,
  pub network: JsWGNetworkDetail,
  pub members: Vec<JsWGNetworkMember>,
  pub peer_sessions: Vec<JsWGPeerSessionRuntime>,
  pub relay_node: Option<JsWGRelayNodeInfo>,
  pub lan_peer_endpoints: Vec<JsWGLANPeerEndpoint>,
  pub revision: f64,
  pub collected_at: f64,
  pub revision_epoch: String,
  pub path_authority_epoch: String,
  /// Decimal string: never round a coordination version through JS Number.
  pub network_policy_revision: String,
}

/// WG 创建网络结果
#[napi(object)]
pub struct JsWGCreateNetworkResult {
  pub success: bool,
  pub network_id: String,
  pub status: u32,
  pub error_code: u32,
  pub error_message: String,
  pub suggested_cidrs: Vec<String>,
}

/// WG 加入网络结果
#[napi(object)]
pub struct JsWGJoinNetworkResult {
  pub success: bool,
  pub member_id: String,
  pub assigned_ip: String,
  pub status: u32,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 创建邀请 token 结果
#[napi(object)]
pub struct JsWGCreateInviteResult {
  pub success: bool,
  pub invite_token: String,
  pub expires_at: f64,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 离开网络结果
#[napi(object)]
pub struct JsWGLeaveNetworkResult {
  pub success: bool,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 网络列表结果
#[napi(object)]
pub struct JsWGListNetworksResult {
  pub success: bool,
  pub revision: f64,
  pub networks: Vec<JsWGNetworkSummary>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 可加入网络的在线设备
#[napi(object)]
pub struct JsWGAvailableDevice {
  pub client_id: String,
  pub device_id: String,
  pub hostname: String,
  pub last_active: f64,
}

/// WG 可用设备列表结果
#[napi(object)]
pub struct JsWGListAvailableDevicesResult {
  pub success: bool,
  pub network_id: String,
  pub devices: Vec<JsWGAvailableDevice>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 网络详情结果
#[napi(object)]
pub struct JsWGGetNetworkResult {
  pub success: bool,
  pub snapshot: Option<JsWGNetworkRuntimeSnapshot>,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 删除网络结果
#[napi(object)]
pub struct JsWGDeleteNetworkResult {
  pub success: bool,
  pub network_id: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 修改网络 CIDR 结果
#[napi(object)]
pub struct JsWGUpdateNetworkCIDRResult {
  pub success: bool,
  pub network_id: String,
  pub new_cidr: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 修改网络中继模式结果
#[napi(object)]
pub struct JsWGUpdateNetworkRelayModeResult {
  pub success: bool,
  pub network_id: String,
  pub relay_mode: u32,
  pub error_code: u32,
  pub error_message: String,
}

/// WG 更新成员信息结果
#[napi(object)]
pub struct JsWGUpdateMemberResult {
  pub success: bool,
  pub network_id: String,
  pub member_id: String,
  pub new_ip: String,
  pub new_hostname: String,
  pub error_code: u32,
  pub error_message: String,
}

/// WG runtime 请求结果
#[napi(object)]
pub struct JsWGNetworkRuntimeResult {
  pub success: bool,
  pub snapshot: Option<JsWGNetworkRuntimeSnapshot>,
  pub error_code: u32,
  pub error_message: String,
}

/// Edge 客户端
#[napi]
pub struct JsEdgeClient {
  inner: Arc<Mutex<Option<Arc<client::EdgeClient>>>>,
  config: client::edge_client::EdgeClientConfig,
  ice_agent: Arc<Mutex<Option<Arc<ice::IceAgent>>>>,
}

fn to_js_tunnel_definition(
  def: crate::protocol::message::TunnelDefinitionData,
) -> JsTunnelDefinition {
  JsTunnelDefinition {
    tunnel_id: def.tunnel_id,
    edge_id: def.edge_id,
    owner_user_id: def.owner_user_id,
    name: def.name,
    app_id: def.app_id,
    protocol: def.protocol,
    intent_json: def.intent_json,
    config_json: def.config_json,
    runtime_json: def.runtime_json,
    state: def.state,
    actor_role: def.actor_role as u32,
    actor_session_id: def.actor_session_id,
    actor_device_id: def.actor_device_id,
    version: def.version as f64,
    revision: def.revision as f64,
    deleted: def.deleted,
    created_at: def.created_at as f64,
    updated_at: def.updated_at as f64,
  }
}

fn to_native_tunnel_definition(
  def: JsTunnelDefinition,
) -> crate::protocol::message::TunnelDefinitionData {
  crate::protocol::message::TunnelDefinitionData {
    tunnel_id: def.tunnel_id,
    edge_id: def.edge_id,
    owner_user_id: def.owner_user_id,
    name: def.name,
    app_id: def.app_id,
    protocol: def.protocol,
    intent_json: def.intent_json,
    config_json: def.config_json,
    runtime_json: def.runtime_json,
    state: def.state,
    actor_role: def.actor_role as u8,
    actor_session_id: def.actor_session_id,
    actor_device_id: def.actor_device_id,
    version: def.version.max(0.0) as u64,
    revision: def.revision.max(0.0) as u64,
    deleted: def.deleted,
    created_at: def.created_at.max(0.0) as u64,
    updated_at: def.updated_at.max(0.0) as u64,
  }
}

fn to_native_tunnel_start_spec(
  spec: JsTunnelChannelStartSpec,
) -> crate::protocol::message::TunnelChannelStartSpecData {
  let local_port = spec.local_port.clamp(0, u16::MAX as u32) as u16;
  let remote_port = spec.remote_port.unwrap_or(0).clamp(0, u16::MAX as u32) as u16;
  let subdomain = spec.subdomain.unwrap_or_default();
  let metadata_json = {
    let metadata_raw = spec.metadata_json.unwrap_or_default();
    if subdomain.trim().is_empty() {
      metadata_raw
    } else {
      inject_subdomain_into_metadata_json(&metadata_raw, &subdomain)
    }
  };
  crate::protocol::message::TunnelChannelStartSpecData {
    key: spec.key,
    protocol: spec.protocol,
    local_host: spec.local_host.unwrap_or_default(),
    local_port,
    remote_port,
    subdomain,
    alias_domain: spec.alias_domain.unwrap_or_default(),
    buffer_size: spec.buffer_size.unwrap_or(0),
    transport: spec.transport.unwrap_or_default(),
    eager_connect_remote: spec.eager_connect_remote.unwrap_or(false),
    metadata_json,
  }
}

fn inject_subdomain_into_metadata_json(metadata_raw: &str, subdomain: &str) -> String {
  let normalized_subdomain = subdomain.trim();
  if normalized_subdomain.is_empty() {
    return metadata_raw.to_string();
  }

  let parsed: serde_json::Value = serde_json::from_str(metadata_raw).unwrap_or_else(|_| json!({}));
  let mut object = match parsed {
    serde_json::Value::Object(map) => map,
    _ => serde_json::Map::new(),
  };
  object.insert(
    "subdomain".to_string(),
    serde_json::Value::String(normalized_subdomain.to_string()),
  );
  serde_json::to_string(&serde_json::Value::Object(object))
    .unwrap_or_else(|_| metadata_raw.to_string())
}

#[cfg(test)]
mod subdomain_metadata_tests {
  use super::inject_subdomain_into_metadata_json;

  #[test]
  fn inject_subdomain_into_empty_metadata_json() {
    let got = inject_subdomain_into_metadata_json("", "alpha-node");
    assert_eq!(got, r#"{"subdomain":"alpha-node"}"#);
  }

  #[test]
  fn inject_subdomain_overwrites_existing_metadata_subdomain() {
    let got = inject_subdomain_into_metadata_json(r#"{"subdomain":"old","x":1}"#, "new");
    assert!(got.contains(r#""subdomain":"new""#));
    assert!(got.contains(r#""x":1"#));
  }

  #[test]
  fn inject_subdomain_ignores_blank_subdomain() {
    let raw = r#"{"x":1}"#;
    let got = inject_subdomain_into_metadata_json(raw, "   ");
    assert_eq!(got, raw);
  }
}

fn to_js_tunnel_summary(
  summary: crate::protocol::message::TunnelOperationSummaryData,
) -> JsTunnelOperationSummary {
  JsTunnelOperationSummary {
    requested: summary.requested,
    succeeded: summary.succeeded,
    failed: summary.failed,
  }
}

fn to_js_tunnel_runtime_snapshot(
  snapshot: crate::protocol::message::TunnelRuntimeSnapshotData,
) -> JsTunnelRuntimeSnapshot {
  JsTunnelRuntimeSnapshot {
    tunnel_id: snapshot.tunnel_id,
    state: snapshot.state,
    runtime_json: snapshot.runtime_json,
    updated_at: snapshot.updated_at as f64,
  }
}

fn to_js_tunnel_start_result(
  result: crate::protocol::message::TunnelStartResponseData,
) -> JsTunnelStartResult {
  JsTunnelStartResult {
    success: result.success,
    mode: result.mode as u32,
    tunnel_id: result.tunnel_id,
    edge_id: result.edge_id,
    summary: to_js_tunnel_summary(result.summary),
    channels: result
      .channels
      .into_iter()
      .map(|item| JsTunnelChannelStartResult {
        key: item.key,
        channel_id: item.channel_id,
        success: item.success,
        error_code: item.error_code,
        error_message: item.error_message,
        remote_endpoint: item.remote_endpoint,
        alias_domain: item.alias_domain,
        custom_domain: item.custom_domain,
        assigned_domain: item.assigned_domain,
        negotiated_buffer_size: item.negotiated_buffer_size,
      })
      .collect(),
    runtime_snapshot: result.runtime_snapshot.map(to_js_tunnel_runtime_snapshot),
    error_code: result.error_code,
    error_message: result.error_message,
  }
}

fn to_js_tunnel_stop_result(
  result: crate::protocol::message::TunnelStopResponseData,
) -> JsTunnelStopResult {
  JsTunnelStopResult {
    success: result.success,
    mode: result.mode as u32,
    tunnel_id: result.tunnel_id,
    edge_id: result.edge_id,
    summary: to_js_tunnel_summary(result.summary),
    channels: result
      .channels
      .into_iter()
      .map(|item| JsTunnelChannelStopResult {
        key: item.key,
        channel_id: item.channel_id,
        success: item.success,
        error_code: item.error_code,
        error_message: item.error_message,
      })
      .collect(),
    runtime_snapshot: result.runtime_snapshot.map(to_js_tunnel_runtime_snapshot),
    error_code: result.error_code,
    error_message: result.error_message,
  }
}

fn to_js_wg_network_summary(
  value: crate::protocol::message::WGNetworkSummaryData,
) -> JsWGNetworkSummary {
  JsWGNetworkSummary {
    network_id: value.network_id,
    owner_user_id: value.owner_user_id,
    name: value.name,
    subnet: value.subnet,
    lifecycle_status: value.lifecycle_status as u32,
    runtime_health: value.runtime_health as u32,
    member_count: value.member_count,
    online_member_count: value.online_member_count,
    self_joined: value.self_joined,
    created_at: value.created_at as f64,
    updated_at: value.updated_at as f64,
    coordinator_edge_id: value.coordinator_edge_id,
  }
}

fn to_js_wg_network_detail(
  value: crate::protocol::message::WGNetworkDetailData,
) -> JsWGNetworkDetail {
  JsWGNetworkDetail {
    network_id: value.network_id,
    owner_user_id: value.owner_user_id,
    name: value.name,
    description: value.description,
    subnet: value.subnet,
    relay_mode: value.relay_mode as u32,
    lifecycle_status: value.lifecycle_status as u32,
    runtime_health: value.runtime_health as u32,
    self_joined: value.self_joined,
    self_member_id: value.self_member_id,
    self_device_id: value.self_device_id,
    member_count: value.member_count,
    online_member_count: value.online_member_count,
    created_at: value.created_at as f64,
    updated_at: value.updated_at as f64,
    coordinator_edge_id: value.coordinator_edge_id,
  }
}

fn to_js_wg_network_member(
  value: crate::protocol::message::WGNetworkMemberData,
) -> JsWGNetworkMember {
  JsWGNetworkMember {
    member_id: value.member_id,
    network_id: value.network_id,
    user_id: value.user_id,
    device_id: value.device_id,
    hostname: value.hostname,
    assigned_ip: value.assigned_ip,
    public_key: value.public_key,
    public_key_fingerprint: value.public_key_fingerprint,
    membership_status: value.membership_status as u32,
    presence_status: value.presence_status as u32,
    is_current_device: value.is_current_device,
    joined_at: value.joined_at as f64,
    last_seen_at: value.last_seen_at as f64,
    updated_at: value.updated_at as f64,
    is_relay_node: value.is_relay_node,
    observed_endpoint: value.observed_endpoint,
    observed_at: value.observed_at as f64,
    membership_generation: value.membership_generation,
  }
}

fn to_js_wg_relay_node_info(
  value: crate::protocol::message::WGRelayNodeInfoData,
) -> JsWGRelayNodeInfo {
  JsWGRelayNodeInfo {
    member_id: value.member_id,
    public_key: value.public_key,
    endpoint: value.endpoint,
    assigned_ip: value.assigned_ip,
    listen_port: value.listen_port,
    peer_endpoints: value
      .peer_endpoints
      .into_iter()
      .map(|peer| JsWgRelayPeerEndpointInfo {
        public_key: peer.public_key,
        assigned_ip: peer.assigned_ip,
        endpoint: peer.endpoint,
        listen_port: peer.listen_port,
      })
      .collect(),
  }
}

fn to_js_wg_peer_endpoint_observation(
  value: crate::protocol::message::WGPeerEndpointObservationData,
) -> JsWGPeerEndpointObservation {
  JsWGPeerEndpointObservation {
    member_id: value.member_id,
    device_id: value.device_id,
    endpoint: value.endpoint,
    public_addr: value.public_addr,
    nat_type: value.nat_type,
    nat_type_code: value.nat_type_code as u32,
    updated_at: value.updated_at as f64,
  }
}

fn to_js_wg_peer_session_runtime(
  value: crate::protocol::message::WGPeerSessionRuntimeData,
) -> JsWGPeerSessionRuntime {
  JsWGPeerSessionRuntime {
    session_id: value.session_id,
    network_id: value.network_id,
    initiator_member_id: value.initiator_member_id,
    target_member_id: value.target_member_id,
    status: value.status as u32,
    path_type: value.path_type as u32,
    last_error: value.last_error,
    observations: value
      .observations
      .into_iter()
      .map(to_js_wg_peer_endpoint_observation)
      .collect(),
    started_at: value.started_at as f64,
    updated_at: value.updated_at as f64,
  }
}

fn to_js_path_version(v: crate::protocol::message::WGPathVersionData) -> JsWGPathVersion {
  JsWGPathVersion {
    network_id: v.network_id,
    member_a_id: v.member_a_id,
    member_b_id: v.member_b_id,
    coordinator_edge_id: v.coordinator_edge_id,
    authority_epoch: v.authority_epoch,
    pair_revision: v.pair_revision,
    network_policy_revision: v.network_policy_revision,
    attempt_id: v.attempt_id,
  }
}

fn to_js_path_report(v: crate::protocol::message::WGPathReportData) -> JsWGPathReport {
  JsWGPathReport {
    version: v.version.map(to_js_path_version),
    member_id: v.member_id,
    command_id: v.command_id,
    kind: v.kind,
    error: v.error,
    actual_path: v.actual_path,
    actual_owner_public_key: v.actual_owner_public_key,
    actual_allowed_ips: v.actual_allowed_ips,
    actual_endpoint: v.actual_endpoint,
    applied_version: v.applied_version.map(to_js_path_version),
    handshake_at: v.handshake_at,
    business_sent: v.business_sent,
    business_replies: v.business_replies,
  }
}

fn to_js_path_pair(v: crate::protocol::message::WGPathPairRuntimeData) -> JsWGPathPairRuntime {
  JsWGPathPairRuntime {
    version: v.version.map(to_js_path_version),
    phase: v.phase,
    target_path: v.target_path,
    committed_path: v.committed_path,
    endpoint_for_a: v.endpoint_for_a,
    endpoint_for_b: v.endpoint_for_b,
    report_a: v.report_a.map(to_js_path_report),
    report_b: v.report_b.map(to_js_path_report),
    last_error: v.last_error,
    last_error_message: v.last_error_message,
  }
}

fn to_js_wg_network_runtime_snapshot(
  value: crate::protocol::message::WGNetworkRuntimeSnapshotData,
) -> JsWGNetworkRuntimeSnapshot {
  JsWGNetworkRuntimeSnapshot {
    path_pairs: value.path_pairs.into_iter().map(to_js_path_pair).collect(),
    network: to_js_wg_network_detail(value.network),
    members: value
      .members
      .into_iter()
      .map(to_js_wg_network_member)
      .collect(),
    peer_sessions: value
      .peer_sessions
      .into_iter()
      .map(to_js_wg_peer_session_runtime)
      .collect(),
    relay_node: value.relay_node.map(to_js_wg_relay_node_info),
    lan_peer_endpoints: value
      .lan_peer_endpoints
      .into_iter()
      .map(|ep| JsWGLANPeerEndpoint {
        public_key: ep.public_key,
        lan_endpoint: ep.lan_endpoint,
        lan_endpoint_candidates: ep.lan_endpoint_candidates,
      })
      .collect(),
    revision: value.revision as f64,
    collected_at: value.collected_at as f64,
    revision_epoch: value.revision_epoch,
    path_authority_epoch: value.path_authority_epoch,
    network_policy_revision: value.network_policy_revision.to_string(),
  }
}

impl JsEdgeClient {
  fn normalize_protocol_hint(protocol: Option<String>) -> String {
    protocol.unwrap_or_default().trim().to_ascii_lowercase()
  }

  fn is_udp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("udp")
  }

  async fn resolve_binding_for_channel(
    client: &Arc<client::EdgeClient>,
    channel_id: &str,
  ) -> Option<(String, String)> {
    client
      .list_p2p_channel_bindings()
      .await
      .into_iter()
      .find(|binding| binding.channel_id == channel_id)
      .map(|binding| (binding.local_addr, binding.protocol))
  }

  async fn get_client(&self) -> Result<Arc<client::EdgeClient>> {
    let guard = self.inner.lock().await;
    guard
      .as_ref()
      .cloned()
      .ok_or_else(|| Error::from_reason("Not connected"))
  }

  fn infer_channel_business_role(channel_id: &str) -> Option<&'static str> {
    let raw = channel_id.trim();
    if raw.is_empty() {
      return None;
    }
    let mut parts = raw.rsplitn(3, ':');
    let _actor = parts.next();
    let role = parts.next()?;
    let _base = parts.next()?;
    match role {
      "consumer" | "controller" => Some("consumer"),
      "publisher" => Some("publisher"),
      _ => None,
    }
  }

  async fn wire_p2p_forwarding(
    client: &Arc<client::EdgeClient>,
    agent: &Arc<ice::IceAgent>,
    source: &str,
  ) {
    let Some(forwarder) = agent.forwarder().await else {
      eprintln!(
        "[JsEdgeClient] skip p2p auto-wire from {}: forwarder not ready",
        source
      );
      return;
    };

    let bindings = client.list_p2p_channel_bindings().await;
    if bindings.is_empty() {
      eprintln!(
        "[JsEdgeClient] skip p2p auto-wire from {}: no p2p channels",
        source
      );
      return;
    }

    eprintln!(
      "[JsEdgeClient] p2p auto-wire from {}: channels={} forwarder[publisher={}, consumer={}]",
      source,
      bindings.len(),
      forwarder.is_publisher(),
      forwarder.is_consumer()
    );

    for binding in bindings.iter() {
      let business_role = Self::infer_channel_business_role(&binding.channel_id);
      let role_text = business_role.unwrap_or("unknown");
      let role_source = if business_role.is_some() {
        "channel-id"
      } else {
        "forwarder-fallback"
      };

      let should_register = business_role
        .map(|role| role == "publisher")
        .unwrap_or_else(|| forwarder.is_publisher());
      if should_register {
        eprintln!(
          "[JsEdgeClient] p2p auto-wire register channel={} protocol={} local={} source={} role={} role_source={}",
          binding.channel_id,
          binding.protocol,
          binding.local_addr,
          source,
          role_text,
          role_source
        );
        forwarder
          .register_channel(binding.channel_id.clone(), binding.local_addr.clone())
          .await;
      } else {
        eprintln!(
          "[JsEdgeClient] p2p auto-wire skip register channel={} source={} role={} role_source={}",
          binding.channel_id, source, role_text, role_source
        );
      }

      let should_listen = business_role
        .map(|role| role == "consumer")
        .unwrap_or_else(|| forwarder.is_consumer());
      if !should_listen {
        eprintln!(
          "[JsEdgeClient] p2p auto-wire skip listener channel={} source={} role={} role_source={}",
          binding.channel_id, source, role_text, role_source
        );
        continue;
      }

      let protocol = binding.protocol.trim().to_ascii_lowercase();
      let listen_result = if Self::is_udp_protocol(&protocol) {
        forwarder
          .start_consumer_udp_listener_with_bind(&binding.channel_id, Some(&binding.local_addr))
          .await
      } else {
        forwarder
          .start_consumer_listener_with_bind(&binding.channel_id, Some(&binding.local_addr))
          .await
      };

      match listen_result {
        Ok(addr) => {
          let addr_str = addr.to_string();
          if addr_str != binding.local_addr {
            client
              .update_channel_local_addr(&binding.channel_id, addr_str.clone())
              .await;
          }
          eprintln!(
            "[JsEdgeClient] p2p consumer listener ready channel={} protocol={} addr={} source={}",
            binding.channel_id, binding.protocol, addr_str, source
          );
        }
        Err(err) => {
          eprintln!(
            "[JsEdgeClient] p2p consumer listener failed channel={} protocol={} bind={} source={} err={}",
            binding.channel_id, binding.protocol, binding.local_addr, source, err
          );
        }
      }
    }
  }
}

#[napi]
impl JsEdgeClient {
  /// 创建新的 Edge 客户端
  #[napi(constructor)]
  pub fn new(config: JsEdgeClientConfig) -> Self {
    let rust_config = client::edge_client::EdgeClientConfig {
      host: config.host,
      port: config.port,
      ca_cert: config.ca_cert.to_vec(),
      client_cert: Some(config.client_cert.to_vec()),
      client_key: Some(config.client_key.to_vec()),
      heartbeat_interval_secs: config.heartbeat_interval_secs.unwrap_or(30) as u64,
      quic_keepalive_secs: config.quic_keepalive_secs.unwrap_or(15) as u64,
      quic_idle_timeout_secs: config.quic_idle_timeout_secs.unwrap_or(300) as u64,
      edge_id: config.edge_id,
      server_name: config.server_name,
    };

    Self {
      inner: Arc::new(Mutex::new(None)),
      config: rust_config,
      ice_agent: Arc::new(Mutex::new(None)),
    }
  }

  /// 连接到 Edge 服务器
  #[napi]
  pub async fn connect(&self) -> Result<()> {
    let client = client::EdgeClient::new(self.config.clone());
    client
      .connect()
      .await
      .map_err(|e| Error::from_reason(e.to_string()))?;

    *self.inner.lock().await = Some(Arc::new(client));
    Ok(())
  }

  /// 断开连接
  #[napi]
  pub async fn disconnect(&self) -> Result<()> {
    if let Some(client) = self.inner.lock().await.take() {
      client.disconnect().await?;
    }
    Ok(())
  }

  /// 是否已连接
  #[napi]
  pub async fn is_connected(&self) -> bool {
    self
      .inner
      .lock()
      .await
      .as_ref()
      .map(|client| client.is_connected())
      .unwrap_or(false)
  }

  /// 认证
  #[napi]
  pub async fn authenticate(&self, params: JsAuthParams) -> Result<JsAuthResult> {
    let client = self.get_client().await?;
    let protocol_major = params.protocol_major.unwrap_or(u32::from(crate::PROTOCOL_MAJOR)).min(u16::MAX as u32) as u16;
    let protocol_minor = params.protocol_minor.unwrap_or(u32::from(crate::PROTOCOL_MINOR)).min(u16::MAX as u32) as u16;
    let required_features = params.required_features.unwrap_or_default();
    let requested_features = params.requested_features.unwrap_or_default();

    let result = client
      .authenticate(
        &params.device_id,
        params.hostname.as_deref().unwrap_or(""),
        &params.client_version,
        &params.capabilities,
        protocol_major,
        protocol_minor,
        &required_features,
        &requested_features,
      )
      .await
      .map_err(Error::from)?;

    Ok(JsAuthResult {
      success: result.success,
      session_id: result.session_id,
      server_version: result.server_version,
      error_code: result.error_code,
      error_message: result.error_message,
      negotiated_protocol_major: result.negotiated_protocol_major as u32,
      negotiated_protocol_minor: result.negotiated_protocol_minor as u32,
      accepted_features: result.accepted_features,
      rejected_features: result.rejected_features,
      compatibility_level: result.compatibility_level as u32,
      reason_code: result.reason_code as u32,
    })
  }

  /// Edge 上线请求
  #[napi]
  pub async fn edge_online(&self) -> Result<JsEdgeResult> {
    let client = self.get_client().await?;

    let result = client.edge_online().await.map_err(Error::from)?;

    Ok(JsEdgeResult {
      success: result.success,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// Edge 下线请求
  #[napi]
  pub async fn edge_offline(&self) -> Result<JsEdgeResult> {
    let client = self.get_client().await?;

    let result = client.edge_offline().await.map_err(Error::from)?;

    Ok(JsEdgeResult {
      success: result.success,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 Edge 状态
  #[napi]
  pub async fn request_edge_status(&self) -> Result<JsEdgeStatusResult> {
    let client = self.get_client().await?;

    let result = client.request_edge_status().await.map_err(Error::from)?;
    let status_timestamp = result.timestamp as f64;

    Ok(JsEdgeStatusResult {
      edge_id: result.edge_id,
      online: result.online,
      uptime: result.uptime as f64,
      timestamp: status_timestamp,
      supported_protocols: result.supported_protocols,
      active_sessions: result.active_sessions,
      total_bytes_in: result.total_bytes_in as f64,
      total_bytes_out: result.total_bytes_out as f64,
      is_owner_view: result.is_owner_view,
      channels: result
        .channels
        .into_iter()
        .map(|ch| JsEdgeChannelStatus {
          channel_id: ch.channel_id,
          session_id: ch.session_id,
          user_id: ch.user_id,
          device_id: ch.device_id,
          actor_role: ch.actor_role as u32,
          actor_session_id: ch.actor_session_id,
          actor_device_id: ch.actor_device_id,
          domain: ch.domain,
          subdomain: ch.subdomain,
          alias_domain: ch.alias_domain,
          channel_key: ch.channel_key,
          protocol: ch.protocol,
          link_type: ch.link_type,
          remote_endpoint: ch.remote_endpoint,
          local_addr: ch.local_addr,
          state: ch.state,
          bytes_in: ch.bytes_in as f64,
          bytes_out: ch.bytes_out as f64,
          connections: ch.connections,
          active_conns: ch.active_conns,
          domain_status: ch.domain_status.map(|s| JsDomainStatus {
            dns_status: s.dns_status as u32,
            cert_status: s.cert_status as u32,
            error: s.error.clone(),
            cert_last_error: s.cert_last_error,
            updated_at: s.updated_at as f64,
          }),
          alias_domain_status: ch.alias_domain_status.map(|s| JsDomainStatus {
            dns_status: s.dns_status as u32,
            cert_status: s.cert_status as u32,
            error: s.error.clone(),
            cert_last_error: s.cert_last_error,
            updated_at: s.updated_at as f64,
          }),
        })
        .collect(),
      dns01_challenges: result
        .dns01_challenges
        .into_iter()
        .map(|ch| JsDns01Challenge {
          record_name: ch.record_name,
          record_value: ch.record_value,
          domain: ch.domain,
          created_at: ch.created_at as f64,
          last_error: ch.last_error,
          updated_at: ch.updated_at as f64,
        })
        .collect(),
      cname_status: result.cname_status as u32,
      assigned_domain_status: result.assigned_domain_status.map(|s| JsDomainStatus {
        dns_status: s.dns_status as u32,
        cert_status: s.cert_status as u32,
        error: s.error.clone(),
        cert_last_error: s.cert_last_error,
        updated_at: s.updated_at as f64,
      }),
      custom_domain_status: result.custom_domain_status.map(|s| JsDomainStatus {
        dns_status: s.dns_status as u32,
        cert_status: s.cert_status as u32,
        error: s.error.clone(),
        cert_last_error: s.cert_last_error,
        updated_at: s.updated_at as f64,
      }),
      domain_runtime: result.domain_runtime.map(|runtime| JsDomainRuntime {
        owner_view: runtime.owner_view,
        state: runtime.state as u32,
        required_records: runtime
          .required_records
          .into_iter()
          .map(|record| JsDomainRecord {
            record_type: record.record_type as u32,
            record_name: record.record_name,
            record_value: record.record_value,
            ttl: record.ttl,
            source: record.source,
          })
          .collect(),
        pending_reason_code: runtime.pending_reason_code,
        last_error: runtime.last_error,
        cname_status: runtime.cname_status as u32,
        cert_status: runtime.cert_status as u32,
        updated_at: runtime.updated_at as f64,
      }),
    })
  }

  /// 请求单 Tunnel 状态
  #[napi]
  pub async fn request_tunnel_status(&self, tunnel_id: String) -> Result<JsTunnelStatusResult> {
    let client = self.get_client().await?;

    let result = client
      .request_tunnel_status(&tunnel_id)
      .await
      .map_err(Error::from)?;

    Ok(JsTunnelStatusResult {
      success: result.success,
      tunnel_id: result.tunnel_id,
      edge_id: result.edge_id,
      online: result.online,
      uptime: result.uptime as f64,
      timestamp: result.timestamp as f64,
      total_bytes_in: result.total_bytes_in as f64,
      total_bytes_out: result.total_bytes_out as f64,
      channels: result
        .channels
        .into_iter()
        .map(|ch| JsEdgeChannelStatus {
          channel_id: ch.channel_id,
          session_id: ch.session_id,
          user_id: ch.user_id,
          device_id: ch.device_id,
          actor_role: ch.actor_role as u32,
          actor_session_id: ch.actor_session_id,
          actor_device_id: ch.actor_device_id,
          domain: ch.domain,
          subdomain: ch.subdomain,
          alias_domain: ch.alias_domain,
          channel_key: ch.channel_key,
          protocol: ch.protocol,
          link_type: ch.link_type,
          remote_endpoint: ch.remote_endpoint,
          local_addr: ch.local_addr,
          state: ch.state,
          bytes_in: ch.bytes_in as f64,
          bytes_out: ch.bytes_out as f64,
          connections: ch.connections,
          active_conns: ch.active_conns,
          domain_status: ch.domain_status.map(|s| JsDomainStatus {
            dns_status: s.dns_status as u32,
            cert_status: s.cert_status as u32,
            error: s.error,
            cert_last_error: s.cert_last_error,
            updated_at: s.updated_at as f64,
          }),
          alias_domain_status: ch.alias_domain_status.map(|s| JsDomainStatus {
            dns_status: s.dns_status as u32,
            cert_status: s.cert_status as u32,
            error: s.error,
            cert_last_error: s.cert_last_error,
            updated_at: s.updated_at as f64,
          }),
        })
        .collect(),
      dns01_challenges: result
        .dns01_challenges
        .into_iter()
        .map(|ch| JsDns01Challenge {
          record_name: ch.record_name,
          record_value: ch.record_value,
          domain: ch.domain,
          created_at: ch.created_at as f64,
          last_error: ch.last_error,
          updated_at: ch.updated_at as f64,
        })
        .collect(),
      cname_status: result.cname_status as u32,
      custom_domain_status: result.custom_domain_status.map(|s| JsDomainStatus {
        dns_status: s.dns_status as u32,
        cert_status: s.cert_status as u32,
        error: s.error,
        cert_last_error: s.cert_last_error,
        updated_at: s.updated_at as f64,
      }),
      domain_runtime: result.domain_runtime.map(|runtime| JsDomainRuntime {
        owner_view: runtime.owner_view,
        state: runtime.state as u32,
        required_records: runtime
          .required_records
          .into_iter()
          .map(|record| JsDomainRecord {
            record_type: record.record_type as u32,
            record_name: record.record_name,
            record_value: record.record_value,
            ttl: record.ttl,
            source: record.source,
          })
          .collect(),
        pending_reason_code: runtime.pending_reason_code,
        last_error: runtime.last_error,
        cname_status: runtime.cname_status as u32,
        cert_status: runtime.cert_status as u32,
        updated_at: runtime.updated_at as f64,
      }),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 Tunnel 定义增量同步
  #[napi]
  pub async fn request_tunnel_sync(
    &self,
    edge_id: Option<String>,
    since_revision: Option<f64>,
    limit: Option<u32>,
    include_deleted: Option<bool>,
  ) -> Result<JsTunnelSyncResult> {
    let client = self.get_client().await?;

    let result = client
      .request_tunnel_sync(
        edge_id.as_deref(),
        since_revision.unwrap_or(0.0).max(0.0) as u64,
        limit.unwrap_or(200),
        include_deleted.unwrap_or(false),
      )
      .await
      .map_err(Error::from)?;

    Ok(JsTunnelSyncResult {
      success: result.success,
      full_snapshot: result.full_snapshot,
      next_revision: result.next_revision as f64,
      has_more: result.has_more,
      definitions: result
        .definitions
        .into_iter()
        .map(to_js_tunnel_definition)
        .collect(),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// Upsert Tunnel 定义
  #[napi]
  pub async fn upsert_tunnel_definition(
    &self,
    edge_id: Option<String>,
    definition: JsTunnelDefinition,
    if_match_revision: Option<f64>,
  ) -> Result<JsTunnelUpsertResult> {
    let client = self.get_client().await?;

    let native_definition = to_native_tunnel_definition(definition);
    let result = client
      .upsert_tunnel_definition(
        edge_id.as_deref(),
        if_match_revision.unwrap_or(0.0).max(0.0) as u64,
        &native_definition,
      )
      .await
      .map_err(Error::from)?;

    Ok(JsTunnelUpsertResult {
      success: result.success,
      conflict: result.conflict,
      next_revision: result.next_revision as f64,
      definition: result.definition.map(to_js_tunnel_definition),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 删除 Tunnel 定义（软删除）
  #[napi]
  pub async fn delete_tunnel_definition(
    &self,
    edge_id: Option<String>,
    tunnel_id: String,
    if_match_revision: Option<f64>,
  ) -> Result<JsTunnelDeleteResult> {
    let client = self.get_client().await?;

    let result = client
      .delete_tunnel_definition(
        edge_id.as_deref(),
        &tunnel_id,
        if_match_revision.unwrap_or(0.0).max(0.0) as u64,
      )
      .await
      .map_err(Error::from)?;

    Ok(JsTunnelDeleteResult {
      success: result.success,
      conflict: result.conflict,
      tunnel_id: result.tunnel_id,
      next_revision: result.next_revision as f64,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 WG 网络列表
  #[napi(js_name = "requestWGListNetworks")]
  pub async fn request_wg_list_networks(
    &self,
    include_deleted: Option<bool>,
  ) -> Result<JsWGListNetworksResult> {
    let client = self.get_client().await?;
    let result = client
      .request_wg_list_networks(include_deleted.unwrap_or(false))
      .await
      .map_err(Error::from)?;

    Ok(JsWGListNetworksResult {
      success: result.success,
      revision: result.revision as f64,
      networks: result
        .networks
        .into_iter()
        .map(to_js_wg_network_summary)
        .collect(),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 WG 可加入网络的在线设备列表
  #[napi(js_name = "requestWGListAvailableDevices")]
  pub async fn request_wg_list_available_devices(
    &self,
    network_id: String,
  ) -> Result<JsWGListAvailableDevicesResult> {
    let client = self.get_client().await?;
    let result = client
      .request_wg_list_available_devices(&network_id)
      .await
      .map_err(Error::from)?;

    Ok(JsWGListAvailableDevicesResult {
      success: result.success,
      network_id: result.network_id,
      devices: result
        .devices
        .into_iter()
        .map(|d| JsWGAvailableDevice {
          client_id: d.client_id,
          device_id: d.device_id,
          hostname: d.hostname,
          last_active: d.last_active as f64,
        })
        .collect(),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 WG 单网络详情
  #[napi(js_name = "requestWGGetNetwork")]
  pub async fn request_wg_get_network(&self, network_id: String) -> Result<JsWGGetNetworkResult> {
    let client = self.get_client().await?;
    let result = client
      .request_wg_get_network(&network_id)
      .await
      .map_err(Error::from)?;

    Ok(JsWGGetNetworkResult {
      success: result.success,
      snapshot: result.snapshot.map(to_js_wg_network_runtime_snapshot),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 请求 WG 网络 runtime 快照
  #[napi(js_name = "requestWGNetworkRuntime")]
  pub async fn request_wg_network_runtime(
    &self,
    network_id: String,
  ) -> Result<JsWGNetworkRuntimeResult> {
    let client = self.get_client().await?;
    let result = client
      .request_wg_network_runtime(&network_id)
      .await
      .map_err(Error::from)?;

    Ok(JsWGNetworkRuntimeResult {
      success: result.success,
      snapshot: result.snapshot.map(to_js_wg_network_runtime_snapshot),
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 创建 WG 网络
  #[napi(js_name = "createWGNetwork")]
  pub async fn create_wg_network(
    &self,
    network_id: String,
    name: String,
    cidr: String,
    relay_mode: Option<u32>,
    description: Option<String>,
    owner_user_id: Option<String>,
    owner_username: Option<String>,
  ) -> Result<JsWGCreateNetworkResult> {
    let client = self.get_client().await?;
    let result = client
      .create_wg_network(
        &network_id,
        &name,
        &cidr,
        relay_mode.unwrap_or(0).min(u8::MAX as u32) as u8,
        description.as_deref().unwrap_or(""),
        owner_user_id.as_deref().unwrap_or(""),
        owner_username.as_deref().unwrap_or(""),
      )
      .await
      .map_err(Error::from)?;

    Ok(JsWGCreateNetworkResult {
      success: result.success,
      network_id: result.network_id,
      status: result.status as u32,
      error_code: result.error_code,
      error_message: result.error_message,
      suggested_cidrs: result.suggested_cidrs,
    })
  }

  /// 加入 WG 网络
  #[napi(js_name = "joinWGNetwork")]
  pub async fn join_wg_network(
    &self,
    network_id: String,
    client_id: String,
    public_key: String,
    hostname: Option<String>,
    invite_token: Option<String>,
  ) -> Result<JsWGJoinNetworkResult> {
    let client = self.get_client().await?;
    let result = client
      .join_wg_network(
        &network_id,
        &client_id,
        &public_key,
        hostname.as_deref().unwrap_or(""),
        invite_token.as_deref().unwrap_or(""),
      )
      .await
      .map_err(Error::from)?;

    Ok(JsWGJoinNetworkResult {
      success: result.success,
      member_id: result.member_id,
      assigned_ip: result.assigned_ip,
      status: result.status as u32,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 创建 WG 邀请 token（仅 network owner 可调用）
  #[napi(js_name = "createWGInvite")]
  pub async fn create_wg_invite(
    &self,
    network_id: String,
    expires_in_secs: Option<u32>,
    max_uses: Option<u32>,
  ) -> Result<JsWGCreateInviteResult> {
    let client = self.get_client().await?;
    let result = client
      .create_wg_invite(
        &network_id,
        expires_in_secs.unwrap_or(3600),
        max_uses.unwrap_or(1),
      )
      .await
      .map_err(Error::from)?;

    Ok(JsWGCreateInviteResult {
      success: result.success,
      invite_token: result.invite_token,
      expires_at: result.expires_at as f64,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 离开 WG 网络
  #[napi(js_name = "leaveWGNetwork")]
  pub async fn leave_wg_network(
    &self,
    network_id: String,
    member_id: String,
    temporary: Option<bool>,
  ) -> Result<JsWGLeaveNetworkResult> {
    let client = self.get_client().await?;
    let result = client
      .leave_wg_network(&network_id, &member_id, temporary.unwrap_or(false))
      .await
      .map_err(Error::from)?;

    Ok(JsWGLeaveNetworkResult {
      success: result.success,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 删除 WG 网络
  #[napi(js_name = "deleteWGNetwork")]
  pub async fn delete_wg_network(&self, network_id: String) -> Result<JsWGDeleteNetworkResult> {
    let client = self.get_client().await?;
    let result = client
      .delete_wg_network(&network_id)
      .await
      .map_err(Error::from)?;

    Ok(JsWGDeleteNetworkResult {
      success: result.success,
      network_id: result.network_id,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 修改 WG 网络 CIDR
  #[napi(js_name = "updateWGNetworkCIDR")]
  pub async fn update_wg_network_cidr(
    &self,
    network_id: String,
    new_cidr: String,
  ) -> Result<JsWGUpdateNetworkCIDRResult> {
    let client = self.get_client().await?;
    let result = client
      .update_wg_network_cidr(&network_id, &new_cidr)
      .await
      .map_err(Error::from)?;

    Ok(JsWGUpdateNetworkCIDRResult {
      success: result.success,
      network_id: result.network_id,
      new_cidr: result.new_cidr,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 修改 WG 网络中继模式
  #[napi(js_name = "updateWGNetworkRelayMode")]
  pub async fn update_wg_network_relay_mode(
    &self,
    network_id: String,
    relay_mode: u32,
  ) -> Result<JsWGUpdateNetworkRelayModeResult> {
    let client = self.get_client().await?;
    let result = client
      .update_wg_network_relay_mode(&network_id, relay_mode as u8)
      .await
      .map_err(Error::from)?;

    Ok(JsWGUpdateNetworkRelayModeResult {
      success: result.success,
      network_id: result.network_id,
      relay_mode: result.relay_mode as u32,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 更新 WG 成员信息（IP / hostname）
  #[napi(js_name = "updateWGMember")]
  pub async fn update_wg_member(
    &self,
    network_id: String,
    member_id: String,
    new_ip: String,
    new_hostname: String,
  ) -> Result<JsWGUpdateMemberResult> {
    let client = self.get_client().await?;
    let result = client
      .update_wg_member(&network_id, &member_id, &new_ip, &new_hostname)
      .await
      .map_err(Error::from)?;

    Ok(JsWGUpdateMemberResult {
      success: result.success,
      network_id: result.network_id,
      member_id: result.member_id,
      new_ip: result.new_ip,
      new_hostname: result.new_hostname,
      error_code: result.error_code,
      error_message: result.error_message,
    })
  }

  /// 启动 Tunnel（批量 channel）
  #[napi]
  pub async fn start_tunnel(
    &self,
    tunnel_id: String,
    channels: Vec<JsTunnelChannelStartSpec>,
    edge_id: Option<String>,
    mode: Option<u32>,
    actor_role: Option<u32>,
    actor_session_id: Option<String>,
    actor_device_id: Option<String>,
    reconnect: Option<bool>,
    definition_if_match_revision: Option<f64>,
    definition: Option<JsTunnelDefinition>,
  ) -> Result<JsTunnelStartResult> {
    let client = self.get_client().await?;

    let native_channels = channels
      .into_iter()
      .map(to_native_tunnel_start_spec)
      .collect::<Vec<_>>();

    let native_definition = definition.map(to_native_tunnel_definition);
    let result = client
      .start_tunnel(
        &tunnel_id,
        edge_id.as_deref(),
        mode.unwrap_or(0) as u8,
        actor_role.map(|v| v as u8),
        actor_session_id.as_deref(),
        actor_device_id.as_deref(),
        &native_channels,
        reconnect.unwrap_or(false),
        definition_if_match_revision.map(|v| v.max(0.0) as u64),
        native_definition.as_ref(),
      )
      .await
      .map_err(Error::from)?;

    let maybe_agent = {
      let guard = self.ice_agent.lock().await;
      guard.as_ref().cloned()
    };
    if let Some(agent) = maybe_agent {
      Self::wire_p2p_forwarding(&client, &agent, "start_tunnel").await;
    }

    Ok(to_js_tunnel_start_result(result))
  }

  /// 停止 Tunnel（支持 selective keys）
  #[napi]
  pub async fn stop_tunnel(
    &self,
    tunnel_id: String,
    keys: Option<Vec<String>>,
    reason: Option<String>,
    edge_id: Option<String>,
    mode: Option<u32>,
    actor_role: Option<u32>,
    actor_session_id: Option<String>,
    actor_device_id: Option<String>,
  ) -> Result<JsTunnelStopResult> {
    let client = self.get_client().await?;

    let normalized_keys = keys
      .unwrap_or_default()
      .into_iter()
      .map(|item| item.trim().to_string())
      .filter(|item| !item.is_empty())
      .collect::<Vec<_>>();

    let result = client
      .stop_tunnel(
        &tunnel_id,
        edge_id.as_deref(),
        mode.unwrap_or(0) as u8,
        actor_role.map(|v| v as u8),
        actor_session_id.as_deref(),
        actor_device_id.as_deref(),
        &normalized_keys,
        reason.as_deref(),
      )
      .await
      .map_err(Error::from)?;

    Ok(to_js_tunnel_stop_result(result))
  }

  /// 加入 Tunnel 协商（consumer/controller）
  #[napi]
  pub async fn join_tunnel(
    &self,
    tunnel_id: String,
    channels: Vec<JsTunnelChannelStartSpec>,
    edge_id: Option<String>,
    mode: Option<u32>,
    actor_role: Option<u32>,
    actor_session_id: Option<String>,
    actor_device_id: Option<String>,
    reconnect: Option<bool>,
  ) -> Result<JsTunnelStartResult> {
    let client = self.get_client().await?;

    let native_channels = channels
      .into_iter()
      .map(to_native_tunnel_start_spec)
      .collect::<Vec<_>>();

    let result = client
      .join_tunnel(
        &tunnel_id,
        edge_id.as_deref(),
        mode.unwrap_or(0) as u8,
        actor_role.map(|v| v as u8),
        actor_session_id.as_deref(),
        actor_device_id.as_deref(),
        &native_channels,
        reconnect.unwrap_or(false),
      )
      .await
      .map_err(Error::from)?;

    let maybe_agent = {
      let guard = self.ice_agent.lock().await;
      guard.as_ref().cloned()
    };
    if let Some(agent) = maybe_agent {
      Self::wire_p2p_forwarding(&client, &agent, "join_tunnel").await;
    }

    Ok(to_js_tunnel_start_result(result))
  }

  /// 离开 Tunnel 协商（session-local）
  #[napi]
  pub async fn leave_tunnel(
    &self,
    tunnel_id: String,
    keys: Option<Vec<String>>,
    reason: Option<String>,
    edge_id: Option<String>,
    mode: Option<u32>,
    actor_role: Option<u32>,
    actor_session_id: Option<String>,
    actor_device_id: Option<String>,
  ) -> Result<JsTunnelStopResult> {
    let client = self.get_client().await?;

    let normalized_keys = keys
      .unwrap_or_default()
      .into_iter()
      .map(|item| item.trim().to_string())
      .filter(|item| !item.is_empty())
      .collect::<Vec<_>>();

    let result = client
      .leave_tunnel(
        &tunnel_id,
        edge_id.as_deref(),
        mode.unwrap_or(0) as u8,
        actor_role.map(|v| v as u8),
        actor_session_id.as_deref(),
        actor_device_id.as_deref(),
        &normalized_keys,
        reason.as_deref(),
      )
      .await
      .map_err(Error::from)?;

    Ok(to_js_tunnel_stop_result(result))
  }

  /// 订阅 Edge 日志推送（通过回调接收日志行）
  ///
  /// 说明：
  /// - 该方法会在后台异步发送 EDGE_LOG_REQUEST(subscribe=true)
  /// - 收到 EDGE_LOG_PUSH 后，会逐行调用 callback(logLine)
  #[napi(
    ts_args_type = "tailLines: number | undefined | null, callback: (err: Error | null, log: string) => void"
  )]
  pub fn subscribe_logs(
    &self,
    tail_lines: Option<i32>,
    callback: ThreadsafeFunction<String>,
  ) -> Result<()> {
    let handler = move |lines: Vec<String>| {
      for line in lines {
        // 移除 ANSI 转义码（终端颜色控制字符）
        let clean_line = strip_ansi_codes(&line);
        // ThreadsafeFunction 需要 Result<T, Error>，第一个参数是 Error（null），第二个是值
        let _ = callback.call(Ok(clean_line), ThreadsafeFunctionCallMode::NonBlocking);
      }
    };

    let inner = self.inner.clone();
    let tail_lines = tail_lines.unwrap_or(100);

    // 使用全局运行时 spawn 异步任务
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.subscribe_logs(tail_lines, handler).await;
      }
    });

    Ok(())
  }

  /// 取消订阅 Edge 日志推送（后台异步发送 EDGE_LOG_REQUEST(subscribe=false)）
  #[napi]
  pub fn unsubscribe_logs(&self) -> Result<()> {
    let inner = self.inner.clone();
    // 使用全局运行时 spawn 异步任务
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_logs().await;
      }
    });
    Ok(())
  }

  /// 订阅 Tunnel 元数据事件推送
  ///
  /// 回调参数为 JSON 字符串，格式：
  /// `{ action, nextRevision, definition? }`
  #[napi(ts_args_type = "callback: (err: Error | null, event: string) => void")]
  pub fn subscribe_tunnel_events(&self, callback: ThreadsafeFunction<String>) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let handler = move |event: crate::protocol::message::TunnelEventPushData| {
          let event_json = json!({
            "action": event.action,
            "nextRevision": event.next_revision,
            "definition": event.definition.map(|d| json!({
              "tunnelId": d.tunnel_id,
              "edgeId": d.edge_id,
              "ownerUserId": d.owner_user_id,
              "name": d.name,
              "appId": d.app_id,
              "protocol": d.protocol,
              "intentJson": d.intent_json,
              "configJson": d.config_json,
              "runtimeJson": d.runtime_json,
              "state": d.state,
              "actorRole": d.actor_role,
              "actorSessionId": d.actor_session_id,
              "actorDeviceId": d.actor_device_id,
              "version": d.version,
              "revision": d.revision,
              "deleted": d.deleted,
              "createdAt": d.created_at,
              "updatedAt": d.updated_at,
            }))
          })
          .to_string();
          let _ = callback.call(Ok(event_json), ThreadsafeFunctionCallMode::NonBlocking);
        };
        let _ = client.subscribe_tunnel_events(handler).await;
      }
    });
    Ok(())
  }

  /// 取消订阅 Tunnel 元数据事件推送
  #[napi]
  pub fn unsubscribe_tunnel_events(&self) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_tunnel_events().await;
      }
    });
    Ok(())
  }

  /// 订阅 WG Network 事件推送（network 级 snapshot 失效信号）
  ///
  /// 回调参数为 JSON 字符串，格式：
  /// `{ action, networkId, nextRevision }`
  /// 出于负载与一致性考虑，推送仅作为失效信号；前端收到后按 networkId
  /// 重新拉取 runtime snapshot（request/response 已具备完整快照能力）。
  #[napi(
    js_name = "subscribeWGNetworkEvents",
    ts_args_type = "callback: (err: Error | null, event: string) => void"
  )]
  pub fn subscribe_wg_network_events(&self, callback: ThreadsafeFunction<String>) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let handler = move |event: crate::protocol::message::WGNetworkEventPushData| {
          let event_json = json!({
            "action": event.action,
            "networkId": event.network_id,
            "nextRevision": event.next_revision,
          })
          .to_string();
          let _ = callback.call(Ok(event_json), ThreadsafeFunctionCallMode::NonBlocking);
        };
        let _ = client.subscribe_wg_network_events(handler).await;
      }
    });
    Ok(())
  }

  /// 取消订阅 WG Network 事件推送
  #[napi(js_name = "unsubscribeWGNetworkEvents")]
  pub fn unsubscribe_wg_network_events(&self) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_wg_network_events().await;
      }
    });
    Ok(())
  }

  /// 订阅 WG P2P 事件（Gather/Punch 推送自 Edge）
  ///
  /// 回调参数为 JSON 字符串：
  /// - Gather: `{ type: "gather", sessionId }`
  /// - Punch: `{ type: "punch", sessionId, clientId, punchAddrs: string[] }`
  #[napi(
    js_name = "subscribeWGP2PEvents",
    ts_args_type = "callback: (err: Error | null, event: string) => void"
  )]
  pub fn subscribe_wg_p2p_events(&self, callback: ThreadsafeFunction<String>) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let handler = move |event: crate::client::edge_client::WGP2PEvent| {
          let event_json = match event {
            crate::client::edge_client::WGP2PEvent::Gather { session_id } => {
              json!({ "type": "gather", "sessionId": session_id }).to_string()
            }
            crate::client::edge_client::WGP2PEvent::Punch { session_id, client_id, punch_addrs } => {
              json!({ "type": "punch", "sessionId": session_id, "clientId": client_id, "punchAddrs": punch_addrs }).to_string()
            }
          };
          let _ = callback.call(Ok(event_json), ThreadsafeFunctionCallMode::NonBlocking);
        };
        let _ = client.subscribe_wg_p2p_events(handler).await;
      }
    });
    Ok(())
  }

  #[napi(js_name = "unsubscribeWGP2PEvents")]
  pub fn unsubscribe_wg_p2p_events(&self) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_wg_p2p_events().await;
      }
    });
    Ok(())
  }

  /// 发送 WG Gather 响应
  #[napi(js_name = "sendWGGatherResponse")]
  pub async fn send_wg_gather_response(
    &self,
    session_id: String,
    client_id: String,
    local_addrs: Vec<String>,
    public_addr: String,
    nat_type: u8,
    local_wg_endpoint: Option<String>,
  ) -> Result<()> {
    let _ = (
      session_id,
      client_id,
      local_addrs,
      public_addr,
      nat_type,
      local_wg_endpoint,
    );
    Err(napi::Error::from_reason(
      "legacy WG gather response is disabled; use the scoped Agent event path",
    ))
  }

  /// 发送 WG Punch 结果
  #[napi(js_name = "sendWGPunchResponse")]
  pub async fn send_wg_punch_response(
    &self,
    session_id: String,
    client_id: String,
    success: bool,
    connected_addr: String,
  ) -> Result<()> {
    let _ = (session_id, client_id, success, connected_addr);
    Err(napi::Error::from_reason(
      "legacy WG punch response is disabled; path results require coordinator evidence",
    ))
  }

  /// 订阅 channel 连接活动事件（open/close）
  ///
  /// 回调参数为 JSON 字符串，格式：
  /// `{ phase, protocol, channelId, connectionId, localAddr, linkTypeHint, remoteEndpoint, reason, timestamp }`
  #[napi(ts_args_type = "callback: (err: Error | null, event: string) => void")]
  pub fn subscribe_channel_connection_events(
    &self,
    callback: ThreadsafeFunction<String>,
  ) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let handler = move |event: crate::client::edge_client::ChannelConnectionEventData| {
          let event_json = json!({
            "phase": event.phase,
            "protocol": event.protocol,
            "channelId": event.channel_id,
            "connectionId": event.connection_id,
            "localAddr": event.local_addr,
            "linkTypeHint": event.link_type_hint,
            "remoteEndpoint": event.remote_endpoint,
            "reason": event.reason,
            "timestamp": event.timestamp,
          })
          .to_string();
          let _ = callback.call(Ok(event_json), ThreadsafeFunctionCallMode::NonBlocking);
        };
        let _ = client.subscribe_channel_connection_events(handler).await;
      }
    });
    Ok(())
  }

  /// 取消订阅 channel 连接活动事件推送
  #[napi]
  pub fn unsubscribe_channel_connection_events(&self) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_channel_connection_events().await;
      }
    });
    Ok(())
  }

  /// 订阅 ICE P2P 事件
  ///
  /// 内部创建 IceAgent 并自动处理 ICE 信令流程（probe/punch/QUIC），
  /// 通过 callback 向 JS 层推送状态变更和结果。
  #[napi(ts_args_type = "callback: (err: Error | null, event: string) => void")]
  pub fn subscribe_ice_events(&self, callback: ThreadsafeFunction<String>) -> Result<()> {
    let inner = self.inner.clone();
    let cert = self.config.client_cert.clone().unwrap_or_default();
    let key = self.config.client_key.clone().unwrap_or_default();
    let ca = self.config.ca_cert.clone();
    let quic_keepalive_secs = self.config.quic_keepalive_secs.max(1);
    let quic_idle_timeout_secs = self.config.quic_idle_timeout_secs;
    let ice_agent_store = self.ice_agent.clone();

    get_runtime().spawn(async move {
      eprintln!("[JsEdgeClient] subscribe_ice_events invoked");
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      let Some(client) = client else {
        eprintln!("[JsEdgeClient] subscribe_ice_events skipped: inner client is None");
        return;
      };

      let agent_config = ice::IceAgentConfig {
        client_cert_pem: cert,
        client_key_pem: key,
        ca_cert_pem: ca,
        quic_keepalive_interval: Duration::from_secs(quic_keepalive_secs),
        quic_idle_timeout: Duration::from_secs(quic_idle_timeout_secs),
        ..Default::default()
      };
      let (agent, mut event_rx) = ice::IceAgent::new(agent_config);
      let agent = Arc::new(agent);

      *ice_agent_store.lock().await = Some(agent.clone());

      let client_for_events = client.clone();
      let agent_for_events = agent.clone();

      tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
          let event_json = match &event {
            ice::IceEvent::StateChanged { state, error } => {
              let ice_session_id = agent_for_events
                .snapshot()
                .await
                .ice_session_id
                .unwrap_or_default();
              if let Some(err_msg) = error.as_deref() {
                if !err_msg.is_empty() {
                  eprintln!(
                    "[JsEdgeClient] ICE_STATE recv sid={} state={:?} error={}",
                    ice_session_id, state, err_msg
                  );
                }
              }
              json!({
                "type": "state",
                "iceSessionId": ice_session_id,
                "state": format!("{:?}", state),
                "error": error,
              })
            }
            ice::IceEvent::PunchResult { ice_session_id, success, peer_addr, attempts_sent, failure_reason } => {
              if !ice_session_id.is_empty() {
                if let Err(err) = client_for_events.send_ice_punch_result(
                  ice_session_id, *success,
                  peer_addr.as_deref().unwrap_or(""),
                  *attempts_sent, 0,
                  failure_reason.as_deref().unwrap_or(""),
                ).await {
                  eprintln!(
                    "[JsEdgeClient] ICE_PUNCH_RESULT send failed sid={} success={} attempts_sent={} err={}",
                    ice_session_id, success, attempts_sent, err
                  );
                }
              }
              json!({
                "type": "punch_result",
                "iceSessionId": ice_session_id,
                "success": success,
                "peerAddr": peer_addr,
                "attemptsSent": attempts_sent,
                "failureReason": failure_reason,
              })
            }
            ice::IceEvent::QuicConnected { ice_session_id, connection_id, local_addr, peer_addr, rtt_ms } => {
              if !ice_session_id.is_empty() {
                if let Err(err) = client_for_events.send_ice_quic_connected(
                  ice_session_id, connection_id, local_addr, peer_addr, *rtt_ms,
                ).await {
                  eprintln!(
                    "[JsEdgeClient] ICE_QUIC_CONNECTED send failed sid={} conn_id={} local={} peer={} err={}",
                    ice_session_id, connection_id, local_addr, peer_addr, err
                  );
                }
              }
              Self::wire_p2p_forwarding(&client_for_events, &agent_for_events, "ice_quic_connected").await;
              json!({
                "type": "quic_connected",
                "iceSessionId": ice_session_id,
                "connectionId": connection_id,
                "localAddr": local_addr,
                "peerAddr": peer_addr,
                "rttMs": rtt_ms,
              })
            }
          };
          let _ = callback.call(Ok(event_json.to_string()), ThreadsafeFunctionCallMode::NonBlocking);
        }
      });

      let (ice_msg_tx, mut ice_msg_rx) = tokio::sync::mpsc::unbounded_channel::<client::IceMessage>();
      let agent_for_handler = agent.clone();
      tokio::spawn(async move {
        while let Some(msg) = ice_msg_rx.recv().await {
          let agent = agent_for_handler.clone();
          match msg {
            client::IceMessage::Start(data) => {
              eprintln!(
                "[JsEdgeClient] ICE_START recv sid={} token_len={} udp={} alt={} gather_timeout_ms={}",
                data.ice_session_id,
                data.token.len(),
                data.edge_udp_addr,
                data.edge_udp_addr_alt,
                data.gather_timeout_ms
              );
              if let Err(err) = agent.handle_ice_start(
                &data.ice_session_id, &data.token, &data.ice_pwd,
                &data.edge_udp_addr, &data.edge_udp_addr_alt,
                data.gather_timeout_ms,
              ).await {
                eprintln!(
                  "[JsEdgeClient] ICE_START handling failed sid={} udp={} alt={} err={}",
                  data.ice_session_id,
                  data.edge_udp_addr,
                  data.edge_udp_addr_alt,
                  err
                );
                agent
                  .handle_ice_state_change("failed", Some(format!("ice_start_failed: {}", err)))
                  .await;
              }
            }
            client::IceMessage::Punch(data) => {
              eprintln!(
                "[JsEdgeClient] ICE_PUNCH recv target={} extras={:?} attempts={} interval_ms={} start_delay_ms={}",
                data.target_addr,
                data.extra_target_addrs,
                data.attempts,
                data.interval_ms,
                data.start_delay_ms
              );
              if let Err(err) = agent.handle_ice_punch(
                &data.ice_session_id,
                &data.target_addr, &data.token, &data.ice_pwd,
                data.attempts, data.interval_ms, data.start_delay_ms,
                data.extra_target_addrs,
              ).await {
                eprintln!(
                  "[JsEdgeClient] ICE_PUNCH handling failed target={} err={}",
                  data.target_addr,
                  err
                );
                agent
                  .handle_ice_state_change("failed", Some(format!("ice_punch_failed: {}", err)))
                  .await;
              }
            }
            client::IceMessage::QuicStart(data) => {
              if let Err(err) = agent.handle_ice_quic_start(
                &data.ice_session_id,
                data.role, &data.peer_addr, &data.alpn, data.connect_timeout_ms,
              ).await {
                eprintln!(
                  "[JsEdgeClient] ICE_QUIC_START handling failed peer={} role={} err={}",
                  data.peer_addr,
                  data.role,
                  err
                );
                agent
                  .handle_ice_state_change("failed", Some(format!("ice_quic_start_failed: {}", err)))
                  .await;
              }
            }
            client::IceMessage::StateChange(data) => {
              let err = if data.error.is_empty() { None } else { Some(data.error) };
              agent.handle_ice_state_change(&data.state, err).await;
            }
          }
        }
      });
      let handler = move |msg: client::IceMessage| {
        if ice_msg_tx.send(msg).is_err() {
          eprintln!("[JsEdgeClient] drop ICE message: handler queue closed");
        }
      };
      match client.subscribe_ice_events(handler).await {
        Ok(()) => eprintln!("[JsEdgeClient] subscribe_ice_events registered"),
        Err(err) => eprintln!("[JsEdgeClient] subscribe_ice_events failed: {}", err),
      }
    });
    Ok(())
  }

  /// 取消订阅 ICE P2P 事件
  #[napi]
  pub fn unsubscribe_ice_events(&self) -> Result<()> {
    let inner = self.inner.clone();
    get_runtime().spawn(async move {
      let client = {
        let guard = inner.lock().await;
        guard.as_ref().cloned()
      };
      if let Some(client) = client {
        let _ = client.unsubscribe_ice_events().await;
      }
    });
    Ok(())
  }

  /// 注册 P2P 通道路由（Publisher 侧需要，告知 forwarder 该 channel 的本地目标地址）
  #[napi]
  pub async fn p2p_register_channel(
    &self,
    channel_id: String,
    local_addr: String,
    protocol: Option<String>,
  ) -> Result<()> {
    let protocol_hint = Self::normalize_protocol_hint(protocol);
    if !protocol_hint.is_empty() {
      eprintln!(
        "[JsEdgeClient] p2p_register_channel protocol_hint={} channel={} local={}",
        protocol_hint, channel_id, local_addr
      );
    }

    let client = self.get_client().await.ok();
    let binding = if let Some(client_ref) = client.as_ref() {
      Self::resolve_binding_for_channel(client_ref, &channel_id).await
    } else {
      None
    };
    let binding_protocol = binding
      .as_ref()
      .map(|(_local_addr, protocol)| protocol.trim().to_ascii_lowercase())
      .unwrap_or_default();
    let effective_protocol = if !protocol_hint.is_empty() {
      protocol_hint.clone()
    } else {
      binding_protocol.clone()
    };
    if !effective_protocol.is_empty() {
      eprintln!(
        "[JsEdgeClient] p2p_register_channel resolved protocol={} channel={}",
        effective_protocol, channel_id
      );
    }

    let agent = self.ice_agent.lock().await;
    let agent = agent
      .as_ref()
      .ok_or_else(|| Error::from_reason("no ice agent"))?;
    let fwd = agent
      .forwarder()
      .await
      .ok_or_else(|| Error::from_reason("no p2p forwarder"))?;
    fwd.register_channel(channel_id, local_addr).await;
    Ok(())
  }

  /// 启动 P2P Consumer 监听器（Consumer 侧调用，返回本地监听地址）
  #[napi]
  pub async fn p2p_start_consumer_listener(
    &self,
    channel_id: String,
    protocol: Option<String>,
  ) -> Result<String> {
    let protocol_hint = Self::normalize_protocol_hint(protocol);
    if !protocol_hint.is_empty() {
      eprintln!(
        "[JsEdgeClient] p2p_start_consumer_listener protocol_hint={} channel={}",
        protocol_hint, channel_id
      );
    }

    let binding = if let Ok(client) = self.get_client().await {
      Self::resolve_binding_for_channel(&client, &channel_id).await
    } else {
      None
    };
    let preferred_bind_addr = binding
      .as_ref()
      .map(|(local_addr, _protocol)| local_addr.clone());
    let binding_protocol = binding
      .as_ref()
      .map(|(_local_addr, protocol)| protocol.trim().to_ascii_lowercase())
      .unwrap_or_default();
    let effective_protocol = if !protocol_hint.is_empty() {
      protocol_hint.clone()
    } else {
      binding_protocol
    };

    let agent = self.ice_agent.lock().await;
    let agent = agent
      .as_ref()
      .ok_or_else(|| Error::from_reason("no ice agent"))?;
    let fwd = agent
      .forwarder()
      .await
      .ok_or_else(|| Error::from_reason("no p2p forwarder"))?;

    let addr = if Self::is_udp_protocol(&effective_protocol) {
      if let Some(bind_addr) = preferred_bind_addr.as_deref() {
        fwd
          .start_consumer_udp_listener_with_bind(&channel_id, Some(bind_addr))
          .await
          .map_err(Error::from_reason)?
      } else {
        fwd
          .start_consumer_udp_listener(&channel_id)
          .await
          .map_err(Error::from_reason)?
      }
    } else {
      if let Some(bind_addr) = preferred_bind_addr.as_deref() {
        fwd
          .start_consumer_listener_with_bind(&channel_id, Some(bind_addr))
          .await
          .map_err(Error::from_reason)?
      } else {
        fwd
          .start_consumer_listener(&channel_id)
          .await
          .map_err(Error::from_reason)?
      }
    };
    if let Some(bind_addr) = preferred_bind_addr.as_deref() {
      let addr_str = addr.to_string();
      if addr_str != bind_addr {
        if let Ok(client) = self.get_client().await {
          client
            .update_channel_local_addr(&channel_id, addr_str.clone())
            .await;
        }
      }
    }
    Ok(addr.to_string())
  }

  /// 获取 P2P Consumer 监听地址
  #[napi]
  pub async fn p2p_get_listener_addr(&self, channel_id: String) -> Result<Option<String>> {
    let agent = self.ice_agent.lock().await;
    let agent = agent
      .as_ref()
      .ok_or_else(|| Error::from_reason("no ice agent"))?;
    let fwd = agent.forwarder().await;
    match fwd {
      Some(fwd) => Ok(fwd.consumer_addr(&channel_id).await.map(|a| a.to_string())),
      None => Ok(None),
    }
  }

  /// 获取当前 P2P ICE 状态快照（前端状态展示用）
  #[napi]
  pub async fn p2p_get_state(&self) -> Result<String> {
    let agent = self.ice_agent.lock().await;
    let agent = agent
      .as_ref()
      .ok_or_else(|| Error::from_reason("no ice agent"))?;
    let snap = agent.snapshot().await;
    let state_str = format!("{:?}", snap.state);
    let result = json!({
      "state": state_str,
      "iceSessionId": snap.ice_session_id,
      "connectionId": snap.connection_id,
      "remoteAddr": snap.remote_addr,
      "rttMs": snap.rtt_ms,
    });
    Ok(result.to_string())
  }

  /// 关闭 P2P 连接，清理资源
  #[napi]
  pub async fn p2p_close(&self) -> Result<()> {
    let agent = self.ice_agent.lock().await;
    if let Some(agent) = agent.as_ref() {
      agent.close().await;
    }
    Ok(())
  }
}

// ==================== 底层协议接口（可选） ====================

/// 构建认证请求（底层接口）
#[napi]
pub fn build_auth_request(
  seq: u32,
  session_id: Option<String>,
  device_id: String,
  hostname: Option<String>,
  client_version: String,
  capabilities: Vec<String>,
  protocol_major: Option<u32>,
  protocol_minor: Option<u32>,
  required_features: Option<Vec<String>>,
  requested_features: Option<Vec<String>>,
) -> Vec<u8> {
  let mut builder = crate::protocol::MessageBuilder::new().seq(seq);
  if let Some(sid) = session_id {
    builder = builder.session_id(sid);
  }
  let caps: Vec<&str> = capabilities.iter().map(|s| s.as_str()).collect();
  let required = required_features.unwrap_or_default();
  let requested = requested_features.unwrap_or_default();
  let required_refs: Vec<&str> = required.iter().map(|s| s.as_str()).collect();
  let requested_refs: Vec<&str> = requested.iter().map(|s| s.as_str()).collect();
  builder.auth_request(
    &device_id,
    hostname.as_deref().unwrap_or(""),
    &client_version,
    &caps,
    protocol_major.unwrap_or(u32::from(crate::PROTOCOL_MAJOR)).min(u16::MAX as u32) as u16,
    protocol_minor.unwrap_or(u32::from(crate::PROTOCOL_MINOR)).min(u16::MAX as u32) as u16,
    &required_refs,
    &requested_refs,
  )
}

/// 构建心跳请求（底层接口）
#[napi]
pub fn build_heartbeat(seq: u32, session_id: Option<String>) -> Vec<u8> {
  let mut builder = crate::protocol::MessageBuilder::new().seq(seq);
  if let Some(sid) = session_id {
    builder = builder.session_id(sid);
  }
  builder.heartbeat()
}

/// 获取消息类型
#[napi]
pub fn get_message_type(data: Vec<u8>) -> Option<u16> {
  crate::protocol::MessageReader::get_type(&data)
    .ok()
    .map(|t| t.0)
}

/// 获取消息序列号
#[napi]
pub fn get_message_seq(data: Vec<u8>) -> Option<u32> {
  crate::protocol::MessageReader::get_seq(&data).ok()
}

/// 设置 Rust 调试开关（兼容 Electron 主进程 set-debug-settings）
///
/// 说明：
/// - 开启时会同时开启 UDP trace（便于排查端口转发链路）
/// - 关闭时会一并关闭 UDP trace
#[napi]
pub fn set_rust_debug_logging(enabled: bool) {
  crate::debug::set_rust_debug_enabled(enabled);
  crate::debug::set_udp_trace_enabled(enabled);
}

/// 单独设置 UDP trace 开关
#[napi]
pub fn set_udp_trace_logging(enabled: bool) {
  crate::debug::set_udp_trace_enabled(enabled);
}

/// 获取 UDP trace 文件路径
#[napi]
pub fn get_udp_trace_log_path() -> String {
  crate::debug::udp_trace_log_path()
    .to_string_lossy()
    .to_string()
}

/// 清空 UDP trace 文件
#[napi]
pub fn clear_udp_trace_log() -> bool {
  crate::debug::clear_udp_trace_log_file().is_ok()
}

#[cfg(test)]
mod tests {
  use super::{to_js_wg_network_member, to_js_wg_network_runtime_snapshot, JsEdgeClient};
  use crate::protocol::message::{
    WGNetworkDetailData, WGNetworkMemberData, WGNetworkRuntimeSnapshotData, WGRelayNodeInfoData,
    WGRelayPeerEndpointInfoData,
  };

  #[test]
  fn infer_channel_business_role_resolves_expected_suffix() {
    assert_eq!(
      JsEdgeClient::infer_channel_business_role("tun-1:tcp-main:publisher:actor-a"),
      Some("publisher")
    );
    assert_eq!(
      JsEdgeClient::infer_channel_business_role("tun-1:tcp-main:consumer:actor-b"),
      Some("consumer")
    );
    assert_eq!(
      JsEdgeClient::infer_channel_business_role("tun-1:tcp-main:controller:actor-c"),
      Some("consumer")
    );
  }

  #[test]
  fn infer_channel_business_role_handles_unknown_or_invalid_values() {
    assert_eq!(
      JsEdgeClient::infer_channel_business_role("tun-1:tcp-main:observer:actor-a"),
      None
    );
    assert_eq!(
      JsEdgeClient::infer_channel_business_role("tun-1:tcp-main"),
      None
    );
    assert_eq!(JsEdgeClient::infer_channel_business_role(""), None);
    assert_eq!(JsEdgeClient::infer_channel_business_role("   "), None);
  }

  #[test]
  fn to_js_wg_network_member_preserves_runtime_fields() {
    let member = to_js_wg_network_member(WGNetworkMemberData {
      member_id: "member-1".to_owned(),
      network_id: "net-1".to_owned(),
      user_id: "user-1".to_owned(),
      device_id: "device-1".to_owned(),
      hostname: "host-1".to_owned(),
      assigned_ip: "10.24.0.2".to_owned(),
      public_key: "pub-1".to_owned(),
      public_key_fingerprint: "fingerprint-1".to_owned(),
      membership_status: 2,
      presence_status: 1,
      is_current_device: false,
      joined_at: 1,
      last_seen_at: 2,
      updated_at: 3,
      is_relay_node: true,
      observed_endpoint: "203.0.113.10:51820".to_owned(),
      observed_at: 1725000000000,
      membership_generation: "membership-1".into(),
    });

    assert_eq!(member.membership_generation, "membership-1");
    assert_eq!(member.public_key, "pub-1");
    assert!(member.is_relay_node);
    assert_eq!(member.observed_endpoint, "203.0.113.10:51820");
  }

  #[test]
  fn to_js_wg_network_runtime_snapshot_includes_relay_node() {
    let snapshot = to_js_wg_network_runtime_snapshot(WGNetworkRuntimeSnapshotData {
      path_pairs: vec![],
      network: WGNetworkDetailData {
        network_id: "net-1".to_owned(),
        owner_user_id: "user-1".to_owned(),
        name: "Demo Net".to_owned(),
        description: String::new(),
        subnet: "10.24.0.0/24".to_owned(),
        relay_mode: 1,
        lifecycle_status: 1,
        runtime_health: 1,
        self_joined: true,
        self_member_id: "member-a".to_owned(),
        self_device_id: "device-a".to_owned(),
        member_count: 2,
        online_member_count: 2,
        created_at: 1,
        updated_at: 2,
        coordinator_edge_id: "edge-1".to_owned(),
      },
      members: vec![],
      peer_sessions: vec![],
      relay_node: Some(WGRelayNodeInfoData {
        member_id: "relay-1".to_owned(),
        public_key: "relay-public-key".to_owned(),
        endpoint: "123.56.218.110:51820".to_owned(),
        assigned_ip: "10.24.0.1".to_owned(),
        listen_port: 51820,
        peer_endpoints: vec![WGRelayPeerEndpointInfoData {
          public_key: "peer-public-key".to_owned(),
          assigned_ip: "10.24.0.2".to_owned(),
          endpoint: "123.56.218.110:59001".to_owned(),
          listen_port: 59001,
        }],
      }),
      lan_peer_endpoints: vec![],
      revision: 42,
      collected_at: 43,
      revision_epoch: "stream-epoch-1".into(),
      path_authority_epoch: "epoch-1".into(),
      network_policy_revision: u64::MAX,
    });

    assert_eq!(snapshot.path_authority_epoch, "epoch-1");
    assert_eq!(snapshot.network_policy_revision, u64::MAX.to_string());
    let relay_node = snapshot.relay_node.expect("relay node should be present");
    assert_eq!(relay_node.member_id, "relay-1");
    assert_eq!(relay_node.endpoint, "123.56.218.110:51820");
    assert_eq!(relay_node.listen_port, 51820);
    assert_eq!(relay_node.peer_endpoints.len(), 1);
    assert_eq!(relay_node.peer_endpoints[0].listen_port, 59001);
  }
}
