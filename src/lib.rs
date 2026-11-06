#![deny(clippy::all)]
// Many modules are only referenced from napi_entry (behind "napi-bindings" feature).
// Suppress dead_code warnings when building without that feature (e.g. yat-fe-linux).
#![allow(dead_code)]

mod client;
mod debug;
mod error;
mod ice;
mod protocol;

// Re-export core modules for Rust consumers (always available)
pub use client::*;
// Preserve typed connection failures for downstream recovery decisions.
pub use error::{CompatibilityError, CompatibilityReason, TransportError};
pub use protocol::compatibility::{PROTOCOL_MAJOR, PROTOCOL_MINOR};

// Re-export protocol types needed by downstream crates (e.g. yat-network)
pub mod protocol_types {
  pub use crate::protocol::generated::message::{
    WGPathBusinessEvidenceT, WGPathCandidateKind, WGPathCandidateT, WGPathError,
    WGPathMemberContextT, WGPathModeReason, WGPathModeSettingT, WGPathRequestKind,
    WGPathPhase, WGPathPlanT, WGPathReportKind, WGPathReportT,
    WGPathRequestT, WGPathRuntimeReportT, WGPathType, WGPathVersionT, WGRelayMode,
  };
  pub use crate::protocol::message::{TunnelChannelStartSpecData, TunnelDefinitionData};
}

// Re-export WG protocol types for yat-network session conversion.
pub use crate::protocol::message::{
  WGPathVersionData, WGPathReportData, WGPathPairRuntimeData, WGPathModeSettingData,
  WGAvailableDeviceData, WGNetworkDetailData, WGNetworkMemberData, WGNetworkRuntimeSnapshotData,
  WGNetworkSummaryData, WGLANPeerEndpointData, WGPeerEndpointObservationData, WGPeerSessionRuntimeData,
  WGRelayNodeInfoData, WGRelayPeerEndpointInfoData,
};

// Re-export Edge/Tunnel status types for yat-network session conversion.
pub use crate::protocol::message::{
  DNS01ChallengeData, DomainRecordData, DomainRuntimeData, EdgeChannelStatusData,
  EdgeDomainStatusData, EdgePortUsageData, EdgeStatusPushData, TunnelDeleteResponseData, TunnelStatusResponseData,
  TunnelSyncResponseData, TunnelUpsertResponseData, TunnelEventPushData,
};

// Re-export debug functions for network crate
pub use debug::set_rust_debug_enabled;

// Re-export ICE types for yat-network (IceAgent P2P hole-punching)
pub use crate::ice::{
  IceAgent, IceAgentConfig, IceEvent, IceState, IceStateSnapshot, P2pForwarder,
};

// NAPI bindings — compiled only when "napi-bindings" feature is enabled (default).
#[cfg(feature = "napi-bindings")]
mod napi_entry;

/// Bounded native WG codec for offline acceptance and diagnostic consumers.
/// This grants no authentication or execution authority; production clients
/// still require a physical EdgeSession subscription and its source token.
pub mod wg_path_codec {
  use crate::protocol::MessageBuilder;
  use crate::protocol_types::{WGPathReportT, WGPathRuntimeReportT, WGPathRequestT};

  pub fn encode_runtime(
    session: &str,
    report: &WGPathRuntimeReportT,
  ) -> Result<Vec<u8>, &'static str> {
    MessageBuilder::new()
      .session_id(session)
      .wg_path_runtime(report)
  }
  pub fn encode_report(session: &str, report: &WGPathReportT) -> Result<Vec<u8>, &'static str> {
    MessageBuilder::new()
      .session_id(session)
      .wg_path_report(report)
  }
  pub fn encode_request(session: &str, request: &WGPathRequestT) -> Result<Vec<u8>, &'static str> {
    MessageBuilder::new().session_id(session).wg_path_request(request)
  }
}
