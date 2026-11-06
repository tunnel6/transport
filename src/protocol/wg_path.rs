//! Bounded native WG coordination codec. Decoding does not grant authority:
//! the executor must bind the authenticated source/session, bootstrap, current
//! membership/runtime and command version before applying or probing anything.

use super::{message as fb, MessageBuilder};

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_CANDIDATES: usize = 32;
const MAX_ALLOWED_IPS: usize = 4096;
type CodecResult<T> = Result<T, &'static str>;

fn strings(values: &[Option<&str>], max: usize) -> CodecResult<()> {
  if values.iter().flatten().any(|v| v.len() > max) {
    return Err("WG path string exceeds bound");
  }
  Ok(())
}

fn version(v: fb::WGPathVersion<'_>) -> CodecResult<()> {
  strings(
    &[
      v.network_id(),
      v.member_a_id(),
      v.member_b_id(),
      v.coordinator_edge_id(),
      v.authority_epoch(),
      v.attempt_id(),
    ],
    256,
  )
}

fn mode(m: fb::WGPathModeSetting<'_>) -> CodecResult<()> {
  strings(&[m.decision_id(), m.request_id(), m.requested_by_member_id()], 256)?;
  if m.mode().0 > fb::WGPathType::RELAY.0 || m.reason().0 > fb::WGPathModeReason::CONFLICT_RECOVERY.0 {
    return Err("unknown WG pair mode/reason");
  }
  Ok(())
}

fn mode_object(m: &fb::WGPathModeSettingT) -> CodecResult<()> {
  strings(&[m.decision_id.as_deref(), m.request_id.as_deref(), m.requested_by_member_id.as_deref()], 256)?;
  if m.mode.0 > fb::WGPathType::RELAY.0 || m.reason.0 > fb::WGPathModeReason::CONFLICT_RECOVERY.0 {
    return Err("unknown WG pair mode/reason");
  }
  Ok(())
}

fn member(m: fb::WGPathMemberContext<'_>) -> CodecResult<()> {
  strings(
    &[
      m.member_id(),
      m.device_id(),
      m.public_key(),
      m.assigned_ip(),
      m.membership_generation(),
      m.runtime_generation(),
      m.network_environment(),
    ],
    256,
  )?;
  if let Some(candidates) = m.candidates() {
    if candidates.len() > MAX_CANDIDATES {
      return Err("excessive WG path candidates");
    }
    for c in candidates {
      strings(&[c.endpoint()], 64)?;
      if c.kind().0 == 0 || c.kind().0 > fb::WGPathCandidateKind::AUTHENTICATED_DIRECT.0 {
        return Err("unknown WG path candidate kind");
      }
    }
  }
  Ok(())
}

fn member_object(m: &fb::WGPathMemberContextT) -> CodecResult<()> {
  strings(
    &[
      m.member_id.as_deref(),
      m.device_id.as_deref(),
      m.public_key.as_deref(),
      m.assigned_ip.as_deref(),
      m.membership_generation.as_deref(),
      m.runtime_generation.as_deref(),
      m.network_environment.as_deref(),
    ],
    256,
  )?;
  if let Some(candidates) = &m.candidates {
    if candidates.len() > MAX_CANDIDATES {
      return Err("excessive WG path candidates");
    }
    for c in candidates {
      strings(&[c.endpoint.as_deref()], 64)?;
    }
  }
  Ok(())
}

fn version_object(v: &fb::WGPathVersionT) -> CodecResult<()> {
  strings(
    &[
      v.network_id.as_deref(),
      v.member_a_id.as_deref(),
      v.member_b_id.as_deref(),
      v.coordinator_edge_id.as_deref(),
      v.authority_epoch.as_deref(),
      v.attempt_id.as_deref(),
    ],
    256,
  )
}

fn history_object(p: &fb::WGPathPlanT) -> CodecResult<()> {
  if let Some(setting) = &p.mode_setting { mode_object(setting)?; }
  version_object(p.version.as_deref().ok_or("missing WG history version")?)?;
  member_object(p.member_a.as_deref().ok_or("missing WG history member A")?)?;
  member_object(p.member_b.as_deref().ok_or("missing WG history member B")?)?;
  strings(
    &[p.command_id.as_deref(), p.relay_public_key.as_deref()],
    256,
  )?;
  strings(
    &[p.endpoint_for_a.as_deref(), p.endpoint_for_b.as_deref()],
    64,
  )?;
  if p.phase != fb::WGPathPhase::CONFIRMED
    || p.phase_timeout_ms != 0
    || p.committed_path == fb::WGPathType::UNKNOWN
    || p.committed_path.0 > fb::WGPathType::RELAY.0
    || p.target_path != p.committed_path
    || p.relay_mode.0 > fb::WGRelayMode::FORCE.0
    || p.verification_nonce.as_ref().is_some_and(|v| v.len() > 16)
  {
    return Err("invalid WG confirmed history");
  }
  Ok(())
}

fn bounded_frame(data: Vec<u8>) -> CodecResult<Vec<u8>> {
  if data.len() > MAX_CONTROL_BYTES {
    return Err("oversized WG path frame");
  }
  Ok(data)
}

impl MessageBuilder<'_> {
  /// Typed uplinks are only encoded here; this does not publish capability or
  /// grant runtime readiness. Edge independently authenticates every report.
  pub fn wg_path_runtime(mut self, report: &fb::WGPathRuntimeReportT) -> CodecResult<Vec<u8>> {
    strings(
      &[
        report.network_id.as_deref(),
        report.authority_epoch.as_deref(),
      ],
      256,
    )?;
    member_object(
      report
        .member
        .as_deref()
        .ok_or("missing WG runtime member")?,
    )?;
    let header = self.build_header(fb::MessageType::WG_PATH_RUNTIME);
    let body = report.pack(&mut self.builder);
    bounded_frame(self.finish(
      header,
      fb::MessageBody::WGPathRuntimeReport,
      Some(body.as_union_value()),
    ))
  }

  pub fn wg_path_report(mut self, report: &fb::WGPathReportT) -> CodecResult<Vec<u8>> {
    if let Some(setting) = &report.saved_mode { mode_object(setting)?; }
    version_object(
      report
        .version
        .as_deref()
        .ok_or("missing WG report version")?,
    )?;
    if let Some(v) = &report.applied_version {
      version_object(v)?;
    }
    if let Some(history) = &report.last_confirmed_plan {
      if report.kind != fb::WGPathReportKind::RECONCILED {
        return Err("WG history requires reconciliation");
      }
      history_object(history)?;
    }
    strings(
      &[
        report.member_id.as_deref(),
        report.runtime_generation.as_deref(),
        report.network_environment.as_deref(),
        report.actual_owner_public_key.as_deref(),
        report.actual_endpoint.as_deref(),
        report.command_id.as_deref(),
        report.prepared_peer_public_key.as_deref(),
        report.prepared_endpoint.as_deref(),
      ],
      256,
    )?;
    strings(&[report.error_message.as_deref()], 1024)?;
    if let Some(ips) = &report.actual_allowed_ips {
      if ips.len() > MAX_ALLOWED_IPS || ips.iter().any(|v| v.len() > 64) {
        return Err("excessive WG actual allowed IPs");
      }
    }
    if report
      .business
      .as_ref()
      .and_then(|b| b.verification_nonce.as_ref())
      .is_some_and(|v| v.len() > 16)
    {
      return Err("excessive WG business nonce");
    }
    let header = self.build_header(fb::MessageType::WG_PATH_REPORT);
    let body = report.pack(&mut self.builder);
    bounded_frame(self.finish(
      header,
      fb::MessageBody::WGPathReport,
      Some(body.as_union_value()),
    ))
  }

  pub fn wg_path_request(mut self, request: &fb::WGPathRequestT) -> CodecResult<Vec<u8>> {
    strings(
      &[
        request.network_id.as_deref(),
        request.peer_member_id.as_deref(),
        request.request_id.as_deref(),
        request.observed_command_id.as_deref(),
        request.observed_authority_epoch.as_deref(),
      ],
      256,
    )?;
    if let Some(setting) = &request.local_mode { mode_object(setting)?; }
    if request.requested_path.0 > fb::WGPathType::RELAY.0 || request.kind.0 > fb::WGPathRequestKind::SWITCH_PATH.0 {
      return Err("unknown WG requested path");
    }
    match request.kind {
      fb::WGPathRequestKind::LEGACY => {
        if request.request_id.is_some() || request.local_mode.is_some() || request.observed_command_id.is_some() {
          return Err("legacy intent cannot carry mode facts");
        }
      }
      fb::WGPathRequestKind::CHANGE_MODE | fb::WGPathRequestKind::SWITCH_PATH => {
        if request.request_id.as_deref().is_none_or(str::is_empty) || request.local_mode.is_some() || request.repair {
          return Err("invalid WG mode change context");
        }
      }
      fb::WGPathRequestKind::SYNC_MODE => {
        if (request.request_id.is_some() && (request.observed_authority_epoch.as_deref().is_none_or(str::is_empty) || request.local_mode.is_none())) || request.requested_path != fb::WGPathType::UNKNOWN || request.repair {
          return Err("mode sync is a fact, not a change");
        }
      }
      _ => return Err("unknown WG request kind"),
    }
    if request.kind == fb::WGPathRequestKind::SYNC_MODE && request.request_id.is_none() && request.observed_command_id.as_deref().is_none_or(str::is_empty) {
      return Err("mode sync needs captured command identity");
    }
    let header = self.build_header(fb::MessageType::WG_PATH_REQUEST);
    let body = request.pack(&mut self.builder);
    bounded_frame(self.finish(
      header,
      fb::MessageBody::WGPathRequest,
      Some(body.as_union_value()),
    ))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::protocol::MessageReader;

  #[test]
  fn shared_mode_contract_keeps_save_ack_change_and_periodic_fact_distinct() {
    let mut p = plan();
    let setting = fb::WGPathModeSettingT { mode: fb::WGPathType::RELAY, decision_id: Some("decision".into()), reason: fb::WGPathModeReason::USER, requested_by_member_id: Some("a".into()), request_id: Some("click".into()) };
    p.mode_setting = Some(Box::new(setting.clone()));
    let request = fb::WGPathRequestT { network_id: Some("net".into()), peer_member_id: Some("b".into()), requested_path: fb::WGPathType::RELAY, kind: fb::WGPathRequestKind::CHANGE_MODE, request_id: Some("click".into()), observed_command_id: p.command_id.clone(), ..Default::default() };
    let bytes = MessageBuilder::new().wg_path_request(&request).unwrap();
    assert_eq!(MessageReader::parse(&bytes).unwrap().body_as_wgpath_request().unwrap().unpack(), request);
    let mut sync = request.clone();
    sync.kind = fb::WGPathRequestKind::SYNC_MODE;
    assert!(MessageBuilder::new().wg_path_request(&sync).is_err());
    sync.request_id = None;
    sync.requested_path = fb::WGPathType::UNKNOWN;
    sync.local_mode = Some(Box::new(setting.clone()));
    let bytes = MessageBuilder::new().wg_path_request(&sync).unwrap();
    assert_eq!(MessageReader::parse(&bytes).unwrap().body_as_wgpath_request().unwrap().unpack(), sync);
    let mut report = fb::WGPathReportT { version: p.version.clone(), saved_mode: Some(Box::new(setting)), ..Default::default() };
    let bytes = MessageBuilder::new().wg_path_report(&report).unwrap();
    assert_eq!(MessageReader::parse(&bytes).unwrap().body_as_wgpath_report().unwrap().unpack().saved_mode, report.saved_mode);
    report.saved_mode.as_mut().unwrap().decision_id = Some("x".repeat(257));
    assert!(MessageBuilder::new().wg_path_report(&report).is_err());
    assert!(fb::WGPathPairRuntimeInfoT::default().plan.is_none());
    assert!(!fb::WGPathPairRuntimeInfoT::default().mode_saved_a);
  }

  fn plan() -> fb::WGPathPlanT {
    fb::WGPathPlanT {
      version: Some(Box::new(fb::WGPathVersionT {
        network_id: Some("net".into()),
        member_a_id: Some("a".into()),
        member_b_id: Some("b".into()),
        authority_epoch: Some("epoch".into()),
        coordinator_edge_id: Some("edge".into()),
        pair_revision: u64::MAX,
        network_policy_revision: u64::MAX,
        attempt_id: Some("attempt".into()),
      })),
      member_a: Some(Box::new(fb::WGPathMemberContextT {
        member_id: Some("a".into()),
        runtime_generation: Some("runtime-a".into()),
        ..Default::default()
      })),
      member_b: Some(Box::new(fb::WGPathMemberContextT {
        member_id: Some("b".into()),
        runtime_generation: Some("runtime-b".into()),
        ..Default::default()
      })),
      phase: fb::WGPathPhase::HEALTH,
      committed_path: fb::WGPathType::DIRECT,
      target_path: fb::WGPathType::DIRECT,
      command_id: Some("health".into()),
      phase_timeout_ms: 1000,
      verification_nonce: Some(vec![8; 16]),
      ..Default::default()
    }
  }


  #[test]
  fn native_wg_typed_uplinks_roundtrip_and_bound_allocations() {
    let p = plan();
    let runtime = fb::WGPathRuntimeReportT {
      network_id: Some("net".into()),
      authority_epoch: Some("epoch".into()),
      network_policy_revision: u64::MAX,
      member: p.member_a.clone(),
      ..Default::default()
    };
    let bytes = MessageBuilder::new()
      .session_id("session")
      .wg_path_runtime(&runtime)
      .unwrap();
    assert_eq!(
      MessageReader::get_type(&bytes).unwrap(),
      fb::MessageType::WG_PATH_RUNTIME
    );
    assert_eq!(
      MessageReader::parse(&bytes)
        .unwrap()
        .body_as_wgpath_runtime_report()
        .unwrap()
        .unpack(),
      runtime
    );
    let report = fb::WGPathReportT {
      version: p.version.clone(),
      kind: fb::WGPathReportKind::HEALTH,
      command_id: p.command_id.clone(),
      applied_version: p.version.clone(),
      actual_allowed_ips: Some(vec!["10.24.0.2/32".into()]),
      business: Some(Box::new(fb::WGPathBusinessEvidenceT {
        sent: 2,
        replies: 1,
        verification_nonce: p.verification_nonce,
        measured_at: u64::MAX,
      })),
      ..Default::default()
    };
    let bytes = MessageBuilder::new().wg_path_report(&report).unwrap();
    assert_eq!(
      MessageReader::get_type(&bytes).unwrap(),
      fb::MessageType::WG_PATH_REPORT
    );
    assert_eq!(
      MessageReader::parse(&bytes)
        .unwrap()
        .body_as_wgpath_report()
        .unwrap()
        .unpack(),
      report
    );
    let request = fb::WGPathRequestT {
      network_id: Some("net".into()),
      peer_member_id: Some("b".into()),
      requested_path: fb::WGPathType::RELAY,
      repair: true,
      ..Default::default()
    };
    let bytes = MessageBuilder::new().wg_path_request(&request).unwrap();
    assert_eq!(
      MessageReader::get_type(&bytes).unwrap(),
      fb::MessageType::WG_PATH_REQUEST
    );
    assert_eq!(
      MessageReader::parse(&bytes)
        .unwrap()
        .body_as_wgpath_request()
        .unwrap()
        .unpack(),
      request
    );
    let mut oversized = runtime;
    oversized.member.as_mut().unwrap().candidates = Some(vec![fb::WGPathCandidateT::default(); 33]);
    assert!(MessageBuilder::new().wg_path_runtime(&oversized).is_err());
    let mut oversized = report;
    oversized.actual_allowed_ips = Some(vec!["10.24.0.2/32".into(); 4097]);
    assert!(MessageBuilder::new().wg_path_report(&oversized).is_err());
    oversized.actual_allowed_ips = None;
    oversized.business.as_mut().unwrap().verification_nonce = Some(vec![0; 17]);
    assert!(MessageBuilder::new().wg_path_report(&oversized).is_err());
    let mut oversized = request;
    oversized.network_id = Some("x".repeat(257));
    assert!(MessageBuilder::new().wg_path_request(&oversized).is_err());
  }
  #[test]
  fn retained_confirmation_roundtrip_is_optional_and_reconciliation_only() {
    let mut history = plan();
    history.phase = fb::WGPathPhase::CONFIRMED;
    history.phase_timeout_ms = 0;
    let mut report = fb::WGPathReportT {
      version: history.version.clone(),
      applied_version: history.version.clone(),
      kind: fb::WGPathReportKind::RECONCILED,
      actual_path: fb::WGPathType::RELAY,
      last_confirmed_plan: Some(Box::new(history.clone())),
      ..Default::default()
    };
    let bytes = MessageBuilder::new().wg_path_report(&report).unwrap();
    let decoded = MessageReader::parse(&bytes)
      .unwrap()
      .body_as_wgpath_report()
      .unwrap()
      .unpack();
    assert_eq!(decoded, report);
    assert_ne!(
      decoded.actual_path,
      decoded.last_confirmed_plan.as_ref().unwrap().committed_path
    );
    report.kind = fb::WGPathReportKind::VERIFIED;
    assert!(MessageBuilder::new().wg_path_report(&report).is_err());
    report.kind = fb::WGPathReportKind::RECONCILED;
    type Mutation = fn(&mut fb::WGPathPlanT);
    let invalid: &[Mutation] = &[
      |p| p.version = None,
      |p| p.member_a = None,
      |p| p.member_b = None,
      |p| p.phase = fb::WGPathPhase::VERIFY,
      |p| p.phase_timeout_ms = 1000,
      |p| p.target_path = fb::WGPathType::RELAY,
      |p| p.committed_path = fb::WGPathType::UNKNOWN,
      |p| p.relay_mode = fb::WGRelayMode(255),
      |p| p.endpoint_for_a = Some("x".repeat(65)),
      |p| p.verification_nonce = Some(vec![1; 17]),
      |p| p.member_a.as_mut().unwrap().membership_generation = Some("x".repeat(257)),
      |p| p.member_b.as_mut().unwrap().candidates = Some(vec![fb::WGPathCandidateT::default(); 33]),
    ];
    for mutate in invalid {
      let mut changed = history.clone();
      mutate(&mut changed);
      report.last_confirmed_plan = Some(Box::new(changed));
      assert!(MessageBuilder::new().wg_path_report(&report).is_err());
    }
    report.last_confirmed_plan = None;
    assert!(MessageBuilder::new().wg_path_report(&report).is_ok());
  }
}
