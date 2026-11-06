//! One wire protocol generation for SaaS and OpenYAT, independent of release tags.

use super::generated::message;
use super::message::AuthResponseData;
use crate::error::{CompatibilityError, CompatibilityReason, Result, TransportError};
use std::sync::LazyLock;

pub const PROTOCOL_MAJOR: u16 = message::ProtocolMajor::CURRENT.0;
pub const PROTOCOL_MINOR: u16 = message::ProtocolMinor::CURRENT.0;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseCompatibility {
  minimum_edge_version: String,
}

// Generated copy of api/compatibility.json, synced alongside the API bindings.
// Keeping artifacts in this crate allows standalone native builds.
// The UI displays this policy through Auth diagnostics, without its own config.
static RELEASE_COMPATIBILITY: LazyLock<ReleaseCompatibility> = LazyLock::new(|| {
  serde_json::from_str(include_str!("../../build/compatibility.json"))
    .expect("invalid bundled release compatibility policy")
});

fn compatibility_error(response: &AuthResponseData, minimum: &str, reason: CompatibilityReason, message: String) -> TransportError {
  TransportError::Incompatible(Box::new(CompatibilityError {
    reason,
    edge_version: response.server_version.clone(),
    minimum_edge_version: minimum.to_string(),
    client_protocol: format!("{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"),
    edge_protocol: format!("{}.{}", response.negotiated_protocol_major, response.negotiated_protocol_minor),
    message,
  }))
}

fn validate_edge_version(response: &AuthResponseData, minimum: &str) -> Result<()> {
  let minimum = minimum.trim();
  // An explicit empty API policy disables product-version parsing and checks.
  // Protocol and authentication checks still run before reaching this point.
  if minimum.is_empty() {
    return Ok(());
  }
  let version = &response.server_version;
  let minimum_version = semver::Version::parse(minimum)
    .expect("invalid minimum Edge version in bundled release policy");
  let normalized = version.trim().strip_prefix('v').unwrap_or(version.trim());
  let Ok(actual) = semver::Version::parse(normalized) else {
    log::warn!(
      "Skipping Edge product-version check: unrecognized server_version={version:?}, minimum={minimum}"
    );
    return Ok(());
  };
  if actual >= minimum_version {
    return Ok(());
  }
  Err(compatibility_error(response, minimum, CompatibilityReason::EdgeVersionTooOld, format!(
    "Unsupported Edge version {version:?}: this client requires Edge >= {minimum}. Upgrade Edge before connecting; the wire protocol must also be compatible.",
  )))
}

pub(crate) fn validate_auth_response(response: &AuthResponseData) -> Result<()> {
  validate_auth_response_with_minimum(response, &RELEASE_COMPATIBILITY.minimum_edge_version)
}

fn validate_auth_response_with_minimum(response: &AuthResponseData, minimum: &str) -> Result<()> {
  // Failed identity/capability checks can leave protocol fields at their
  // defaults. Only an explicit protocol rejection or a successful legacy Auth
  // is evidence of a mismatch.
  if (response.success && response.negotiated_protocol_major != PROTOCOL_MAJOR)
    || response.reason_code == message::CompatibilityReasonCode::INCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH.0
    || response.reason_code == message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK.0 {
    return Err(compatibility_error(response, minimum, CompatibilityReason::ProtocolMismatch, format!(
      "Client/Edge compatibility rejected: client protocol {}.{}, Edge {} protocol {}.{}; reason_code={}; {}. Use client and Edge builds with matching wire protocols.",
      PROTOCOL_MAJOR, PROTOCOL_MINOR, response.server_version,
      response.negotiated_protocol_major, response.negotiated_protocol_minor,
      response.reason_code, response.error_message,
    )));
  }
  if !response.success || response.session_id.is_empty()
    || ![message::CompatibilityLevel::COMPAT_FULL.0, message::CompatibilityLevel::COMPAT_DEGRADED.0].contains(&response.compatibility_level) {
    return Err(TransportError::AuthFailed(format!(
      "Edge authentication rejected: reason_code={}; {}", response.reason_code, response.error_message,
    )));
  }
  validate_edge_version(response, minimum)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::protocol::{MessageBuilder, MessageReader};

  fn response(major: u16, level: message::CompatibilityLevel, reason: message::CompatibilityReasonCode) -> AuthResponseData {
    AuthResponseData {
      success: true, session_id: "session".into(), server_version: "1.3.0".into(),
      error_code: 0, error_message: String::new(), server_time: 0,
      negotiated_protocol_major: major, negotiated_protocol_minor: 0,
      accepted_features: vec![], rejected_features: vec![],
      compatibility_level: level.0, reason_code: reason.0,
    }
  }

  #[test]
  fn protocol_v2_rejects_legacy_and_invalid_auth_before_session_activation() {
    for (major, level, reason) in [
      (1, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL),
      (3, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL),
      (2, message::CompatibilityLevel::COMPAT_UNKNOWN, message::CompatibilityReasonCode::REASON_UNKNOWN),
      (2, message::CompatibilityLevel(255), message::CompatibilityReasonCode::OK_FULL),
      (2, message::CompatibilityLevel::COMPAT_DEGRADED, message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK),
      (2, message::CompatibilityLevel::COMPAT_INCOMPATIBLE, message::CompatibilityReasonCode::INCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH),
    ] {
      let error = validate_auth_response(&response(major, level, reason)).unwrap_err();
      if major != PROTOCOL_MAJOR
        || reason == message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK
        || reason == message::CompatibilityReasonCode::INCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH {
        assert!(matches!(error, TransportError::Incompatible(issue) if issue.reason == CompatibilityReason::ProtocolMismatch));
      } else {
        assert!(matches!(error, TransportError::AuthFailed(_)));
      }
    }
    for level in [message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityLevel::COMPAT_DEGRADED] {
      validate_auth_response(&response(PROTOCOL_MAJOR, level, message::CompatibilityReasonCode::OK_FULL)).unwrap();
    }
    let mut denied = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    denied.success = false;
    assert!(validate_auth_response(&denied).is_err());
    let mut missing_session = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    missing_session.session_id.clear();
    assert!(validate_auth_response(&missing_session).is_err());
  }

  #[test]
  fn release_baseline_is_checked_even_when_wire_protocol_matches() {
    for version in ["1.2.99", "v1.2.0", "1.3.0-rc.1"] {
      let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
      auth.server_version = version.into();
      let error = validate_auth_response_with_minimum(&auth, "1.3.0").unwrap_err().to_string();
      assert!(error.contains("requires Edge >= 1.3.0"), "{version}: {error}");
    }
    for version in ["1.3.0", "v1.3.0", "1.3.0+build.42", "1.3.1", "1.10.0", "2.0.0"] {
      let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
      auth.server_version = version.into();
      validate_auth_response_with_minimum(&auth, "1.3.0").unwrap();
    }
  }

  #[test]
  fn auth_diagnostics_distinguish_protocol_version_identity_and_capabilities() {
    let protocol = response(1, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    assert!(matches!(validate_auth_response(&protocol), Err(TransportError::Incompatible(issue))
      if issue.reason == CompatibilityReason::ProtocolMismatch && issue.edge_protocol == "1.0" && issue.client_protocol == "2.0"));

    let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    auth.server_version = "1.2.9".into();
    assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::Incompatible(issue))
      if issue.reason == CompatibilityReason::EdgeVersionTooOld && issue.minimum_edge_version == "1.3.0"));
    auth.server_version.clear();
    validate_auth_response_with_minimum(&auth, "1.3.0").unwrap();

    for reason in [message::CompatibilityReasonCode::INCOMPATIBLE_REQUIRED_FEATURE_MISSING,
      message::CompatibilityReasonCode::INCOMPATIBLE_SECURITY_BASELINE,
      message::CompatibilityReasonCode::REASON_UNKNOWN] {
      let mut denied = response(0, message::CompatibilityLevel::COMPAT_INCOMPATIBLE, reason);
      denied.success = false;
      assert!(matches!(validate_auth_response(&denied), Err(TransportError::AuthFailed(_))));
    }
  }

  #[test]
  fn unrecognized_edge_versions_skip_only_the_product_version_gate() {
    for version in ["openyat-1.3.0", "unknown", "", " \t\n", "abc12345", "edge-v0.1.0", "1.3.0-invalid!"] {
      let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
      auth.server_version = version.into();
      for level in [message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityLevel::COMPAT_DEGRADED] {
        auth.compatibility_level = level.0;
        validate_auth_response_with_minimum(&auth, "1.3.0").unwrap_or_else(|error| panic!("{version:?}: {error}"));
      }
      for major in [1, 3] {
        auth.negotiated_protocol_major = major;
        assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::Incompatible(issue))
          if issue.reason == CompatibilityReason::ProtocolMismatch && issue.edge_version == version));
      }
      auth.negotiated_protocol_major = PROTOCOL_MAJOR;
      for reason in [message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK,
        message::CompatibilityReasonCode::INCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH] {
        auth.reason_code = reason.0;
        assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::Incompatible(issue))
          if issue.reason == CompatibilityReason::ProtocolMismatch));
      }
      auth.reason_code = message::CompatibilityReasonCode::OK_FULL.0;
      for level in [message::CompatibilityLevel::COMPAT_UNKNOWN, message::CompatibilityLevel::COMPAT_INCOMPATIBLE] {
        auth.compatibility_level = level.0;
        assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::AuthFailed(_))));
      }
      auth.compatibility_level = message::CompatibilityLevel::COMPAT_FULL.0;
      auth.success = false;
      assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::AuthFailed(_))));
      auth.success = true;
      auth.session_id.clear();
      assert!(matches!(validate_auth_response_with_minimum(&auth, "1.3.0"), Err(TransportError::AuthFailed(_))));
    }
  }

  #[test]
  fn empty_minimum_disables_product_version_parsing_and_comparison() {
    for minimum in ["", " \t\n"] {
      for version in ["openyat-1.3.0", "0.1.0", "1.3.0-rc.1", "", "unknown"] {
        for level in [message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityLevel::COMPAT_DEGRADED] {
          let mut auth = response(PROTOCOL_MAJOR, level, message::CompatibilityReasonCode::OK_FULL);
          auth.server_version = version.into();
          validate_auth_response_with_minimum(&auth, minimum).unwrap_or_else(|error| panic!("{version:?}: {error}"));
        }
      }
    }
  }

  #[test]
  fn empty_minimum_preserves_protocol_and_authentication_gates() {
    for (major, level, reason, protocol_mismatch) in [
      (1, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL, true),
      (3, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL, true),
      (PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_DEGRADED, message::CompatibilityReasonCode::OK_DEGRADED_LEGACY_FALLBACK, true),
      (PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_INCOMPATIBLE, message::CompatibilityReasonCode::INCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH, true),
      (PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_UNKNOWN, message::CompatibilityReasonCode::REASON_UNKNOWN, false),
      (PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_INCOMPATIBLE, message::CompatibilityReasonCode::INCOMPATIBLE_REQUIRED_FEATURE_MISSING, false),
      (PROTOCOL_MAJOR, message::CompatibilityLevel(255), message::CompatibilityReasonCode::OK_FULL, false),
    ] {
      let mut auth = response(major, level, reason);
      auth.server_version = "openyat-1.3.0".into();
      let error = validate_auth_response_with_minimum(&auth, "").unwrap_err();
      if protocol_mismatch {
        assert!(matches!(error, TransportError::Incompatible(issue)
          if issue.reason == CompatibilityReason::ProtocolMismatch && issue.minimum_edge_version.is_empty()));
      } else {
        assert!(matches!(error, TransportError::AuthFailed(_)));
      }
    }
    let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    auth.success = false;
    assert!(matches!(validate_auth_response_with_minimum(&auth, ""), Err(TransportError::AuthFailed(_))));
    auth.success = true;
    auth.session_id.clear();
    assert!(matches!(validate_auth_response_with_minimum(&auth, ""), Err(TransportError::AuthFailed(_))));
  }

  #[test]
  fn bundled_policy_controls_the_product_version_gate() {
    for version in ["openyat-1.3.0", "", "unknown"] {
      let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
      auth.server_version = version.into();
      validate_auth_response(&auth).unwrap();
    }
    let mut auth = response(PROTOCOL_MAJOR, message::CompatibilityLevel::COMPAT_FULL, message::CompatibilityReasonCode::OK_FULL);
    auth.server_version = "0.0.0-legacy".into();
    if RELEASE_COMPATIBILITY.minimum_edge_version.trim().is_empty() {
      validate_auth_response(&auth).unwrap();
    } else {
      assert!(matches!(validate_auth_response(&auth), Err(TransportError::Incompatible(issue))
        if issue.reason == CompatibilityReason::EdgeVersionTooOld));
    }
  }

  #[test]
  fn protocol_v2_auth_is_explicit_and_message_body_tags_are_stable() {
    let bytes = MessageBuilder::new().auth_request("device", "host", "1.3.0", &[], PROTOCOL_MAJOR, PROTOCOL_MINOR, &[], &[]);
    let msg = MessageReader::parse(&bytes).unwrap();
    assert_eq!(msg.body_as_auth_request().unwrap().protocol_major(), 2);
    assert_eq!(message::MessageType::EDGE_DOMAIN_CERTIFICATE_REQUEST.0, 0x6009);
    assert_eq!(message::MessageType::EDGE_DOMAIN_CERTIFICATE_RESPONSE.0, 0x600A);
    assert_eq!(message::MessageType::TUNNEL_SYNC_REQUEST.0, 0x6100);
    assert_eq!(message::MessageType::TUNNEL_LEAVE_RESPONSE.0, 0x6110);
    assert_eq!(message::MessageBody::EdgeDomainCertificateRequest.0, 82);
    assert_eq!(message::MessageBody::EdgeDomainCertificateResponse.0, 83);
    // Missing fields must continue to decode as legacy, including in new bindings.
    assert_eq!(message::AuthRequestArgs::default().protocol_major, 1);
    assert_eq!(message::AuthResponseArgs::default().negotiated_protocol_major, 1);
  }
}
