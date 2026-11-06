//! Synchronous source-bound lifecycle facts, independent of the legacy event
//! subscriber. Domain membership decisions remain in the Network crate.

use super::*;
use crate::protocol::message::{ParsedResponse, WGNetworkRuntimeSnapshotData};

pub enum WGPathLifecycleFact<'a> {
  Snapshot(&'a WGNetworkRuntimeSnapshotData),
  Event {
    network_id: &'a str,
    revision_epoch: &'a str,
    revision: u64,
    action: u8,
    snapshot: Option<&'a WGNetworkRuntimeSnapshotData>,
  },
  /// Successful mutations without a complete snapshot require fresh assembly.
  /// None means the old wire response does not identify the affected network.
  Changed(Option<&'a str>),
}

#[cfg(test)]
mod tests {
  use super::super::super::read_loop::ReadDispatch;
  use super::*;

  fn event(session: &str) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let body = message::WGNetworkEventPushT {
      action: message::WGNetworkEventAction::DELETE,
      network_id: Some("network".into()),
      next_revision: 9,
      revision_epoch: Some("edge-stream".into()),
      snapshot: None,
    }
    .pack(&mut builder);
    envelope(
      &mut builder,
      MessageType::WG_NETWORK_EVENT_PUSH,
      session,
      message::MessageBody::WGNetworkEventPush,
      body.as_union_value(),
    )
  }

  fn mutation(session: &str, success: bool) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let mut response = message::WGUpdateMemberResponseT::default();
    response.success = success;
    response.network_id = Some("network".into());
    let body = response.pack(&mut builder);
    envelope(
      &mut builder,
      MessageType::WG_UPDATE_MEMBER_ACK,
      session,
      message::MessageBody::WGUpdateMemberResponse,
      body.as_union_value(),
    )
  }

  #[tokio::test]
  async fn runtime_snapshot_is_observed_before_its_request_waiter_can_resume() {
    let connection = Arc::new(PathConnection::new(Some("edge".into())));
    let subscription = connection.subscribe("session".into()).unwrap();
    let seen = Arc::new(AtomicBool::new(false));
    let observed = seen.clone();
    subscription
      .session
      .observe_lifecycle(Arc::new(move |fact| {
        let WGPathLifecycleFact::Snapshot(snapshot) = fact else {
          panic!("expected snapshot");
        };
        assert_eq!(snapshot.network.network_id, "network");
        assert_eq!(snapshot.network_policy_revision, u64::MAX);
        observed.store(true, Ordering::Release);
      }))
      .unwrap();
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let mut snapshot = message::WGNetworkRuntimeSnapshotInfoT::default();
    let mut network = message::WGNetworkDetailInfoT::default();
    network.network_id = Some("network".into());
    snapshot.network = Some(Box::new(network));
    snapshot.network_policy_revision = u64::MAX;
    let mut response = message::WGNetworkRuntimeResponseT::default();
    response.success = true;
    response.snapshot = Some(Box::new(snapshot));
    let body = response.pack(&mut builder);
    let bytes = envelope(
      &mut builder,
      MessageType::WG_NETWORK_RUNTIME_RESPONSE,
      "session",
      message::MessageBody::WGNetworkRuntimeResponse,
      body.as_union_value(),
    );
    let client = EdgeClient::new(EdgeClientConfig::default());
    let (tx, rx) = oneshot::channel();
    client.pending_requests.lock().await.insert(42, tx);
    connection
      .observe_control_frame(
        MessageType::WG_NETWORK_RUNTIME_RESPONSE,
        &bytes,
        Some("session"),
      )
      .unwrap();
    assert!(seen.load(Ordering::Acquire));
    <EdgeClient as ReadDispatch>::dispatch_pending_response(
      MessageType::WG_NETWORK_RUNTIME_RESPONSE,
      bytes.clone(),
      &client.pending_requests,
      &client.pending_type_requests,
    )
    .await;
    assert_eq!(rx.await.unwrap(), bytes);
    assert!(connection
      .observe_control_frame(MessageType::WG_NETWORK_EVENT_PUSH, b"bad", Some("session"))
      .is_err());
    assert!(
      !subscription.session.is_active(),
      "invalid source must also wake a waiting consumer"
    );
  }

  fn envelope(
    builder: &mut flatbuffers::FlatBufferBuilder<'_>,
    kind: MessageType,
    session: &str,
    body_type: message::MessageBody,
    body: flatbuffers::WIPOffset<flatbuffers::UnionWIPOffset>,
  ) -> Vec<u8> {
    let session = builder.create_string(session);
    let header = message::MessageHeader::create(
      builder,
      &message::MessageHeaderArgs {
        type_: kind,
        session_id: Some(session),
        seq: 42,
        ..Default::default()
      },
    );
    let root = message::Message::create(
      builder,
      &message::MessageArgs {
        header: Some(header),
        body_type,
        body: Some(body),
      },
    );
    builder.finish(root, None);
    builder.finished_data().to_vec()
  }

  #[tokio::test]
  async fn source_guard_precedes_legacy_event_queue_and_request_receipt() {
    let connection = Arc::new(PathConnection::new(Some("edge".into())));
    let subscription = connection.subscribe("session".into()).unwrap();
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = order.clone();
    subscription
      .session
      .observe_lifecycle(Arc::new(move |fact| {
        match fact {
          WGPathLifecycleFact::Event {
            network_id,
            revision_epoch,
            revision,
            action,
            snapshot,
          } => {
            assert_eq!(
              (network_id, revision_epoch, revision, action),
              ("network", "edge-stream", 9, 2)
            );
            assert!(snapshot.is_none());
          }
          WGPathLifecycleFact::Changed(id) => assert_eq!(id, Some("network")),
          _ => panic!("unexpected fact"),
        }
        observed.lock().unwrap().push("guard");
      }))
      .unwrap();
    let client = EdgeClient::new(EdgeClientConfig::default());
    let queued = order.clone();
    *client.wg_network_event_handler.lock().await = Some(Box::new(move |_| {
      queued.lock().unwrap().push("event");
    }));
    let bytes = event("session");
    connection
      .observe_control_frame(MessageType::WG_NETWORK_EVENT_PUSH, &bytes, Some("session"))
      .unwrap();
    assert!(
      <EdgeClient as ReadDispatch>::handle_push_notifications(
        MessageType::WG_NETWORK_EVENT_PUSH,
        &bytes,
        &client.log_handler,
        &client.tunnel_event_handler,
        &client.wg_network_event_handler
      )
      .await
    );
    assert_eq!(*order.lock().unwrap(), ["guard", "event"]);
    let (sender, receiver) = oneshot::channel();
    client.pending_requests.lock().await.insert(42, sender);
    let bytes = mutation("session", true);
    connection
      .observe_control_frame(MessageType::WG_UPDATE_MEMBER_ACK, &bytes, Some("session"))
      .unwrap();
    assert!(<EdgeClient as ReadDispatch>::dispatch_pending_response(
      MessageType::WG_UPDATE_MEMBER_ACK,
      bytes.clone(),
      &client.pending_requests,
      &client.pending_type_requests
    )
    .await
    .is_none());
    assert_eq!(receiver.await.unwrap(), bytes);
    assert_eq!(*order.lock().unwrap(), ["guard", "event", "guard"]);
    connection
      .observe_control_frame(
        MessageType::WG_UPDATE_MEMBER_ACK,
        &mutation("session", false),
        Some("session"),
      )
      .unwrap();
    assert_eq!(
      order.lock().unwrap().len(),
      3,
      "failed mutations are not revocations"
    );
  }

  #[test]
  fn replaced_or_corrupt_source_cannot_keep_a_guarded_consumer_active() {
    let connection = Arc::new(PathConnection::new(Some("edge".into())));
    let old = connection.subscribe("session".into()).unwrap();
    let old_token = old.session.clone();
    drop(old);
    let new = connection.subscribe("session".into()).unwrap();
    assert!(old_token
      .observe_lifecycle(Arc::new(|_| panic!("stale observer")))
      .is_err());
    new
      .session
      .observe_lifecycle(Arc::new(|_| panic!("foreign frame delivered")))
      .unwrap();
    assert!(new.session.observe_lifecycle(Arc::new(|_| {})).is_err());
    assert!(connection
      .observe_control_frame(
        MessageType::WG_NETWORK_EVENT_PUSH,
        &event("session"),
        Some("replaced-auth")
      )
      .is_err());
    assert!(!new.session.is_active());
    let fresh = connection.subscribe("session".into()).unwrap();
    fresh
      .session
      .observe_lifecycle(Arc::new(|_| panic!("invalid frame delivered")))
      .unwrap();
    assert!(connection
      .observe_control_frame(
        MessageType::WG_NETWORK_EVENT_PUSH,
        b"corrupt",
        Some("session")
      )
      .is_err());
    assert!(!fresh.session.is_active());
  }
}

pub type WGPathLifecycleObserver = Arc<dyn Fn(WGPathLifecycleFact<'_>) + Send + Sync>;

impl PathConnection {
  pub(in super::super) fn observe_control_frame(
    &self,
    kind: MessageType,
    data: &[u8],
    current_session: Option<&str>,
  ) -> Result<()> {
    if !matches!(
      kind,
      MessageType::WG_NETWORK_EVENT_PUSH
        | MessageType::WG_NETWORK_RUNTIME_RESPONSE
        | MessageType::WG_GET_NETWORK_ACK
        | MessageType::WG_JOIN_NETWORK_ACK
        | MessageType::WG_LEAVE_NETWORK_ACK
        | MessageType::WG_DELETE_NETWORK_ACK
        | MessageType::WG_UPDATE_NETWORK_CIDR_ACK
        | MessageType::WG_UPDATE_NETWORK_RELAY_MODE_ACK
        | MessageType::WG_UPDATE_MEMBER_ACK
    ) {
      return Ok(());
    }
    let mut registration = self.registration.lock().unwrap_or_else(|e| e.into_inner());
    let Some(r) = registration.as_ref().filter(|r| r.lifecycle.is_some()) else {
      return Ok(());
    };
    if !self.active.load(Ordering::Acquire) || !r.valid.load(Ordering::Acquire) {
      return Ok(());
    }
    let header = match MessageReader::get_session_id(data) {
      Ok(header) => header,
      Err(error) => {
        if let Some(stale) = registration.take() {
          stale.valid.store(false, Ordering::Release);
        }
        return Err(TransportError::Protocol(error.into()));
      }
    };
    if current_session != Some(r.session_id.as_str())
      || header.is_some_and(|s| !s.is_empty() && s != r.session_id)
    {
      if let Some(stale) = registration.take() {
        stale.valid.store(false, Ordering::Release);
      }
      return Err(TransportError::Protocol(
        "WG lifecycle source/session mismatch".into(),
      ));
    }
    let response = match MessageReader::parse_response(data) {
      Ok(response) => response,
      Err(error) => {
        if let Some(stale) = registration.take() {
          stale.valid.store(false, Ordering::Release);
        }
        return Err(TransportError::Protocol(error.into()));
      }
    };
    let observe = r.lifecycle.as_ref().unwrap();
    use WGPathLifecycleFact::*;
    match response {
      ParsedResponse::WGNetworkRuntimeResponse(r) if r.success => {
        if let Some(s) = r.snapshot.as_ref() {
          observe(Snapshot(s));
        } else {
          observe(Changed(None));
        }
      }
      ParsedResponse::WGGetNetworkResponse(r) if r.success => {
        if let Some(s) = r.snapshot.as_ref() {
          observe(Snapshot(s));
        } else {
          observe(Changed(None));
        }
      }
      ParsedResponse::WGNetworkEventPush(e) => observe(Event {
        network_id: &e.network_id,
        revision_epoch: &e.revision_epoch,
        revision: e.next_revision,
        action: e.action,
        snapshot: e.snapshot.as_ref(),
      }),
      ParsedResponse::WGJoinNetworkResponse(r) if r.success => observe(Changed(None)),
      ParsedResponse::WGLeaveNetworkResponse(r) if r.success => observe(Changed(None)),
      ParsedResponse::WGDeleteNetworkResponse(r) if r.success => {
        observe(Changed(Some(&r.network_id)))
      }
      ParsedResponse::WGUpdateNetworkCIDRResponse(r) if r.success => {
        observe(Changed(Some(&r.network_id)))
      }
      ParsedResponse::WGUpdateNetworkRelayModeResponse(r) if r.success => {
        observe(Changed(Some(&r.network_id)))
      }
      ParsedResponse::WGUpdateMemberResponse(r) if r.success => {
        observe(Changed(Some(&r.network_id)))
      }
      _ => {}
    }
    Ok(())
  }
}
