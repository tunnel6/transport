//! Opt-in WG coordination over the existing authenticated control connection.
//! No capability advertisement, runtime registration or route execution here.

use super::*;
use crate::protocol_types::{WGPathReportT, WGPathRequestT, WGPathRuntimeReportT};

mod lifecycle;
// tls_tests removed: WG_PATH_PLAN delivery mechanism deleted
pub use lifecycle::{WGPathLifecycleFact, WGPathLifecycleObserver};

const MAX_SEND_BUDGET: Duration = Duration::from_secs(5);

/// An opaque physical-connection and authentication binding. Retain it with
/// bootstrap/runtime work; a new connection must acquire a new subscription.
#[derive(Clone)]
pub struct WGPathSession {
  connection: Arc<PathConnection>,
  session_id: String,
  valid: Arc<AtomicBool>,
}

impl WGPathSession {
  /// Install once, before fetching bootstrap. Called synchronously at ingress
  /// on this physical connection, before response/event queues. The observer
  /// must perform bounded memory work only and must not reenter transport.
  pub fn observe_lifecycle(&self, observer: WGPathLifecycleObserver) -> Result<()> {
    let mut registration = self
      .connection
      .registration
      .lock()
      .unwrap_or_else(|e| e.into_inner());
    let r = registration.as_mut().ok_or(TransportError::NotConnected)?;
    if !self.is_active() || !Arc::ptr_eq(&r.valid, &self.valid) {
      return Err(TransportError::NotConnected);
    }
    if r.lifecycle.is_some() {
      return Err(TransportError::Protocol(
        "WG lifecycle observer already installed".into(),
      ));
    }
    r.lifecycle = Some(observer);
    Ok(())
  }

  pub fn session_id(&self) -> &str {
    &self.session_id
  }
  pub fn edge_id(&self) -> &str {
    self.connection.edge_id.as_deref().unwrap_or_default()
  }
  pub fn is_active(&self) -> bool {
    self.valid.load(Ordering::Acquire) && self.connection.active.load(Ordering::Acquire)
  }
}

pub struct WGPathSubscription {
  pub session: WGPathSession,
}

impl Drop for WGPathSubscription {
  fn drop(&mut self) {
    self.session.valid.store(false, Ordering::Release);
  }
}

struct Registration {
  session_id: String,
  valid: Arc<AtomicBool>,
  lifecycle: Option<WGPathLifecycleObserver>,
}

pub(super) struct PathConnection {
  edge_id: Option<String>,
  active: AtomicBool,
  closed: tokio::sync::watch::Sender<bool>,
  registration: std::sync::Mutex<Option<Registration>>,
}

impl PathConnection {
  pub(super) fn new(edge_id: Option<String>) -> Self {
    Self {
      edge_id,
      active: AtomicBool::new(true),
      closed: tokio::sync::watch::channel(false).0,
      registration: std::sync::Mutex::new(None),
    }
  }

  pub(super) fn cancel_subscription(&self) {
    if let Some(registration) = self
      .registration
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .take()
    {
      registration.valid.store(false, Ordering::Release);
    }
  }

  pub(super) fn close(&self) {
    self.active.store(false, Ordering::Release);
    self.closed.send_replace(true);
    self.cancel_subscription();
  }

  fn subscribe(self: &Arc<Self>, session_id: String) -> Result<WGPathSubscription> {
    let edge = self.edge_id.as_deref().unwrap_or_default();
    if edge.is_empty() || edge.len() > 256 || session_id.is_empty() || session_id.len() > 256 {
      return Err(TransportError::Protocol(
        "WG path requires an authenticated Edge/session binding".into(),
      ));
    }
    let mut registration = self.registration.lock().unwrap_or_else(|e| e.into_inner());
    if !self.active.load(Ordering::Acquire) {
      return Err(TransportError::NotConnected);
    }
    if registration
      .as_ref()
      .is_some_and(|r| r.valid.load(Ordering::Acquire))
    {
      return Err(TransportError::Protocol(
        "WG path already has a consumer".into(),
      ));
    }
    let valid = Arc::new(AtomicBool::new(true));
    let session = WGPathSession {
      connection: self.clone(),
      session_id: session_id.clone(),
      valid: valid.clone(),
    };
    *registration = Some(Registration {
      session_id,
      valid,
      lifecycle: None,
    });
    Ok(WGPathSubscription { session })
  }
}

/// Cancelling a partially written frame invalidates that physical transport.
/// The guard is armed only after acquiring the writer and validating its token.
struct FrameWriteGuard<'a, W> {
  writer: tokio::sync::MutexGuard<'a, Option<W>>,
  connection: &'a PathConnection,
  connected: &'a AtomicBool,
  shutdown: Option<mpsc::Sender<()>>,
  armed: bool,
}

impl<W> Drop for FrameWriteGuard<'_, W> {
  fn drop(&mut self) {
    if self.armed {
      self.writer.take();
      self.connection.close();
      self.connected.store(false, Ordering::Release);
      if let Some(shutdown) = &self.shutdown {
        let _ = shutdown.try_send(());
      }
    }
  }
}

impl EdgeClient {
  pub fn subscribe_connection_closed(&self)->Result<tokio::sync::watch::Receiver<bool>> {
    Ok(self.path_connection().ok_or(TransportError::NotConnected)?.closed.subscribe())
  }

  pub(super) fn path_connection(&self) -> Option<Arc<PathConnection>> {
    self
      .wg_path_connection
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .clone()
  }

  /// Local bounded subscription only; does not request/advertise coordination.
  pub async fn subscribe_wg_path_plans(&self) -> Result<WGPathSubscription> {
    let writer = self.writer.lock().await;
    if !self.is_connected() || writer.is_none() {
      return Err(TransportError::NotConnected);
    }
    // Hold authentication stable through registration. Cloning then releasing
    // this lock would let re-auth cancel the old subscription before we create
    // a new one with that same stale identity.
    let authenticated = self.session_id.read().await;
    let session_id = authenticated.clone().ok_or(TransportError::NotConnected)?;
    let result = self
      .path_connection()
      .ok_or(TransportError::NotConnected)?
      .subscribe(session_id);
    drop(authenticated);
    result
  }

  pub async fn send_wg_path_runtime(
    &self,
    session: &WGPathSession,
    report: &WGPathRuntimeReportT,
    deadline: tokio::time::Instant,
  ) -> Result<()> {
    let bytes = MessageBuilder::new()
      .seq(self.next_seq())
      .session_id(session.session_id())
      .wg_path_runtime(report)
      .map_err(|e| TransportError::Protocol(e.into()))?;
    self.send_path_frame(session, bytes, deadline).await
  }

  pub async fn send_wg_path_report(
    &self,
    session: &WGPathSession,
    report: &WGPathReportT,
    deadline: tokio::time::Instant,
  ) -> Result<()> {
    let bytes = MessageBuilder::new()
      .seq(self.next_seq())
      .session_id(session.session_id())
      .wg_path_report(report)
      .map_err(|e| TransportError::Protocol(e.into()))?;
    self.send_path_frame(session, bytes, deadline).await
  }

  pub async fn send_wg_path_request(
    &self,
    session: &WGPathSession,
    request: &WGPathRequestT,
    deadline: tokio::time::Instant,
  ) -> Result<crate::WGNetworkRuntimeSnapshotData> {
    let seq = self.next_seq();
    let bytes = MessageBuilder::new()
      .seq(seq)
      .session_id(session.session_id())
      .wg_path_request(request)
      .map_err(|e| TransportError::Protocol(e.into()))?;
    self
      .path_request_receipt(
        seq,
        request.network_id.as_deref().unwrap_or_default(),
        deadline,
        self.send_path_frame(session, bytes, deadline),
      )
      .await
  }

  async fn path_request_receipt(
    &self,
    seq: u32,
    network_id: &str,
    deadline: tokio::time::Instant,
    send: impl std::future::Future<Output = Result<()>>,
  ) -> Result<crate::WGNetworkRuntimeSnapshotData> {
    let mut registration = PendingRequestGuard {
      client: self,
      seq,
      expect_type: MessageType::WG_NETWORK_RUNTIME_RESPONSE,
      stage: "path_request",
      finished: false,
    };
    let (tx, rx) = oneshot::channel();
    // Sequence only: another GET's legacy seq=0 snapshot is not a receipt.
    self.pending_requests.lock().await.insert(seq, tx);
    let result = async {
      send.await?;
      let data = tokio::time::timeout_at(deadline, rx)
        .await
        .map_err(|_| {
          TransportError::Protocol(
            "WG proposal acceptance receipt timed out; refresh the coordinator connection".into(),
          )
        })?
        .map_err(|_| TransportError::NotConnected)?;
      if MessageReader::get_type(&data).ok() == Some(MessageType::ERROR) {
        let error =
          MessageReader::parse_error(&data).map_err(|e| TransportError::Protocol(e.into()))?;
        return Err(TransportError::Protocol(format!(
          "WG proposal rejected by Edge: {}",
          error.message
        )));
      }
      let response = MessageReader::parse_wg_network_runtime_response(&data)
        .map_err(|e| TransportError::Protocol(e.into()))?;
      if !response.success
        || response
          .snapshot
          .as_ref()
          .is_none_or(|s| s.network.network_id != network_id)
      {
        return Err(TransportError::Protocol(format!(
          "WG proposal receipt invalid: {}",
          response.error_message
        )));
      }
      Ok(response.snapshot.unwrap())
    }
    .await;
    registration.cleanup().await;
    result
  }

  async fn send_path_frame(
    &self,
    session: &WGPathSession,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
  ) -> Result<()> {
    let deadline = deadline.min(tokio::time::Instant::now() + MAX_SEND_BUDGET);
    tokio::time::timeout_at(deadline, async {
      let shutdown = self.shutdown_tx.lock().await.clone();
      let writer = self.writer.lock().await;
      // Keep the auth read lock through the write; re-auth cannot replace it
      // between the final session check and the frame's last byte.
      let current_session = self.session_id.read().await;
      let current_connection = self.path_connection().ok_or(TransportError::NotConnected)?;
      if !session.is_active()
        || !self.is_connected()
        || !Arc::ptr_eq(&current_connection, &session.connection)
        || current_session.as_deref() != Some(session.session_id())
        || writer.is_none()
      {
        return Err(TransportError::NotConnected);
      }
      if tokio::time::Instant::now() >= deadline {
        return Err(TransportError::Timeout);
      }
      let mut guard = FrameWriteGuard {
        writer,
        connection: &session.connection,
        connected: &self.connected,
        shutdown,
        armed: true,
      };
      write_frame(
        guard.writer.as_mut().ok_or(TransportError::NotConnected)?,
        &bytes,
      )
      .await?;
      guard.armed = false;
      Ok(())
    })
    .await
    .map_err(|_| TransportError::Timeout)?
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::client::edge_client::read_loop::ReadDispatch;

  fn request_receipt(seq: u32, network: &str, rejection: Option<&str>) -> Vec<u8> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let header = message::MessageHeaderT {
      type_: if rejection.is_some() {
        MessageType::ERROR
      } else {
        MessageType::WG_NETWORK_RUNTIME_RESPONSE
      },
      seq,
      ..Default::default()
    };
    let body = if let Some(reason) = rejection {
      message::MessageBodyT::Error(Box::new(message::ErrorT {
        code: message::ErrorCode::INTERNAL_ERROR,
        message: Some(reason.into()),
        ..Default::default()
      }))
    } else {
      message::MessageBodyT::WGNetworkRuntimeResponse(Box::new(
        message::WGNetworkRuntimeResponseT {
          success: true,
          snapshot: Some(Box::new(message::WGNetworkRuntimeSnapshotInfoT {
            network: Some(Box::new(message::WGNetworkDetailInfoT {
              network_id: Some(network.into()),
              ..Default::default()
            })),
            path_pairs: Some(vec![message::WGPathPairRuntimeInfoT {
              plan: Some(Box::new(message::WGPathPlanT {
                command_id: Some("winning-command".into()),
                ..Default::default()
              })),
              ..Default::default()
            }]),
            ..Default::default()
          })),
          ..Default::default()
        },
      ))
    };
    let msg = message::MessageT {
      header: Some(Box::new(header)),
      body,
    }
    .pack(&mut builder);
    builder.finish(msg, None);
    builder.finished_data().to_vec()
  }

  #[tokio::test]
  async fn path_proposal_waits_for_its_receipt_and_returns_rejection_to_the_caller() {
    let client = EdgeClient::new(EdgeClientConfig::default());
    for rejection in [
      None,
      Some("device=TV-001 lacks wg.path-coordination.v1"),
      Some("WG path negotiation capacity reached"),
    ] {
      let seq = client.next_seq();
      let data = request_receipt(seq, "net", rejection);
      let result = client
        .path_request_receipt(
          seq,
          "net",
          tokio::time::Instant::now() + Duration::from_secs(1),
          async {
            EdgeClient::dispatch_pending_response(
              MessageReader::get_type(&data).unwrap(),
              data,
              &client.pending_requests,
              &client.pending_type_requests,
            )
            .await;
            Ok(())
          },
        )
        .await;
      if let Some(reason) = rejection {
        assert!(result.unwrap_err().to_string().contains(reason));
      } else {
        let receipt = result.unwrap();
        assert_eq!(receipt.path_pairs[0].command_id, "winning-command");
      }
      assert!(client.pending_requests.lock().await.is_empty());
      assert!(client.pending_type_requests.lock().await.is_empty());
    }
    let result = client
      .path_request_receipt(
        99,
        "net",
        tokio::time::Instant::now() + Duration::from_millis(1),
        async { Ok(()) },
      )
      .await;
    assert!(result
      .unwrap_err()
      .to_string()
      .contains("acceptance receipt timed out"));
    assert!(client.pending_requests.lock().await.is_empty());
    assert!(client.pending_type_requests.lock().await.is_empty());
  }

  #[tokio::test]
  async fn cancelled_partial_frame_discards_writer_and_cancels_the_bound_consumer() {
    let connection = Arc::new(PathConnection::new(Some("edge-a".into())));
    let subscription = connection.subscribe("session-a".into()).unwrap();
    let (stream, mut reader) = tokio::io::duplex(8);
    let writer = Mutex::new(Some(stream));
    let connected = AtomicBool::new(true);
    let (shutdown, mut shutdown_rx) = mpsc::channel(1);
    let result = tokio::time::timeout(Duration::from_millis(25), async {
      let mut guard = FrameWriteGuard {
        writer: writer.lock().await,
        connection: &connection,
        connected: &connected,
        shutdown: Some(shutdown),
        armed: true,
      };
      write_frame(guard.writer.as_mut().unwrap(), &[9; 128])
        .await
        .unwrap();
      guard.armed = false;
    })
    .await;
    assert!(result.is_err());
    assert!(writer.lock().await.is_none());
    assert!(!connected.load(Ordering::Acquire));
    assert!(!subscription.session.is_active());
    assert_eq!(shutdown_rx.recv().await, Some(()));
    let mut header = [0; 4];
    reader.read_exact(&mut header).await.unwrap();
    assert_eq!(u32::from_be_bytes(header), 128);
  }

  #[tokio::test]
  async fn complete_frame_keeps_writer_and_deadline_waiting_for_writer_does_not_cancel_it() {
    let connection = Arc::new(PathConnection::new(Some("edge-a".into())));
    let subscription = connection.subscribe("session-a".into()).unwrap();
    let writer = Mutex::new(Some(Vec::new()));
    let connected = AtomicBool::new(true);
    {
      let mut guard = FrameWriteGuard {
        writer: writer.lock().await,
        connection: &connection,
        connected: &connected,
        shutdown: None,
        armed: true,
      };
      write_frame(guard.writer.as_mut().unwrap(), b"frame")
        .await
        .unwrap();
      guard.armed = false;
    }
    assert_eq!(
      writer.lock().await.as_deref(),
      Some(&b"\0\0\0\x05frame"[..])
    );
    assert!(subscription.session.is_active());
    assert!(connected.load(Ordering::Acquire));
    let client = EdgeClient::new(EdgeClientConfig::default());
    client.connected.store(true, Ordering::Release);
    *client.session_id.write().await = Some("session-a".into());
    *client.wg_path_connection.lock().unwrap() = Some(connection);
    let _held = client.writer.lock().await;
    assert!(matches!(
      client
        .send_path_frame(
          &subscription.session,
          vec![],
          tokio::time::Instant::now() + Duration::from_millis(25)
        )
        .await,
      Err(TransportError::Timeout)
    ));
    assert!(
      subscription.session.is_active(),
      "no write started, so timeout must not invalidate transport"
    );
    assert!(client.is_connected());
  }
}
