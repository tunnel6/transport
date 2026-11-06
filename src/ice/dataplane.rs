use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct QuicDataPlane {
  connection: quinn::Connection,
  streams: Arc<Mutex<HashMap<String, ChannelStream>>>,
}

struct ChannelStream {
  send: quinn::SendStream,
  _channel_id: String,
}

impl QuicDataPlane {
  pub fn new(connection: quinn::Connection) -> Self {
    Self {
      connection,
      streams: Arc::new(Mutex::new(HashMap::new())),
    }
  }

  pub async fn close(&self) {
    let mut streams = self.streams.lock().await;
    for (_, mut stream) in streams.drain() {
      let _ = stream.send.finish();
    }
    self.connection.close(0u32.into(), b"closed");
  }

  pub fn connection_id(&self) -> String {
    format!("{:x}", self.connection.stable_id())
  }

  pub fn remote_address(&self) -> String {
    self.connection.remote_address().to_string()
  }

  pub fn rtt_ms(&self) -> u32 {
    self.connection.rtt().as_millis() as u32
  }
}
