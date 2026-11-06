//! Client 模块
//!
//! 负责与 Edge 服务器的通信

pub mod cert;
pub mod enrollment;
pub use enrollment::EnrollmentToken;
pub(crate) mod cert_verifier;
pub mod connection;
pub mod edge_client;
pub mod framing;
pub mod pairing;
pub use pairing::discover_pairing_certificates;
pub(crate) mod utils;

pub use cert::{generate_csr, generate_key_pair, CertRequestResult};
pub use connection::{connect_healthcheck, connect_mtls, TlsConnection};
pub use edge_client::{
  AuthResult, EdgeClient, EdgeClientConfig, IceMessage, P2pChannelBinding, WGP2PEvent, ChannelConnectionEventData,
};
pub use edge_client::{
  WGPathLifecycleFact, WGPathLifecycleObserver, WGPathSession, WGPathSubscription,
};

// Re-export WG protocol types used in EdgeClient public method signatures
pub use crate::protocol::message::{
  WGGetNetworkResponseData, WGJoinNetworkResponseData, WGLeaveNetworkResponseData,
};
