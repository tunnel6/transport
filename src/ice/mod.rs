mod agent;
mod dataplane;
mod forwarder;
mod probe;

// Always export — yat-network (non-NAPI) needs IceAgent for P2P hole-punching.
pub use agent::{IceAgent, IceAgentConfig, IceEvent, IceState, IceStateSnapshot};
pub use forwarder::P2pForwarder;
