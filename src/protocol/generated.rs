// FlatBuffers artifacts are generated in the API repository and committed here.
// Sync with api/scripts/gen.sh sync-transport; cargo does not run flatc.

// 消息协议
#[path = "../../build/fb/rust/message_generated.rs"]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(clippy::all)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(mismatched_lifetime_syntaxes)]
pub mod message_generated;

// Tunnel 协议
#[path = "../../build/fb/rust/tunnel_generated.rs"]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(clippy::all)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(mismatched_lifetime_syntaxes)]
pub mod tunnel_generated;

// 重导出常用模块
pub use message_generated::message;
