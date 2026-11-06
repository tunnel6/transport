// Protocol 模块
// 封装 FlatBuffers 协议的高级 API

pub mod generated;
pub mod message;
pub mod compatibility;

// 重导出常用类型
pub use generated::message::MessageType;

// 重导出高级 API
pub use message::{EdgeStatusPushData, MessageBuilder, MessageReader, ParsedResponse};
