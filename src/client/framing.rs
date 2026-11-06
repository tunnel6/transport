//! 消息帧编解码
//!
//! 协议格式: [4字节长度(大端/网络字节序)][FlatBuffers消息体]

use crate::error::{Result, TransportError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 最大消息长度 (16MB)
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// 发送一帧消息
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
  let len = data.len() as u32;

  if len > MAX_MESSAGE_SIZE {
    return Err(TransportError::Protocol(format!(
      "Message too large: {} bytes (max: {})",
      len, MAX_MESSAGE_SIZE
    )));
  }

  // 写入长度（大端/网络字节序）
  writer.write_all(&len.to_be_bytes()).await?;

  // 写入数据
  writer.write_all(data).await?;

  // 刷新缓冲区
  writer.flush().await?;

  Ok(())
}

/// 读取一帧消息
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
  // 读取长度（4字节大端/网络字节序）
  let mut len_buf = [0u8; 4];
  reader.read_exact(&mut len_buf).await?;
  let len = u32::from_be_bytes(len_buf);

  // 检查长度
  if len > MAX_MESSAGE_SIZE {
    return Err(TransportError::Protocol(format!(
      "Message too large: {} bytes (max: {})",
      len, MAX_MESSAGE_SIZE
    )));
  }

  if len == 0 {
    return Ok(Vec::new());
  }

  // 读取消息体
  let mut data = vec![0u8; len as usize];
  reader.read_exact(&mut data).await?;

  Ok(data)
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::BufReader;

  #[tokio::test]
  async fn test_frame_roundtrip() {
    let data = b"Hello, World!";
    let mut buffer = Vec::new();

    // 写入
    write_frame(&mut buffer, data).await.unwrap();

    // 验证格式
    assert_eq!(&buffer[0..4], &(data.len() as u32).to_be_bytes());
    assert_eq!(&buffer[4..], data);

    // 读取
    let mut reader = BufReader::new(&buffer[..]);
    let result = read_frame(&mut reader).await.unwrap();
    assert_eq!(result, data);
  }
}
