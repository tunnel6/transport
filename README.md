# Transport Module | Transport 模块

[English](#english) | [中文](#chinese)

---

<a name="english"></a>

## English

### Overview

The Transport module is a Rust-based client communication layer for yat-fe (Electron) to communicate with Edge servers. It provides certificate management, mTLS connection handling, and FlatBuffers-based protocol communication through NAPI-RS bindings.

### Features

- **Certificate Request**: First-time connection via OAuth Token to request client certificates from Edge
- **mTLS Connection**: Mutual TLS authentication with Edge servers
- **Message Framing**: Length-prefixed message format `[4-byte length (little-endian)][FlatBuffers message]`
- **Heartbeat**: Automatic heartbeat maintenance for connection keep-alive
- **Request-Response Matching**: Sequence-based request-response correlation
- **Edge Control**: Online/Offline control for Edge service management
- **Actor-aware Tunnel Metadata**: Parse/build `actor_role`, `actor_session_id`, `actor_device_id` for tunnel sync/upsert/event
- **Actor-aware Tunnel Start**: `startTunnel` supports passing actor context in request config

### Architecture

```
transport/src/
├── lib.rs              # NAPI interface exports
├── error.rs            # Error type definitions
├── protocol/
│   ├── mod.rs          # Protocol module entry
│   ├── generated.rs    # FlatBuffers generated code import
│   └── message.rs      # High-level message builder/reader API
└── client/
    ├── mod.rs          # Client module entry
    ├── connection.rs   # TCP/TLS connection management
    ├── framing.rs      # Message frame encoding/decoding
    ├── cert.rs         # Key pair and CSR generation
    └── edge_client.rs  # EdgeClient main class
```

### Installation

```bash
cd modules/tunnel/transport
yarn install
yarn build
```

### Usage

#### 1. Request Certificate (First Connection)

```typescript
import { requestCertificate } from 'tunnel'

const cert = await requestCertificate(
  'edge.example.com', // host
  8443, // port
  undefined, // serverName (defaults to {edgeId}.edge.myproxy.dev)
  caCertBuffer, // CA certificate (PEM)
  'invite:credential', // One prefixed enrollment token
  'device-456', // Device ID
  'edge-example', // Edge ID
)

// Store the certificate
console.log(cert.certificate) // Client certificate (PEM)
console.log(cert.privateKey) // Private key (PEM)
console.log(cert.caCertificate) // CA certificate chain (PEM)
console.log(cert.expiresAt) // Expiration timestamp (ms)
console.log(cert.serialNumber) // Certificate serial number
```

#### 2. Connect with mTLS

```typescript
import { JsEdgeClient } from 'tunnel'

const client = new JsEdgeClient({
  host: 'edge.example.com',
  port: 8443,
  caCert: caCertBuffer,
  clientCert: clientCertBuffer,
  clientKey: clientKeyBuffer,
  heartbeatIntervalSecs: 30, // optional
})

// Connect
await client.connect()

// Authenticate
const authResult = await client.authenticate({
  deviceId: 'device-456',
  clientVersion: '1.0.0',
  capabilities: ['tunnel', 'push'],
})

if (authResult.success) {
  console.log('Session ID:', authResult.sessionId)
}

// Edge online/offline control
await client.edgeOnline()
await client.edgeOffline()

// Disconnect
await client.disconnect()
```

#### 2.1 Start Tunnel with Actor Context

```typescript
const result = await client.startTunnel(
  'tunnel-1',
  [
    {
      key: 'tcp-main',
      protocol: 'tcp',
      localHost: '127.0.0.1',
      localPort: 5900,
      bufferSize: 16384,
      metadataJson: JSON.stringify({ eagerConnectRemote: true }),
    },
  ],
  undefined, // edgeId
  0, // mode: all-or-nothing
  3, // actorRole: controller
  'session-xyz', // actorSessionId
  'device-abc', // actorDeviceId
  false, // reconnect
)
```

#### 3. Low-level Protocol API (Optional)

```typescript
import { buildAuthRequest, buildHeartbeat, getMessageType, getMessageSeq } from 'tunnel'

// Build messages manually
const authMsg = buildAuthRequest(1, null, 'user-123', 'device-456', '1.0.0', [])
const heartbeatMsg = buildHeartbeat(2, 'session-id')

// Parse message metadata
const msgType = getMessageType(data)
const msgSeq = getMessageSeq(data)
```

### Certificate Flow

```
┌─────────┐                    ┌──────────┐                    ┌─────────┐
│  yat-fe │                    │   Edge   │                    │ Captain │
└────┬────┘                    └────┬─────┘                    └────┬────┘
     │                              │                               │
     │  1. One-way TLS + OAuth      │                               │
     │ ─────────────────────────────>                               │
     │                              │                               │
     │  2. Generate KeyPair + CSR   │                               │
     │                              │                               │
     │  3. CertRequest(CSR, Token)  │                               │
     │ ─────────────────────────────>                               │
     │                              │  4. Forward CSR               │
     │                              │ ──────────────────────────────>
     │                              │                               │
     │                              │  5. Signed Certificate        │
     │                              │ <──────────────────────────────
     │                              │                               │
     │  6. CertResponse(Cert)       │                               │
     │ <─────────────────────────────                               │
     │                              │                               │
     │  7. Store Cert locally       │                               │
     │                              │                               │
     │  8. mTLS Connection          │                               │
     │ ═════════════════════════════>                               │
     │                              │                               │
```

### Dependencies

- **napi-rs**: Node.js N-API bindings for Rust
- **flatbuffers**: Google FlatBuffers serialization
- **tokio**: Async runtime
- **tokio-rustls**: TLS support
- **rcgen**: Key pair and CSR generation

---

<a name="chinese"></a>

## 中文

### 概述

Transport 模块是一个基于 Rust 的客户端通信层，用于 yat-fe (Electron) 与 Edge 服务器通信。通过 NAPI-RS 绑定提供证书管理、mTLS 连接处理和基于 FlatBuffers 的协议通信。

### 功能特性

- **证书申请**: 首次连接通过 OAuth Token 向 Edge 申请客户端证书
- **mTLS 连接**: 与 Edge 服务器的双向 TLS 认证
- **消息帧**: 长度前缀消息格式 `[4字节长度(小端)][FlatBuffers消息体]`
- **心跳维护**: 自动心跳保持连接活跃
- **请求-响应匹配**: 基于序列号的请求响应关联
- **Edge 控制**: Edge 服务上下线管理
- **Actor 感知的 Tunnel 元数据**: 支持解析/构建 `actor_role`、`actor_session_id`、`actor_device_id`
- **Actor 感知的 Tunnel 启动**: `startTunnel` 支持传入 actor 上下文

### 架构

```
transport/src/
├── lib.rs              # NAPI 接口导出
├── error.rs            # 错误类型定义
├── protocol/
│   ├── mod.rs          # 协议模块入口
│   ├── generated.rs    # FlatBuffers 生成代码引入
│   └── message.rs      # 高级消息构建/解析 API
└── client/
    ├── mod.rs          # 客户端模块入口
    ├── connection.rs   # TCP/TLS 连接管理
    ├── framing.rs      # 消息帧编解码
    ├── cert.rs         # 密钥对和 CSR 生成
    └── edge_client.rs  # EdgeClient 主类
```

### 安装

```bash
cd modules/tunnel/transport
yarn install
yarn build
```

### 使用方法

#### 1. 申请证书（首次连接）

```typescript
import { requestCertificate } from 'tunnel'

const cert = await requestCertificate(
  'edge.example.com', // 主机
  8443, // 端口
  undefined, // serverName (defaults to {edgeId}.edge.myproxy.dev)
  caCertBuffer, // CA 证书 (PEM)
  'invite:credential', // 单一带前缀的签发凭据
  'device-456', // 设备 ID
  'edge-example', // Edge ID
)

// 存储证书
console.log(cert.certificate) // 客户端证书 (PEM)
console.log(cert.privateKey) // 私钥 (PEM)
console.log(cert.caCertificate) // CA 证书链 (PEM)
console.log(cert.expiresAt) // 过期时间戳（毫秒）
console.log(cert.serialNumber) // 证书序列号
```

#### 2. 使用 mTLS 连接

````typescript
import { JsEdgeClient } from 'tunnel'

const client = new JsEdgeClient({
  host: 'edge.example.com',
  port: 8443,
  caCert: caCertBuffer,
  clientCert: clientCertBuffer,
  clientKey: clientKeyBuffer,
  heartbeatIntervalSecs: 30, // 可选
})

// 连接
await client.connect()

// 认证
const authResult = await client.authenticate({
  deviceId: 'device-456',
  clientVersion: '1.0.0',
  capabilities: ['tunnel', 'push'],
})

if (authResult.success) {
  console.log('会话 ID:', authResult.sessionId)
}

#### 2.1 传入 Actor 上下文启动 Tunnel

```typescript
const result = await client.startTunnel(
  'tunnel-1',
  [
    {
      key: 'tcp-main',
      protocol: 'tcp',
      localHost: '127.0.0.1',
      localPort: 5900,
      bufferSize: 16384,
      metadataJson: JSON.stringify({ eagerConnectRemote: true }),
    },
  ],
  undefined, // edgeId
  0, // mode: all-or-nothing
  3, // actorRole: controller
  'session-xyz', // actorSessionId
  'device-abc', // actorDeviceId
  false, // reconnect
)
````

// Edge 上下线控制
await client.edgeOnline()
await client.edgeOffline()

// 断开连接
await client.disconnect()

````

#### 3. 底层协议 API（可选）

```typescript
import { buildAuthRequest, buildHeartbeat, getMessageType, getMessageSeq } from 'tunnel'

// 手动构建消息
const authMsg = buildAuthRequest(1, null, 'user-123', 'device-456', '1.0.0', [])
const heartbeatMsg = buildHeartbeat(2, 'session-id')

// 解析消息元数据
const msgType = getMessageType(data)
const msgSeq = getMessageSeq(data)
````

### 证书签发流程

```
┌─────────┐                    ┌──────────┐                    ┌─────────┐
│  yat-fe │                    │   Edge   │                    │ Captain │
└────┬────┘                    └────┬─────┘                    └────┬────┘
     │                              │                               │
     │  1. 单向 TLS + OAuth         │                               │
     │ ─────────────────────────────>                               │
     │                              │                               │
     │  2. 生成密钥对 + CSR         │                               │
     │                              │                               │
     │  3. CertRequest(CSR, Token)  │                               │
     │ ─────────────────────────────>                               │
     │                              │  4. 转发 CSR                  │
     │                              │ ──────────────────────────────>
     │                              │                               │
     │                              │  5. 签发证书                  │
     │                              │ <──────────────────────────────
     │                              │                               │
     │  6. CertResponse(证书)       │                               │
     │ <─────────────────────────────                               │
     │                              │                               │
     │  7. 本地存储证书             │                               │
     │                              │                               │
     │  8. mTLS 连接                │                               │
     │ ═════════════════════════════>                               │
     │                              │                               │
```

### 依赖

- **napi-rs**: Rust 的 Node.js N-API 绑定
- **flatbuffers**: Google FlatBuffers 序列化
- **tokio**: 异步运行时
- **tokio-rustls**: TLS 支持
- **rcgen**: 密钥对和 CSR 生成

### 协议格式

消息帧格式：

```
+----------------+------------------------+
| 4 bytes        | N bytes                |
| Length (LE)    | FlatBuffers Message    |
+----------------+------------------------+
```

CSR CN 格式：`device_{deviceId}`。签发后的身份和权限由 Edge/Captain 根据凭据决定。

### Protocol and compatibility policy sources / 协议与兼容策略来源

The API repository owns `schema/message.fbs` (message IDs, wire fields and current
protocol major/minor) and `compatibility.json` (minimum Edge product version).
`build/fb/rust/` and `build/compatibility.json` are committed API artifacts, not
independently maintained definitions. Cargo embeds these artifacts so this crate
and CLI consumers can build without an API checkout. Never edit the copies by hand.

唯一维护源位于 API 仓库；transport 只执行校验。FE 显示 Agent Auth 诊断中的版本下限，
不另外维护配置。更新 API 后，在 workspace 根目录执行：

```bash
bash api/scripts/gen.sh flatbuffer
bash api/scripts/gen.sh sync-transport
bash api/scripts/gen.sh check-transport
```

For a separate checkout, pass `--transport-root /path/to/transport` to the sync or
check command. The check fails when any synchronized artifact differs.
