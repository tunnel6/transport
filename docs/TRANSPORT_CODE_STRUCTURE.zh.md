# Transport Code Structure

> Other languages: [English](./TRANSPORT_CODE_STRUCTURE.md) | [日本語](./TRANSPORT_CODE_STRUCTURE.ja.md) | [Español](./TRANSPORT_CODE_STRUCTURE.es.md)

本文档用于描述 `tunnel/transport` 当前代码结构、关键调用链与维护约束，方便后续继续重构与死代码清理。

## 1. 顶层分层

- `src/lib.rs`
  - NAPI 导出层（`#[napi]`）。
  - 负责 JS/Node 与 Rust 内核之间的数据转换、回调桥接与生命周期管理。
- `src/client/`
  - Edge 控制面与数据面客户端逻辑（mTLS、消息收发、隧道控制、订阅、HTTP/TCP/UDP 转发）。
- `src/ice/`
  - P2P/ICE/QUIC 协商与转发（探测、打洞、QUIC 连接、P2P forwarder）。
- `src/protocol/`
  - 协议编解码与消息类型定义（`generated.rs` + `message.rs`）。
- `src/error.rs`
  - 统一错误类型（`TransportError`）及转换。
- `src/debug.rs`
  - 调试辅助。

## 1.1 Code Tree（当前）

```text
modules/tunnel/transport/
└── src/
    ├── lib.rs                         # NAPI 导出入口，Node <-> Rust 桥接层
    ├── debug.rs                       # 调试辅助
    ├── error.rs                       # 统一错误定义与转换
    ├── client/                        # Edge 客户端主逻辑（控制面 + 数据面）
    │   ├── mod.rs                     # client 模块聚合入口
    │   ├── cert.rs                    # CSR/密钥生成与证书请求结构
    │   ├── cert_verifier.rs           # 证书校验
    │   ├── connection.rs              # TLS/mTLS 建连
    │   ├── connection.rs.bak          # 历史备份（非正式调用链）
    │   ├── edge_client.rs             # EdgeClient 主体与共享状态
    │   ├── framing.rs                 # 协议帧读写
    │   ├── utils.rs                   # 工具函数（HTTP 解析、link type 归一化等）
    │   └── edge_client/               # EdgeClient 按职责拆分的子模块
    │       ├── data_packet.rs         # DATA 帧处理与投递
    │       ├── edge_ops.rs            # Edge 控制面操作（online/offline/status）
    │       ├── http.rs                # HTTP push + HTTP 转发
    │       ├── ice.rs                 # ICE 协议帧处理
    │       ├── read_loop.rs           # 读循环与 msg_type 分发
    │       ├── subscriptions.rs       # 事件订阅与回调注册
    │       ├── tcp_bridge.rs          # 本地 TCP 桥接与连接生命周期
    │       ├── tunnel_ops.rs          # Tunnel 控制面操作（sync/start/stop 等）
    │       └── udp_assoc.rs           # UDP association 管理与收发
    ├── ice/                           # P2P/ICE/QUIC 协商与转发
    │   ├── mod.rs                     # ice 模块导出入口
    │   ├── agent.rs                   # IceAgent 状态机主流程
    │   ├── dataplane.rs               # QUIC 数据面会话包装
    │   ├── forwarder.rs               # P2P forwarder（publisher/consumer）
    │   └── probe.rs                   # 探测包构建与校验
    └── protocol/                      # 协议编解码与消息定义
        ├── mod.rs                     # protocol 模块导出入口
        ├── generated.rs               # FlatBuffers 生成代码
        └── message.rs                 # 业务消息构建/解析封装
```

- `connection.rs.bak` 为历史备份文件，不属于当前正式模块调用链。

## 2. client 目录结构

### 2.1 入口

- `src/client/mod.rs`
  - client 子模块导出与聚合入口。
- `src/client/edge_client.rs`
  - `EdgeClient` 主体：连接管理、请求响应关联、共享状态存储、基础工具方法。

### 2.2 edge_client 子模块（按职责拆分）

- `src/client/edge_client/read_loop.rs`
  - 读循环入口，按 `msg_type` 分发到各处理逻辑。
  - 保留消息类型判定与异常/兜底处理。
- `src/client/edge_client/http.rs`
  - HTTP Push 请求处理 + HTTP 正向转发。
  - 统一管理 HTTP 请求解析、转发和响应回写。
- `src/client/edge_client/data_packet.rs`
  - DATA packet 处理（连接数据帧解包与投递）。
- `src/client/edge_client/tcp_bridge.rs`
  - 本地 TCP <-> 协议帧桥接与连接生命周期。
- `src/client/edge_client/udp_assoc.rs`
  - UDP association 管理、收发与超时回收。
- `src/client/edge_client/ice.rs`
  - ICE 协议帧处理（`ICE_START` / `ICE_PUNCH` / `ICE_QUIC_START` / `ICE_STATE_CHANGE`）。
- `src/client/edge_client/edge_ops.rs`
  - Edge 级控制面操作（online/offline/status）。
- `src/client/edge_client/tunnel_ops.rs`
  - Tunnel 级控制面操作（status/sync/upsert/delete/start/stop）。
- `src/client/edge_client/subscriptions.rs`
  - 事件订阅与回调注册（tunnel/channel/ice/log）。

### 2.3 其他 client 组件

- `src/client/connection.rs`
  - TLS/mTLS 连接建立与证书加载。
- `src/client/cert.rs`
  - CSR/密钥生成与证书请求数据结构。
- `src/client/cert_verifier.rs`
  - 证书校验逻辑。
- `src/client/framing.rs`
  - 帧读写工具。
- `src/client/utils.rs`
  - 辅助函数（HTTP 解析、link type 归一化与推断等）。

## 3. ICE 目录结构

- `src/ice/agent.rs`
  - `IceAgent` 状态机主流程（gather/probe/punch/quic/fallback/close）。
- `src/ice/probe.rs`
  - 探测报文构建、校验与结果解析。
- `src/ice/dataplane.rs`
  - QUIC 数据面会话包装（连接元信息与关闭流程）。
- `src/ice/forwarder.rs`
  - P2P 转发器（publisher/consumer 两角色）与 stream/tcp 桥接。

## 4. Node 导出链路（清理死代码时必须保护）

### 4.1 主链路

1. `src/lib.rs` 暴露 `#[napi]` 接口（例如 `edge_online`、`request_tunnel_sync`、`start_tunnel`、`subscribe_ice_events`）。
2. NAPI 方法调用 `client::EdgeClient` 的同名/近似方法。
3. `EdgeClient` 再通过 `read_loop` + 各子模块 trait/impl 执行实际协议处理。
4. 事件回调通过 `ThreadsafeFunction` 回到 Node 侧。

### 4.2 清理约束

- 只要函数处于 `#[napi] -> EdgeClient -> 子模块` 调用链上，即使 Rust 本地引用较少，也不能当成死代码删除。
- `protocol/generated.rs` 与 `protocol/message.rs` 中部分 `allow(dead_code)` 来自协议兼容面，不应随意删除。

## 5. 当前已完成的结构化清理

- 将 `edge_client` 逻辑按职责拆分到 `src/client/edge_client/` 目录。
- 合并 read 分发逻辑到 `read_loop.rs`，避免分散维护。
- 合并 HTTP 处理相关逻辑到 `http.rs`。
- ICE 中移除一批未被调用的数据面接口，保留实际运行所需最小能力。
- 移除 `forwarder.rs` 中未读取字段（`ChannelRoute.channel_id`）。

## 6. 后续维护建议

- 新增功能优先放在职责明确的子模块，避免回流到 `edge_client.rs` 大文件。
- 先确认是否经过 `#[napi]` 导出链，再做 dead code 删除。
- 每次重构后至少执行：
  - `cd modules/tunnel/transport && cargo test`
  - 必要时补充调用链文档，保持“结构图 + 代码”同步。

## 7. P2P 接口与状态机变化图（待实现基线）

> 说明：本节记录 2026-05-14 已确认的重构方向，用于修复“ICE 成功后业务流量未切换到 P2P”的问题。  
> 当前为设计基线，不代表代码已全部实现。

### 7.1 关键原则

1. `ICE_QUIC_START.role` 仅用于 QUIC 建链角色（server/client）。
2. 业务转发角色（publisher/consumer）按 channel 维度决定，不由 `ICE_QUIC_START.role` 推断。
3. P2P 数据面接线在两个时机触发（双触发，解决时序竞争）：
   - `IceEvent::QuicConnected`
   - `start_tunnel` 成功返回后

### 7.2 接口变化图（Rust / NAPI）

```text
Before (现状，问题路径)
ICE_QUIC_START.role
    └── IceAgent::handle_ice_quic_start()
          └── ForwarderRole 直接绑定 (server=>publisher, client=>consumer)
                └── 业务流量角色被会话角色覆盖
                      └── 常见结果：QUIC 已连通，但 channel 未正确注册/监听

After (目标，解耦路径)
ICE_QUIC_START.role
    └── 仅决定 QUIC handshake 分支 (accept/connect)

Channel metadata / start_tunnel runtime
    └── 决定每个 channel 的业务方向（publisher/consumer）
          └── wire_p2p_forwarding() 自动接线
                ├── publisher: register_channel(channel_id, local_addr)
                └── consumer : start_consumer_listener(bind=local_addr)
```

### 7.3 状态机变化图（Transport 侧）

```text
Before
[ICE Connected]
    └── forwarder 已创建（会话级）
          └── 等待 JS 手动调用:
                - p2p_register_channel(...)
                - p2p_start_consumer_listener(...)
                      └── 若未调用或时序不对 => 数据仍走 relay / 无流量

After
[ICE Connected]
    └── 触发自动接线（按 channel 列表）
          ├── 若 channel=publisher: 注册路由
          └── 若 channel=consumer : 起本地 listener（优先绑定原 local_addr）

[start_tunnel success]
    └── 再触发一次自动接线（幂等）
          └── 兜底覆盖“tunnel 先成功、ICE 后成功”或“ICE 先成功、tunnel 后成功”两类顺序
```

### 7.4 模块改动映射（计划）

1. `src/lib.rs`
   - 新增/扩展自动接线协调入口（例如 `wire_p2p_forwarding`）。
   - 在 `subscribe_ice_events` 的 `QuicConnected` 分支触发接线。
   - 在 `start_tunnel` 成功后触发接线。
2. `src/client/edge_client.rs`
   - 暴露 P2P channel 绑定快照（仅 `link_type=p2p`）。
   - 允许在 consumer listener 建立后更新 channel `local_addr`。
3. `src/ice/forwarder.rs`
   - consumer listener 支持“指定 bind 地址”模式（优先绑定业务期望端口）。
   - 保留现有随机端口能力作为 fallback。

### 7.5 当前范围边界

1. 本轮优先修复 TCP/HTTP 在 P2P 通道上的切流问题。
2. UDP 与 HTTPS 证书策略暂不在本轮实现范围内（HTTPS 另行设计）。

## 8. P2P 联调检查清单（执行版）

> 目的：快速验证“ICE 成功后 TCP/HTTP 已自动切流到 P2P”，并在失败时定位断点。

### 8.1 前置条件

1. 双端均已 `subscribe_ice_events`。
2. tunnel channel 的 `link_type` 为 `p2p`（至少一个 TCP/HTTP channel）。
3. 保持 `transport` Rust 日志可见（`stderr` / 运行日志）。

### 8.2 核心触发顺序

1. 触发 `start_tunnel`（或恢复已有 tunnel）。
2. 等待 ICE 协商到 `quic_connected`。
3. 观察是否出现两次自动接线触发日志：
   - `source=start_tunnel`
   - `source=ice_quic_connected`

### 8.3 必看日志（成功路径）

1. 自动接线总览：
   - `p2p auto-wire from <source>: channels=<n> forwarder[publisher=..., consumer=...]`
2. Publisher 路由注册：
   - `p2p auto-wire register channel=...`
3. Consumer 监听建立：
   - `p2p consumer listener ready channel=... addr=...`
4. 数据进入 P2P 转发：
   - `P2pForwarder] publisher stream route lookup channel=...`

### 8.4 常见失败分支与判因

1. `skip p2p auto-wire ... no p2p channels`
   - 原因：channel 未被标记为 `link_type=p2p` 或 `local_addr` 为空。
2. `skip p2p auto-wire for udp channel=...`
   - 原因：当前策略明确跳过 UDP（本轮范围外）。
3. `p2p consumer listener failed channel=... bind=...`
   - 原因：本地端口占用/无权限绑定；需检查 `local_addr` 可用性。
4. `publisher stream error: no route for channel ...`
   - 原因：Publisher 未注册成功，或 channel_id/canonical_id 不一致。

### 8.5 验收标准（本轮）

1. 至少一个 TCP/HTTP channel 在 `quic_connected` 后出现 `register` 或 `listener ready` 日志。
2. 业务流量触发时出现 `publisher stream route lookup` 且无 `no route for channel`。
3. 同一会话中 `start_tunnel` 与 `ice_quic_connected` 任一先后顺序都能最终接线成功。
