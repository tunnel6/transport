# Transport Code Structure

> Other languages: [中文](./TRANSPORT_CODE_STRUCTURE.zh.md) | [日本語](./TRANSPORT_CODE_STRUCTURE.ja.md) | [Español](./TRANSPORT_CODE_STRUCTURE.es.md)

This document describes the current code structure of `tunnel/transport`, key call chains, and maintenance constraints, to support future refactoring and dead code cleanup.

## 1. Top-Level Layers

- `src/lib.rs`
  - NAPI export layer (`#[napi]`).
  - Responsible for data conversion, callback bridging, and lifecycle management between JS/Node and the Rust core.
- `src/client/`
  - Edge control-plane and data-plane client logic (mTLS, message send/receive, tunnel control, subscriptions, HTTP/TCP/UDP forwarding).
- `src/ice/`
  - P2P/ICE/QUIC negotiation and forwarding (probing, hole punching, QUIC connections, P2P forwarder).
- `src/protocol/`
  - Protocol encoding/decoding and message type definitions (`generated.rs` + `message.rs`).
- `src/error.rs`
  - Unified error type (`TransportError`) and conversions.
- `src/debug.rs`
  - Debugging helpers.

## 1.1 Code Tree (current)

```text
modules/tunnel/transport/
└── src/
    ├── lib.rs                         # NAPI export entry, Node <-> Rust bridge layer
    ├── debug.rs                       # Debugging helpers
    ├── error.rs                       # Unified error definitions and conversions
    ├── client/                        # Edge client main logic (control plane + data plane)
    │   ├── mod.rs                     # client module aggregation entry
    │   ├── cert.rs                    # CSR/key generation and certificate request structures
    │   ├── cert_verifier.rs           # Certificate verification
    │   ├── connection.rs              # TLS/mTLS connection establishment
    │   ├── connection.rs.bak          # Historical backup (not part of the formal call chain)
    │   ├── edge_client.rs             # EdgeClient main body and shared state
    │   ├── framing.rs                 # Protocol frame read/write
    │   ├── utils.rs                   # Utility functions (HTTP parsing, link type normalization, etc.)
    │   └── edge_client/               # EdgeClient submodules split by responsibility
    │       ├── data_packet.rs         # DATA frame handling and delivery
    │       ├── edge_ops.rs            # Edge control-plane operations (online/offline/status)
    │       ├── http.rs                # HTTP push + HTTP forwarding
    │       ├── ice.rs                 # ICE protocol frame handling
    │       ├── read_loop.rs           # Read loop and msg_type dispatching
    │       ├── subscriptions.rs       # Event subscriptions and callback registration
    │       ├── tcp_bridge.rs          # Local TCP bridging and connection lifecycle
    │       ├── tunnel_ops.rs          # Tunnel control-plane operations (sync/start/stop, etc.)
    │       └── udp_assoc.rs           # UDP association management and send/receive
    ├── ice/                           # P2P/ICE/QUIC negotiation and forwarding
    │   ├── mod.rs                     # ice module export entry
    │   ├── agent.rs                   # IceAgent state machine main flow
    │   ├── dataplane.rs               # QUIC data-plane session wrapper
    │   ├── forwarder.rs               # P2P forwarder (publisher/consumer)
    │   └── probe.rs                   # Probe packet construction and validation
    └── protocol/                      # Protocol encoding/decoding and message definitions
        ├── mod.rs                     # protocol module export entry
        ├── generated.rs               # FlatBuffers generated code
        └── message.rs                 # Business message build/parse wrappers
```

- `connection.rs.bak` is a historical backup file and is not part of the current formal module call chain.

## 2. client Directory Structure

### 2.1 Entry Points

- `src/client/mod.rs`
  - client submodule exports and aggregation entry.
- `src/client/edge_client.rs`
  - `EdgeClient` main body: connection management, request-response correlation, shared state storage, basic utility methods.

### 2.2 edge_client Submodules (split by responsibility)

- `src/client/edge_client/read_loop.rs`
  - Read loop entry, dispatching to each handler by `msg_type`.
  - Keeps message type determination and exception/fallback handling.
- `src/client/edge_client/http.rs`
  - HTTP Push request handling + HTTP forward proxying.
  - Centrally manages HTTP request parsing, forwarding, and response write-back.
- `src/client/edge_client/data_packet.rs`
  - DATA packet handling (unpacking and delivery of connection data frames).
- `src/client/edge_client/tcp_bridge.rs`
  - Local TCP <-> protocol frame bridging and connection lifecycle.
- `src/client/edge_client/udp_assoc.rs`
  - UDP association management, send/receive, and timeout reclamation.
- `src/client/edge_client/ice.rs`
  - ICE protocol frame handling (`ICE_START` / `ICE_PUNCH` / `ICE_QUIC_START` / `ICE_STATE_CHANGE`).
- `src/client/edge_client/edge_ops.rs`
  - Edge-level control-plane operations (online/offline/status).
- `src/client/edge_client/tunnel_ops.rs`
  - Tunnel-level control-plane operations (status/sync/upsert/delete/start/stop).
- `src/client/edge_client/subscriptions.rs`
  - Event subscriptions and callback registration (tunnel/channel/ice/log).

### 2.3 Other client Components

- `src/client/connection.rs`
  - TLS/mTLS connection establishment and certificate loading.
- `src/client/cert.rs`
  - CSR/key generation and certificate request data structures.
- `src/client/cert_verifier.rs`
  - Certificate verification logic.
- `src/client/framing.rs`
  - Frame read/write utilities.
- `src/client/utils.rs`
  - Helper functions (HTTP parsing, link type normalization and inference, etc.).

## 3. ICE Directory Structure

- `src/ice/agent.rs`
  - `IceAgent` state machine main flow (gather/probe/punch/quic/fallback/close).
- `src/ice/probe.rs`
  - Probe message construction, validation, and result parsing.
- `src/ice/dataplane.rs`
  - QUIC data-plane session wrapper (connection metadata and shutdown flow).
- `src/ice/forwarder.rs`
  - P2P forwarder (publisher/consumer roles) with stream/tcp bridging.

## 4. Node Export Chain (must be protected when cleaning dead code)

### 4.1 Main Chain

1. `src/lib.rs` exposes `#[napi]` interfaces (e.g. `edge_online`, `request_tunnel_sync`, `start_tunnel`, `subscribe_ice_events`).
2. NAPI methods call the same-named or closely-named methods on `client::EdgeClient`.
3. `EdgeClient` then performs the actual protocol handling via `read_loop` + per-submodule trait/impl.
4. Event callbacks return to the Node side via `ThreadsafeFunction`.

### 4.2 Cleanup Constraints

- As long as a function is on the `#[napi] -> EdgeClient -> submodule` call chain, it must not be deleted as dead code even if local Rust references are few.
- Some `allow(dead_code)` entries in `protocol/generated.rs` and `protocol/message.rs` come from the protocol compatibility surface and should not be removed casually.

## 5. Structured Cleanup Completed So Far

- Split `edge_client` logic by responsibility into the `src/client/edge_client/` directory.
- Merged read dispatch logic into `read_loop.rs` to avoid scattered maintenance.
- Merged HTTP handling logic into `http.rs`.
- Removed a batch of uncalled data-plane interfaces from ICE, keeping only the minimal capabilities actually required at runtime.
- Removed unread fields in `forwarder.rs` (`ChannelRoute.channel_id`).

## 6. Future Maintenance Recommendations

- Prefer placing new features in clearly-responsible submodules; avoid flowing code back into the large `edge_client.rs` file.
- First confirm whether the code is on the `#[napi]` export chain before deleting dead code.
- After each refactor, at minimum run:
  - `cd modules/tunnel/transport && cargo test`
  - Update call-chain documentation as needed to keep "structure diagram + code" in sync.

## 7. P2P Interfaces and State Machine Change Diagram (baseline to be implemented)

> Note: This section records the refactoring direction confirmed on 2026-05-14, aimed at fixing the issue "after ICE succeeds, business traffic does not switch to P2P".
> This is a design baseline and does not mean the code is fully implemented.

### 7.1 Key Principles

1. `ICE_QUIC_START.role` is only used for the QUIC connection-establishment role (server/client).
2. Business forwarding roles (publisher/consumer) are decided per channel, not inferred from `ICE_QUIC_START.role`.
3. P2P data-plane wiring is triggered at two moments (dual trigger, resolving timing races):
   - `IceEvent::QuicConnected`
   - After `start_tunnel` returns successfully

### 7.2 Interface Change Diagram (Rust / NAPI)

```text
Before (current, problematic path)
ICE_QUIC_START.role
    └── IceAgent::handle_ice_quic_start()
          └── ForwarderRole bound directly (server=>publisher, client=>consumer)
                └── Business traffic role overridden by session role
                      └── Common result: QUIC connected, but channel not properly registered/listening

After (target, decoupled path)
ICE_QUIC_START.role
    └── Decides only the QUIC handshake branch (accept/connect)

Channel metadata / start_tunnel runtime
    └── Decides the business direction of each channel (publisher/consumer)
          └── wire_p2p_forwarding() automatic wiring
                ├── publisher: register_channel(channel_id, local_addr)
                └── consumer : start_consumer_listener(bind=local_addr)
```

### 7.3 State Machine Change Diagram (Transport side)

```text
Before
[ICE Connected]
    └── forwarder created (session-level)
          └── Waiting for manual JS calls:
                - p2p_register_channel(...)
                - p2p_start_consumer_listener(...)
                      └── If not called or called at the wrong time => traffic still goes through relay / no traffic

After
[ICE Connected]
    └── Trigger automatic wiring (per channel list)
          ├── If channel=publisher: register route
          └── If channel=consumer : start local listener (prefer binding the original local_addr)

[start_tunnel success]
    └── Trigger automatic wiring once more (idempotent)
          └── Covers both orderings: "tunnel succeeds first, ICE later" or "ICE succeeds first, tunnel later"
```

### 7.4 Module Change Mapping (planned)

1. `src/lib.rs`
   - Add/extend the automatic wiring coordination entry (e.g. `wire_p2p_forwarding`).
   - Trigger wiring in the `QuicConnected` branch of `subscribe_ice_events`.
   - Trigger wiring after `start_tunnel` succeeds.
2. `src/client/edge_client.rs`
   - Expose the P2P channel binding snapshot (only `link_type=p2p`).
   - Allow updating a channel's `local_addr` after the consumer listener is established.
3. `src/ice/forwarder.rs`
   - Consumer listener supports a "specified bind address" mode (prefer binding the business-expected port).
   - Keep the existing random-port capability as a fallback.

### 7.5 Current Scope Boundaries

1. This round prioritizes fixing TCP/HTTP traffic switching over P2P channels.
2. UDP and HTTPS certificate policies are out of scope for this round (HTTPS to be designed separately).

## 8. P2P Integration Checklist (executable)

> Purpose: quickly verify that "after ICE succeeds, TCP/HTTP has automatically switched to P2P", and locate the break point on failure.

### 8.1 Prerequisites

1. Both sides have called `subscribe_ice_events`.
2. The tunnel channel's `link_type` is `p2p` (at least one TCP/HTTP channel).
3. Keep `transport` Rust logs visible (`stderr` / runtime logs).

### 8.2 Core Trigger Order

1. Trigger `start_tunnel` (or restore an existing tunnel).
2. Wait for ICE negotiation to reach `quic_connected`.
3. Observe whether two automatic wiring trigger logs appear:
   - `source=start_tunnel`
   - `source=ice_quic_connected`

### 8.3 Required Logs (success path)

1. Automatic wiring overview:
   - `p2p auto-wire from <source>: channels=<n> forwarder[publisher=..., consumer=...]`
2. Publisher route registration:
   - `p2p auto-wire register channel=...`
3. Consumer listener established:
   - `p2p consumer listener ready channel=... addr=...`
4. Data entering P2P forwarding:
   - `P2pForwarder] publisher stream route lookup channel=...`

### 8.4 Common Failure Branches and Causes

1. `skip p2p auto-wire ... no p2p channels`
   - Cause: the channel is not marked as `link_type=p2p`, or `local_addr` is empty.
2. `skip p2p auto-wire for udp channel=...`
   - Cause: the current policy explicitly skips UDP (out of scope for this round).
3. `p2p consumer listener failed channel=... bind=...`
   - Cause: local port occupied / no permission to bind; check `local_addr` availability.
4. `publisher stream error: no route for channel ...`
   - Cause: Publisher registration failed, or channel_id/canonical_id mismatch.

### 8.5 Acceptance Criteria (this round)

1. At least one TCP/HTTP channel shows a `register` or `listener ready` log after `quic_connected`.
2. When business traffic is triggered, `publisher stream route lookup` appears with no `no route for channel`.
3. Within the same session, either ordering of `start_tunnel` and `ice_quic_connected` eventually wires successfully.
