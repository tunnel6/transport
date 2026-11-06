# Transport コード構造

> この文書は [TRANSPORT_CODE_STRUCTURE.zh.md](./TRANSPORT_CODE_STRUCTURE.zh.md) の日本語訳です。現在、英語版 (TRANSPORT_CODE_STRUCTURE.md) がデフォルト言語です。

本ドキュメントは `tunnel/transport` の現在のコード構造、主要な呼び出しチェーン、およびメンテナンス上の制約を説明し、今後のリファクタリングとデッドコード整理に資することを目的としています。

## 1. トップレベルの階層構成

- `src/lib.rs`
  - NAPI エクスポート層（`#[napi]`）。
  - JS/Node と Rust カーネル間のデータ変換、コールバックブリッジ、ライフサイクル管理を担当。
- `src/client/`
  - Edge コントロールプレーンおよびデータプレーンのクライアントロジック（mTLS、メッセージ送受信、トンネル制御、サブスクリプション、HTTP/TCP/UDP 転送）。
- `src/ice/`
  - P2P/ICE/QUIC のネゴシエーションと転送（プローブ、ホールパンチング、QUIC 接続、P2P フォワーダー）。
- `src/protocol/`
  - プロトコルのエンコード/デコードとメッセージ型定義（`generated.rs` + `message.rs`）。
- `src/error.rs`
  - 統一エラー型（`TransportError`）とその変換。
- `src/debug.rs`
  - デバッグ支援機能。

## 1.1 コードツリー（現在）

```text
modules/tunnel/transport/
└── src/
    ├── lib.rs                         # NAPI エクスポート入口、Node <-> Rust ブリッジ層
    ├── debug.rs                       # デバッグ支援機能
    ├── error.rs                       # 統一エラー定義と変換
    ├── client/                        # Edge クライアント本体ロジック（コントロールプレーン + データプレーン）
    │   ├── mod.rs                     # client モジュールの集約入口
    │   ├── cert.rs                    # CSR/鍵生成と証明書リクエスト構造体
    │   ├── cert_verifier.rs           # 証明書検証
    │   ├── connection.rs              # TLS/mTLS 接続確立
    │   ├── connection.rs.bak          # 過去のバックアップ（正式な呼び出しチェーン外）
    │   ├── edge_client.rs             # EdgeClient 本体と共有状態
    │   ├── framing.rs                 # プロトコルフレームの読み書き
    │   ├── utils.rs                   # ユーティリティ関数（HTTP パース、link type の正規化など）
    │   └── edge_client/               # EdgeClient を責務別に分割したサブモジュール
    │       ├── data_packet.rs         # DATA フレームの処理と配信
    │       ├── edge_ops.rs            # Edge コントロールプレーン操作（online/offline/status）
    │       ├── http.rs                # HTTP push + HTTP 転送
    │       ├── ice.rs                 # ICE プロトコルフレームの処理
    │       ├── read_loop.rs           # 読み取りループと msg_type ディスパッチ
    │       ├── subscriptions.rs       # イベント購読とコールバック登録
    │       ├── tcp_bridge.rs          # ローカル TCP ブリッジと接続ライフサイクル
    │       ├── tunnel_ops.rs          # トンネルコントロールプレーン操作（sync/start/stop など）
    │       └── udp_assoc.rs           # UDP association の管理と送受信
    ├── ice/                           # P2P/ICE/QUIC のネゴシエーションと転送
    │   ├── mod.rs                     # ice モジュールのエクスポート入口
    │   ├── agent.rs                   # IceAgent ステートマシン本体フロー
    │   ├── dataplane.rs               # QUIC データプレーンセッションのラッパー
    │   ├── forwarder.rs               # P2P フォワーダー（publisher/consumer）
    │   └── probe.rs                   # プローブパッケージの構築と検証
    └── protocol/                      # プロトコルのエンコード/デコードとメッセージ定義
        ├── mod.rs                     # protocol モジュールのエクスポート入口
        ├── generated.rs               # FlatBuffers 生成コード
        └── message.rs                 # ビジネスメッセージの構築/解析ラッパー
```

- `connection.rs.bak` は過去のバックアップファイルであり、現在の正式なモジュール呼び出しチェーンには含まれません。

## 2. client ディレクトリ構造

### 2.1 エントリポイント

- `src/client/mod.rs`
  - client サブモジュールのエクスポートと集約入口。
- `src/client/edge_client.rs`
  - `EdgeClient` 本体：接続管理、リクエスト・レスポンスの相関付け、共有状態ストア、基本ユーティリティメソッド。

### 2.2 edge_client サブモジュール（責務別分割）

- `src/client/edge_client/read_loop.rs`
  - 読み取りループの入口。`msg_type` に応じて各処理ロジックへディスパッチ。
  - メッセージ型の判定と例外/フォールバック処理を維持。
- `src/client/edge_client/http.rs`
  - HTTP Push リクエスト処理 + HTTP 正向転送。
  - HTTP リクエストのパース、転送、レスポンス書き戻しを一元管理。
- `src/client/edge_client/data_packet.rs`
  - DATA パケット処理（接続データフレームのデコードと配信）。
- `src/client/edge_client/tcp_bridge.rs`
  - ローカル TCP <-> プロトコルフレームのブリッジと接続ライフサイクル。
- `src/client/edge_client/udp_assoc.rs`
  - UDP association の管理、送受信、タイムアウト回収。
- `src/client/edge_client/ice.rs`
  - ICE プロトコルフレームの処理（`ICE_START` / `ICE_PUNCH` / `ICE_QUIC_START` / `ICE_STATE_CHANGE`）。
- `src/client/edge_client/edge_ops.rs`
  - Edge レベルのコントロールプレーン操作（online/offline/status）。
- `src/client/edge_client/tunnel_ops.rs`
  - トンネルレベルのコントロールプレーン操作（status/sync/upsert/delete/start/stop）。
- `src/client/edge_client/subscriptions.rs`
  - イベント購読とコールバック登録（tunnel/channel/ice/log）。

### 2.3 その他の client コンポーネント

- `src/client/connection.rs`
  - TLS/mTLS 接続の確立と証明書の読み込み。
- `src/client/cert.rs`
  - CSR/鍵生成と証明書リクエストのデータ構造。
- `src/client/cert_verifier.rs`
  - 証明書検証ロジック。
- `src/client/framing.rs`
  - フレーム読み書きユーティリティ。
- `src/client/utils.rs`
  - 補助関数（HTTP パース、link type の正規化と推論など）。

## 3. ICE ディレクトリ構造

- `src/ice/agent.rs`
  - `IceAgent` ステートマシンの本体フロー（gather/probe/punch/quic/fallback/close）。
- `src/ice/probe.rs`
  - プローブメッセージの構築、検証、結果解析。
- `src/ice/dataplane.rs`
  - QUIC データプレーンセッションのラッパー（接続メタ情報とクローズフロー）。
- `src/ice/forwarder.rs`
  - P2P フォワーダー（publisher/consumer の 2 角色）と stream/tcp ブリッジ。

## 4. Node エクスポートチェーン（デッドコード整理時に保護必須）

### 4.1 主要チェーン

1. `src/lib.rs` が `#[napi]` インターフェースを公開（例：`edge_online`、`request_tunnel_sync`、`start_tunnel`、`subscribe_ice_events`）。
2. NAPI メソッドが `client::EdgeClient` の同名または類似の名前のメソッドを呼び出す。
3. `EdgeClient` は `read_loop` + 各サブモジュールの trait/impl を介して実際のプロトコル処理を実行。
4. イベントコールバックは `ThreadsafeFunction` を通じて Node 側へ返される。

### 4.2 整理上の制約

- 関数が `#[napi] -> EdgeClient -> サブモジュール` の呼び出しチェーン上にある限り、Rust 内のローカル参照が少なくてもデッドコードとして削除してはなりません。
- `protocol/generated.rs` と `protocol/message.rs` 内の一部の `allow(dead_code)` はプロトコル互換性維持のためのものであり、安易に削除すべきではありません。

## 5. 現在までに完了した構造整理

- `edge_client` のロジックを責務別に `src/client/edge_client/` ディレクトリへ分割。
- 読み取りディスパッチロジックを `read_loop.rs` に統合し、分散メンテナンスを回避。
- HTTP 処理関連ロジックを `http.rs` に統合。
- ICE から未呼び出しのデータプレーンインターフェースを一括削除し、実行に実際に必要な最小機能のみ維持。
- `forwarder.rs` 内の未読み取りフィールド（`ChannelRoute.channel_id`）を削除。

## 6. 今後のメンテナンス提案

- 新機能は責務の明確なサブモジュールに配置し、巨大な `edge_client.rs` ファイルへ流し戻さないこと。
- デッドコードを削除する前に、`#[napi]` エクスポートチェーン上にあるかを必ず確認する。
- リファクタリング後は最低限、次を実行：
  - `cd modules/tunnel/transport && cargo test`
  - 必要に応じて呼び出しチェーン文書を更新し、「構造図 + コード」の同期を維持。

## 7. P2P インターフェースとステートマシン変更図（実装待ちベースライン）

> 注：本節は 2026-05-14 に確定したリファクタリング方向を記録したもので、「ICE 成功後にビジネストラフィックが P2P へ切り替わらない」問題の修正を目的としています。
> 現在は設計ベースラインであり、コードがすべて実装済みであることを意味しません。

### 7.1 主要原則

1. `ICE_QUIC_START.role` は QUIC 接続確立の角色（server/client）にのみ使用する。
2. ビジネストランスファーの角色（publisher/consumer）は channel 単位で決定し、`ICE_QUIC_START.role` から推論しない。
3. P2P データプレーンの配線は 2 つのタイミングでトリガーする（デュアルトリガーによりタイミング競合を解決）：
   - `IceEvent::QuicConnected`
   - `start_tunnel` の成功リターン後

### 7.2 インターフェース変更図（Rust / NAPI）

```text
Before（現状、問題のあるパス）
ICE_QUIC_START.role
    └── IceAgent::handle_ice_quic_start()
          └── ForwarderRole に直接バインド (server=>publisher, client=>consumer)
                └── ビジネストラフィックの角色がセッションの角色に上書きされる
                      └── よくある結果：QUIC 接続済みだが、channel が正しく登録/監視されていない

After（目標、分離されたパス）
ICE_QUIC_START.role
    └── QUIC ハンドシェイクの分岐 (accept/connect) のみを決定

Channel metadata / start_tunnel runtime
    └── 各 channel のビジネスの方向 (publisher/consumer) を決定
          └── wire_p2p_forwarding() による自動配線
                ├── publisher: register_channel(channel_id, local_addr)
                └── consumer : start_consumer_listener(bind=local_addr)
```

### 7.3 ステートマシン変更図（Transport 側）

```text
Before
[ICE Connected]
    └── forwarder が作成済み（セッションレベル）
          └── JS からの手動呼び出しを待機:
                - p2p_register_channel(...)
                - p2p_start_consumer_listener(...)
                      └── 未呼び出しまたはタイミングが不正 => トラフィックは依然 relay 経由 / トラフィックなし

After
[ICE Connected]
    └── 自動配線をトリガー（channel リストに従う）
          ├── channel=publisher の場合: ルートを登録
          └── channel=consumer の場合: ローカル listener を起動（元の local_addr のバインドを優先）

[start_tunnel success]
    └── 自動配線を再度トリガー（冪等）
          └── 「tunnel が先に成功し ICE が後」「ICE が先に成功し tunnel が後」の両方の順序をフォールバックでカバー
```

### 7.4 モジュール変更マッピング（計画）

1. `src/lib.rs`
   - 自動配線の調整エントリを追加/拡張（例：`wire_p2p_forwarding`）。
   - `subscribe_ice_events` の `QuicConnected` 分岐で配線をトリガー。
   - `start_tunnel` 成功後に配線をトリガー。
2. `src/client/edge_client.rs`
   - P2P channel バインディングのスナップショットを公開（`link_type=p2p` のみ）。
   - consumer listener 確立後の channel `local_addr` の更新を許可。
3. `src/ice/forwarder.rs`
   - consumer listener が「バインドアドレス指定」モードをサポート（ビジネスの期待ポートのバインドを優先）。
   - 既存のランダムポート機能を fallback として維持。

### 7.5 現在のスコープ境界

1. 本次ラウンドは TCP/HTTP の P2P チャネルへのトラフィック切替問題の修正を優先。
2. UDP と HTTPS 証明書ポリシーは本次ラウンドの実装範囲外（HTTPS は別途設計）。

## 8. P2P 結合テストチェックリスト（実行版）

> 目的：「ICE 成功後に TCP/HTTP が自動的に P2P へ切り替わったか」を素早く検証し、失敗時は断点を特定する。

### 8.1 前提条件

1. 両エンドがともに `subscribe_ice_events` を実行済み。
2. tunnel channel の `link_type` が `p2p`（少なくとも 1 つの TCP/HTTP channel）。
3. `transport` の Rust ログを確認可能な状態を維持（`stderr` / 実行ログ）。

### 8.2 中核となるトリガー順序

1. `start_tunnel` をトリガー（または既存トンネルの復元）。
2. ICE ネゴシエーションが `quic_connected` に到達するのを待つ。
3. 自動配線のトリガーログが 2 回現れるか観察：
   - `source=start_tunnel`
   - `source=ice_quic_connected`

### 8.3 必須ログ（成功パス）

1. 自動配線の概要：
   - `p2p auto-wire from <source>: channels=<n> forwarder[publisher=..., consumer=...]`
2. Publisher ルート登録：
   - `p2p auto-wire register channel=...`
3. Consumer リッサー確立：
   - `p2p consumer listener ready channel=... addr=...`
4. データが P2P 転送に入ったこと：
   - `P2pForwarder] publisher stream route lookup channel=...`

### 8.4 よくある失敗分岐と原因判定

1. `skip p2p auto-wire ... no p2p channels`
   - 原因：channel が `link_type=p2p` とマークされていない、または `local_addr` が空。
2. `skip p2p auto-wire for udp channel=...`
   - 原因：現在のポリシーは UDP を明示的にスキップ（本次ラウンドの範囲外）。
3. `p2p consumer listener failed channel=... bind=...`
   - 原因：ローカルポートが使用中 / バインド権限なし。`local_addr` の使用可否を確認する必要あり。
4. `publisher stream error: no route for channel ...`
   - 原因：Publisher の登録失敗、または channel_id/canonical_id の不一致。

### 8.5 受け入れ基準（本次ラウンド）

1. 少なくとも 1 つの TCP/HTTP channel が `quic_connected` 後に `register` または `listener ready` ログを表示する。
2. ビジネストラフィック発生時に `publisher stream route lookup` が表示され、`no route for channel` が現れない。
3. 同一セッション内では `start_tunnel` と `ice_quic_connected` のどちらが先に成功しても、最終的に配線が成功する。
