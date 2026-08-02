# tapswarm

打刻（チェックイン）データのみを受け取り、スライディングウィンドウ内のアクティブクライアント数を返す混雑度測定API。**利用登録・APIキー・ユーザー認証を必要としない。**

仕様書: [`.github/assets/spec.md`](.github/assets/spec.md) (v0.2)

---

## ローカルで動かす

必要なのは Docker Desktop だけです（パターンBでは Rust ツールチェインも）。

### パターンA — 全部 compose で起動する

```bash
docker compose up --build
```

Redis・PostgreSQL・APIサーバーが起動し、マイグレーションが自動適用されて `http://localhost:8080` で待ち受けます。**初回はコンテナ内で Rust をフルビルドするため数分かかります。**

起動を待ってから進めたい場合:

```bash
docker compose up --build -d --wait
```

### パターンB — データストアだけ compose、APIは手元で動かす（推奨）

コード修正のたびにイメージを焼き直さずに済み、コンパイルエラーもそのまま読めます。

```bash
docker compose up -d redis postgres
```

```bash
cp .env.example .env && set -a && . ./.env && set +a && cargo run
```

`.env.example` の接続先は `localhost:6379` / `localhost:5432` を向いており、compose がその2ポートを公開しているのでそのまま繋がります。

## 動作確認

サーバーが起動している状態で:

```bash
bash scripts/smoke.sh
```

仕様書 §7 の全エンドポイントに加え、**自称トークンの拒否・他アプリのトークン流用の拒否・クールダウン・k-匿名性・バリデーション**が実際に効いていることを検証します。約40項目です。

手で1回叩いてみる場合:

```bash
curl -s localhost:8080/healthz
```

ユニットテストは外部依存なしで走ります:

```bash
cargo test
```

## 中を覗く / 片付ける

```bash
docker compose exec -T redis redis-cli --scan --pattern 'ck:*' < /dev/null
```

```bash
docker compose exec -T postgres psql -U tapswarm -d tapswarm -c 'SELECT count(*) FROM checkins;' < /dev/null
```

> `docker compose exec` は標準入力を掴むため、スクリプトの中で使うと**後続の行を吸い込んで壊れます**。`< /dev/null` を必ず付けてください（付け忘れると `ZCARD` が常に `0` を返すなど、静かに誤った値が出ます）。

```bash
docker compose logs -f api
```

停止（データは残る）:

```bash
docker compose down
```

データも消して作り直す:

```bash
docker compose down -v
```

## うまく動かないとき

| 症状 | 原因と対処 |
|:---|:---|
| `api` が起動直後に終了する | 環境変数の不足・不備。`docker compose logs api` に日本語で理由が出ます。`SIGNING_KEY` と `HASH_KEY` は **32バイト以上**が必須です |
| `cargo run` が接続エラー | `docker compose ps` で redis / postgres が `healthy` か確認してください |
| ポートが使用中 | 既存の Redis / PostgreSQL が 6379 / 5432 を掴んでいます。停止するか、`docker-compose.yml` の `ports` を変更してください |
| ビルドエラーが出る | **本 PoC はまだ一度もコンパイル検証ができていません**（下記「現状」を参照）。パターンB でエラー全文を確認するのが早いです |

## 現状

コードは書き上げていますが、**ビルド・実行の検証は未了です。** 依存クレート（`axum 0.8` / `redis 0.27` / `sqlx 0.8`）の API 差異による型エラーが残っている可能性があります。ビルドが通ったら `Cargo.lock` をコミットして、以降のビルドを再現可能にしてください。

---

## 使い方

### 1. `app_id` を発行する（サーバー登録は不要）

```bash
cargo run -- gen-app-id
```

128bit のランダム値です。**連番や `myapp-prod` のような推測可能な値は構文レベルで拒否されます**（§5.2）。本来は SDK が初回起動時に生成します。

### 2. クライアントトークンを取得する（端末の生涯で1回）

```bash
curl -X POST http://localhost:8080/api/v1/clients \
  -H 'content-type: application/json' \
  -d '{"app_id":"YOUR_APP_ID"}'
```

```json
{ "client_token": "v1.…", "expires_at": "2026-08-31T12:34:56Z" }
```

**端末はこれを永続保存して再利用してください。** 毎回取得すると、そのたびに別のクライアントとして数えられます。

### 3. 打刻する

```bash
curl -X POST http://localhost:8080/api/v1/checkin \
  -H 'content-type: application/json' \
  -d '{"app_id":"YOUR_APP_ID","location_id":"shop-001","client_token":"v1.…"}'
```

### 4. 混雑度を取得する

```bash
curl "http://localhost:8080/api/v1/crowd_level?app_id=YOUR_APP_ID&location_id=shop-001&window=15"
```

```json
{
  "location_id": "shop-001",
  "count": 42,
  "window": 15,
  "as_of": "2026-08-01T12:34:56Z",
  "suppressed": false,
  "signals": { "unique_ip_count": 18, "new_client_ratio": 0.12 }
}
```

`count` が「混んでいる」かどうかは**判定しません**。`signals` も同様に、真偽の判定ではなく判断材料です。駅前広場で `unique_ip_count: 1` に対し `count: 42` なら異常ですが、社内カフェなら正常です。その文脈を持つのはクライアント側です（§2.2, §2.3）。

---

## 設計の要点

### 認証なしで水増しを防ぐ、のではない

**認証がない以上、水増しの完全な防止は原理的に不可能です**（Sybil 攻撃）。目標は「割に合わなくする」「被害を1アプリに閉じる」「事後に検出できる」の3点で、4層で実現しています（§5）。

| 層 | 実装 | 効果 |
|:---|:---|:---|
| 0 | `app_id` を 128bit ランダムに強制（[`token.rs`](src/token.rs)） | 無差別攻撃の遮断。汚染が1アプリに閉じる |
| 1 | `client_id` の自称を廃止し HMAC 署名付きトークンをサーバーが発行（[`token.rs`](src/token.rs)） | **水増しコストがトークン取得コストに変換される** |
| 2 | 60秒クールダウン + IPレート制限（[`hot.rs`](src/hot.rs)） | 連打の抑止。冪等性の担保 |
| 3 | `signals` の開示（[`crowd.rs`](src/routes/crowd.rs)） | 判定せず判断材料を返す |
| 4 | `count < 3` の秘匿（[`crowd.rs`](src/routes/crowd.rs)） | 少人数時の個人特定を防止 |

層1が要点です。打刻そのものに厳しいIP制限をかけると、**スタジアムの共有Wi-Fi や CGNAT 配下の正規ユーザーを巻き添えにします**。しかしトークン取得は端末の生涯でほぼ1回なので、クォータを消費するのは新規端末だけで済みます。

### 時刻源は Redis に統一

APIサーバーは複数台構成になるため、システムクロックではなく Lua スクリプト内の `redis.call('TIME')` を単一の時刻源としています（§4.4、[`hot.rs`](src/hot.rs)）。インスタンス間のクロックスキューが `count` に影響しません。

### Hot層は同期、Cold層は非同期

Redis への書き込みまで非同期にすると、打刻直後の取得に自分の打刻が反映されません（read-after-write 不整合）。非同期にしてよいのは PostgreSQL のみです（§4.2/4.3）。

---

## 既知の制約

| 項目 | 内容 |
|:---|:---|
| **Redis Cluster 非対応** | 1回のパイプラインで複数スロットに跨るキーを扱うため。§10 の想定規模では単一ノードで足ります |
| **Cold層のデータロスを許容** | プロセス内バウンデッドキューのため、キュー溢れと再起動でログを失います。統計分析用なので `count` には影響しません（§4.3）。永続キュー化は Phase 2 |
| **保持期間の削除方法が仕様と異なる** | 仕様（§9.1）は月次パーティションの `DROP` ですが、本 PoC は DEFAULT パーティションのみのため `DELETE` で代用しています（[`cold.rs`](src/cold.rs)）。本番前にパーティション運用へ切り替えが必要 |
| **`signals` に ±5分の誤差** | HyperLogLog を5分バケットで保持するため。`count` 自体は秒精度です（§6.1） |
| **`TRUSTED_PROXY_HOPS` の設定が必須** | 既定は `0`（TCPソースアドレス）。Railway / Render 等のプロキシ配下では `1` を設定しないと、`X-Forwarded-For` の詐称でレート制限が無力化します（[`state.rs`](src/state.rs)） |
| **MVP スコープ外** | 統計分析API、`trend`、Proof of Work（§12） |

## 本番投入前に必ず行うこと

1. `SIGNING_KEY` / `HASH_KEY` を十分な長さのランダム値に差し替える（`docker-compose.yml` の値は開発用）
2. `TRUSTED_PROXY_HOPS` をデプロイ構成に合わせて設定する
3. PostgreSQL の月次パーティション運用に切り替える
4. Redis の AOF 永続化とバックアップを確認する
