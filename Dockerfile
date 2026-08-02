# syntax=docker/dockerfile:1
# マルチアーキテクチャ（arm64 / amd64）対応の軽量コンテナ — 仕様書 §4.1

FROM rust:1-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 依存だけを先にビルドしてレイヤキャッシュを効かせる
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
COPY migrations ./migrations
# ソース更新をビルドに確実に反映させる
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim AS runtime
# curl は compose のヘルスチェック（/healthz）専用。
# 本番イメージを絞りたい場合は curl とヘルスチェックを外してよい。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 tapswarm

COPY --from=builder /build/target/release/tapswarm /usr/local/bin/tapswarm

USER tapswarm
EXPOSE 8080
ENV BIND_ADDR=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/tapswarm"]
