-- Cold層（統計分析用ログ）— 仕様書 §6.3
--
-- 保持期間は 90日（COLD_RETENTION_DAYS）。削除は DELETE ではなく
-- 月次パーティションの DROP で行う（§9.1）。

CREATE TABLE IF NOT EXISTS checkins (
    id            BIGSERIAL,
    app_id        CHAR(26)     NOT NULL,
    location_id   VARCHAR(64)  NOT NULL,
    client_hash   BYTEA        NOT NULL,   -- 16 bytes, §5.3.4（生トークンは保存しない）
    ip_hash       BYTEA,                   -- 16 bytes, §9.3（生IPは保存しない）
    is_new_client BOOLEAN      NOT NULL,
    occurred_at   TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX IF NOT EXISTS checkins_lookup_idx
    ON checkins (app_id, location_id, occurred_at DESC);

-- DEFAULT パーティション。
-- 月次パーティションが未作成でも INSERT が失敗しないための受け皿。
-- 本番では月次パーティションを事前作成し、DEFAULT は空に保つこと。
CREATE TABLE IF NOT EXISTS checkins_default PARTITION OF checkins DEFAULT;
