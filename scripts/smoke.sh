#!/usr/bin/env bash
# tapswarm スモークテスト
#
# 仕様書 §7 の各エンドポイントと、§5 のスパム対策が実際に効いていることを
# 稼働中のサーバーに対して確認する。
#
#   ./scripts/smoke.sh [BASE_URL]   (既定: http://localhost:8080)

set -uo pipefail

BASE="${1:-http://localhost:8080}"
PASS=0
FAIL=0

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }

check() { # check <説明> <実際> <期待>
  if [ "$2" = "$3" ]; then
    echo "  $(c 32 PASS)  $1"
    PASS=$((PASS + 1))
  else
    echo "  $(c 31 FAIL)  $1"
    echo "        期待: $3"
    echo "        実際: $2"
    FAIL=$((FAIL + 1))
  fi
}

# JSON から値を1つ取り出す（jq に依存しない）。
# 文字列はそのまま、それ以外は JSON 表記で出す（true/false が Python の
# True/False にならないようにするため）。
jget() { python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
    if d is None: break
print('null' if d is None else d if isinstance(d, str) else json.dumps(d))
" "$1"; }

# 26文字 Base32 の app_id を生成する（§5.2）。
# サーバーへの登録は不要なので、クライアント側で作れる。
gen_app_id() {
  python3 -c "import os,base64;print(base64.b32encode(os.urandom(16)).decode().rstrip('='))"
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

post() { curl -s -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }
post_status() { status -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }

# 前提が崩れたら、その場で理由を出して止める。
#
# 以前はトークン発行の失敗を jget が静かに "null" に変換し、打刻の結果も
# 捨てていたため、ずっと後ろの「削除されない」という無関係な症状として
# 現れていた。前提の失敗は前提として報告する。
abort() {
  # 必ず stderr へ出す。issue_token のようにコマンド置換の中から呼ばれると、
  # stdout に書いたものが呼び出し元の変数へ流れ込んでしまうため。
  {
    echo
    echo "  $(c 31 ABORT)  $1"
    shift
    for line in "$@"; do echo "         $line"; done
    echo
  } >&2
  # コマンド置換の中では exit はサブシェルしか抜けない。
  # スクリプト本体に TERM を送って確実に停止させる。
  kill -TERM $$ 2>/dev/null
  exit 2
}

# トークンを1つ発行する。失敗したら即停止。
issue_token() {
  local body t
  body=$(post /api/v1/clients "{\"app_id\":\"$APP\"}")
  t=$(printf '%s' "$body" | jget client_token)
  if [ "${t#v1.}" = "$t" ]; then
    abort "client_token を発行できませんでした" \
      "応答: $body" \
      "" \
      "IP あたりのトークン発行上限（既定 60個/時、仕様書 §5.3.2）に" \
      "達している可能性があります。本スクリプトは1回の実行で7個消費するため、" \
      "1時間に8回程度が上限です。" \
      "" \
      "繰り返し流したい場合は .env に次を設定してサーバーを再起動してください:" \
      "  CLIENT_ISSUE_QUOTA_PER_HOUR=100000"
  fi
  printf '%s' "$t"
}

# 打刻して、受理されたことを確認する。受理されなければ即停止。
checkin_ok() { # checkin_ok <location_id> <client_token>
  local body
  body=$(post /api/v1/checkin "{\"app_id\":\"$APP\",\"location_id\":\"$1\",\"client_token\":\"$2\"}")
  if [ "$(printf '%s' "$body" | jget accepted)" != "true" ]; then
    abort "打刻が受理されませんでした (location_id=$1)" "応答: $body"
  fi
}

echo
echo "$(c 1 "tapswarm smoke test") — $BASE"
echo

# ---------------------------------------------------------------------------
echo "$(c 36 "▸ ヘルスチェック（§7.6）")"
check "GET /healthz が 200" "$(status "$BASE/healthz")" "200"
check "GET /readyz が 200"  "$(status "$BASE/readyz")"  "200"
check "存在しないパスは 404" "$(status "$BASE/api/v1/nope")" "404"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ app_id のバリデーション（§5.2）")"
APP=$(gen_app_id)
check "生成された app_id が26文字" "${#APP}" "26"
check "人間可読な app_id は 400" \
  "$(post_status /api/v1/clients '{"app_id":"myapp-prod"}')" "400"
check "空の app_id は 400" \
  "$(post_status /api/v1/clients '{"app_id":""}')" "400"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ トークン発行（§7.1）")"
TOK1=$(issue_token)
check "client_token が発行される" "$([ -n "$TOK1" ] && echo yes || echo no)" "yes"
check "プレフィックスが v1." "${TOK1:0:3}" "v1."

LOC="smoke-$(date +%s)"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ 自称 client_token は拒否される（§5.3.3）")"
check "でたらめなトークンは 401" \
  "$(post_status /api/v1/checkin "{\"app_id\":\"$APP\",\"location_id\":\"$LOC\",\"client_token\":\"attacker-0001\"}")" \
  "401"
FORGED="v1.$(echo -n "$TOK1" | cut -d. -f2).AAAAAAAAAAAAAAAAAAAAAA"
check "署名を差し替えたトークンは 401" \
  "$(post_status /api/v1/checkin "{\"app_id\":\"$APP\",\"location_id\":\"$LOC\",\"client_token\":\"$FORGED\"}")" \
  "401"

OTHER_APP=$(gen_app_id)
check "他アプリのトークン流用は 401" \
  "$(post_status /api/v1/checkin "{\"app_id\":\"$OTHER_APP\",\"location_id\":\"$LOC\",\"client_token\":\"$TOK1\"}")" \
  "401"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ 打刻とクールダウン（§5.4.1, §7.2）")"
R=$(post /api/v1/checkin "{\"app_id\":\"$APP\",\"location_id\":\"$LOC\",\"client_token\":\"$TOK1\"}")
check "1回目の打刻が受理される" "$(echo "$R" | jget accepted)" "true"
R=$(post /api/v1/checkin "{\"app_id\":\"$APP\",\"location_id\":\"$LOC\",\"client_token\":\"$TOK1\"}")
check "60秒以内の再打刻は無視される" "$(echo "$R" | jget accepted)" "false"
check "その理由が cooldown" "$(echo "$R" | jget reason)" "cooldown"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ k-匿名性（§5.6, k=3）")"
Q="app_id=$APP&location_id=$LOC&window=15"
R=$(curl -s "$BASE/api/v1/crowd_level?$Q")
check "1人だけの地点は suppressed"  "$(echo "$R" | jget suppressed)" "true"
check "count は伏せられる"          "$(echo "$R" | jget count)"      "null"
check "signals も伏せられる"        "$(echo "$R" | jget signals)"    "null"

# k に達するまでクライアントを増やす
for _ in 2 3; do
  checkin_ok "$LOC" "$(issue_token)"
done

R=$(curl -s "$BASE/api/v1/crowd_level?$Q")
check "3人になると開示される" "$(echo "$R" | jget suppressed)" "false"
check "count が 3"           "$(echo "$R" | jget count)"      "3"
check "window が返る"        "$(echo "$R" | jget window)"     "15"
check "as_of が返る"         "$([ "$(echo "$R" | jget as_of)" != "null" ] && echo yes || echo no)" "yes"
check "unique_ip_count が返る" \
  "$([ "$(echo "$R" | jget signals.unique_ip_count)" != "null" ] && echo yes || echo no)" "yes"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ バリデーション（§8.3）")"
for W in 0 -1 1.5 abc 1441 ""; do
  check "window=$W は 400" "$(status "$BASE/api/v1/crowd_level?app_id=$APP&location_id=$LOC&window=$W")" "400"
done
check "window 欠落は 400" "$(status "$BASE/api/v1/crowd_level?app_id=$APP&location_id=$LOC")" "400"
check "location_id に日本語は 400" \
  "$(status "$BASE/api/v1/crowd_level?app_id=$APP&location_id=%E6%B8%8B%E8%B0%B7&window=15")" "400"
check "エラー形式に code が含まれる" \
  "$(curl -s "$BASE/api/v1/crowd_level?app_id=$APP&location_id=$LOC&window=0" | jget error.code)" \
  "invalid_window"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ 一括取得（§7.4）")"
R=$(curl -s "$BASE/api/v1/crowd_levels?app_id=$APP&location_ids=$LOC,nowhere-1&window=15")
check "results が2件返る" "$(echo "$R" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["results"]))')" "2"
check "順序が指定順と一致" \
  "$(echo "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["results"][0]["location_id"])')" "$LOC"
check "未知の地点も 404 にせず suppressed で返す" \
  "$(echo "$R" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["results"][1]["suppressed"]))')" "true"

BIG=$(python3 -c "print(','.join('l%d'%i for i in range(101)))")
check "101件は 400" "$(status "$BASE/api/v1/crowd_levels?app_id=$APP&location_ids=$BIG&window=15")" "400"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ 打刻時の同梱集計（§7.2 オプション）")"
T=$(issue_token)
R=$(curl -s -X POST "$BASE/api/v1/checkin?with_count=1&window=15" \
      -H 'content-type: application/json' \
      -d "{\"app_id\":\"$APP\",\"location_id\":\"$LOC\",\"client_token\":\"$T\"}")
check "crowd_level が同梱される" "$(echo "$R" | jget crowd_level.count)" "4"

# ---------------------------------------------------------------------------
echo
echo "$(c 36 "▸ データ削除（§7.5）")"
# 直前までのステップ数に依存しないよう、専用の地点とクライアントで検証する。
# 累計人数を絶対値で期待すると、前段のどれか1つが変わるだけで壊れてしまう。
DLOC="del-$(date +%s)"
DQ="app_id=$APP&location_id=$DLOC&window=15"
DT3=""
for _ in 1 2 3; do
  DT3=$(issue_token)
  checkin_ok "$DLOC" "$DT3"
done

check "削除前は3人で開示される" "$(curl -s "$BASE/api/v1/crowd_level?$DQ" | jget count)" "3"

check "偽トークンでの削除は 401" \
  "$(status -X DELETE "$BASE/api/v1/clients/me" -H 'content-type: application/json' \
      -d "{\"app_id\":\"$APP\",\"client_token\":\"attacker-0001\"}")" \
  "401"
check "偽トークンでは誰も消えない" "$(curl -s "$BASE/api/v1/crowd_level?$DQ" | jget count)" "3"

DBODY="{\"app_id\":\"$APP\",\"client_token\":\"$DT3\"}"
DRESP=$(curl -s -i -X DELETE "$BASE/api/v1/clients/me" \
             -H 'content-type: application/json' -d "$DBODY")
check "DELETE /clients/me が 204" "$(printf '%s' "$DRESP" | head -1 | awk '{print $2}')" "204"

# 3人 → 2人。k=3 を下回るので秘匿に切り替わる
R=$(curl -s "$BASE/api/v1/crowd_level?$DQ")
check "削除により k を下回り秘匿される" "$(echo "$R" | jget suppressed)" "true"
check "秘匿時は count も返らない"        "$(echo "$R" | jget count)"      "null"

if [ "$(echo "$R" | jget suppressed)" != "true" ]; then
  echo
  echo "  $(c 33 "[debug] 削除が反映されていないため状態を出力します")"
  echo "        APP  = $APP"
  echo "        DLOC = $DLOC"
  echo "        DT3  = $DT3  (${#DT3} 文字)"
  echo "        送信した本文 = $DBODY"
  echo "        DELETE の応答:"
  printf '%s\n' "$DRESP" | sed 's/^/          | /'
  echo "        削除後の応答 = $R"
  echo "        locs   : $(docker compose exec -T redis redis-cli SMEMBERS "locs:$APP" < /dev/null | tr '\n' ' ')"
  echo "        ZCARD  : $(docker compose exec -T redis redis-cli ZCARD "ck:$APP:$DLOC" < /dev/null)"
  echo "        members: $(docker compose exec -T redis redis-cli ZRANGEBYSCORE "ck:$APP:$DLOC" -inf +inf < /dev/null | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
echo
if [ "$FAIL" -eq 0 ]; then
  echo "$(c 32 "すべて成功") — $PASS 件"
else
  echo "$(c 31 "失敗あり") — 成功 $PASS 件 / 失敗 $FAIL 件"
fi
echo
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
