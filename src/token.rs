//! 識別子とクライアントトークン — 仕様書 §5.2, §5.3
//!
//! 本サービスの水増し対策の中核。クライアントによる `client_id` の自称を廃止し、
//! サーバーが HMAC 署名付きトークンを発行する。トークンはサーバー側に保存せず、
//! 署名検証のみで真正性を判定する（ステートレス検証）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const APP_ID_BYTES: usize = 16; // 128bit
const APP_ID_CHARS: usize = 26; // Base32(128bit) = 26文字
const NONCE_BYTES: usize = 16;
// kid(1) + app_id(16) + issued_at(4) + nonce(16) = 37
const PAYLOAD_BYTES: usize = 1 + APP_ID_BYTES + 4 + NONCE_BYTES;
const SIG_BYTES: usize = 16;
const HASH_BYTES: usize = 16;
const TOKEN_PREFIX: &str = "v1.";
pub const MAX_TOKEN_CHARS: usize = 256;

/// 現行の署名鍵ID。鍵ローテーション時にインクリメントし、
/// 旧鍵はトークン TTL の期間だけ検証用に保持する。
const CURRENT_KID: u8 = 0;

/// 発行から24時間以内のトークンを「新規クライアント」とみなす（§5.5 `new_client_ratio`）
const NEW_CLIENT_WINDOW_SEC: u64 = 86_400;

// ---------------------------------------------------------------------------
// app_id
// ---------------------------------------------------------------------------

/// アプリ識別子。128bit のランダム値（§5.2）。
///
/// 連番や `myapp-prod` のような推測可能な値を構文レベルで禁止することで、
/// 無差別攻撃を遮断する。事前登録は行わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppId([u8; APP_ID_BYTES]);

impl AppId {
    pub fn generate() -> Self {
        let mut b = [0u8; APP_ID_BYTES];
        rand::thread_rng().fill_bytes(&mut b);
        Self(b)
    }

    /// `^[A-Z2-7]{26}$` に合致し、かつ正準な Base32 表現であることを検証する。
    pub fn parse(s: &str) -> Result<Self, AppError> {
        if s.len() != APP_ID_CHARS {
            return Err(AppError::invalid_app_id());
        }
        let decoded = BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| AppError::invalid_app_id())?;
        let bytes: [u8; APP_ID_BYTES] =
            decoded.try_into().map_err(|_| AppError::invalid_app_id())?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; APP_ID_BYTES] {
        &self.0
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&BASE32_NOPAD.encode(&self.0))
    }
}

// ---------------------------------------------------------------------------
// client_token
// ---------------------------------------------------------------------------

/// 検証済みクライアント。
pub struct VerifiedClient {
    payload: [u8; PAYLOAD_BYTES],
    issued_at: u64,
}

/// `payload` には nonce が含まれ、これと署名が揃うとトークンそのものになる。
/// 誤ってログやエラーメッセージへ出さないよう、`Debug` では伏せる（§9.2）。
impl std::fmt::Debug for VerifiedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedClient")
            .field("payload", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl VerifiedClient {
    /// Redis / PostgreSQL に保存する識別子（§5.3.4）。
    ///
    /// 生の `client_token` はどのストレージにも保存しない。これによりストレージが
    /// 漏洩してもトークンの再利用（なりすまし打刻）はできない。
    pub fn client_hash(&self, hash_key: &[u8]) -> Vec<u8> {
        truncated_hmac(hash_key, &self.payload, HASH_BYTES)
    }

    /// 発行から24時間以内か（§5.5 `new_client_ratio` の分子）
    pub fn is_new(&self, now: u64) -> bool {
        now.saturating_sub(self.issued_at) < NEW_CLIENT_WINDOW_SEC
    }
}

pub struct TokenIssuer {
    signing_key: Vec<u8>,
    ttl_sec: u64,
}

impl TokenIssuer {
    pub fn new(signing_key: Vec<u8>, ttl_sec: u64) -> Self {
        Self {
            signing_key,
            ttl_sec,
        }
    }

    /// 新しい `client_token` を発行する（§7.1）。
    ///
    /// 戻り値は `(token, expires_at_unix)`。
    pub fn issue(&self, app_id: &AppId, now: u64) -> (String, u64) {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = CURRENT_KID;
        payload[1..1 + APP_ID_BYTES].copy_from_slice(app_id.as_bytes());
        // UNIX秒を u32 BE で格納（2106年まで表現可能）
        payload[1 + APP_ID_BYTES..5 + APP_ID_BYTES]
            .copy_from_slice(&(now as u32).to_be_bytes());
        payload[5 + APP_ID_BYTES..].copy_from_slice(&nonce);

        let sig = truncated_hmac(self.signing_key_for(CURRENT_KID), &payload, SIG_BYTES);

        let token = format!(
            "{TOKEN_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(&sig)
        );
        (token, now + self.ttl_sec)
    }

    /// トークンを検証する（§5.3.3）。
    ///
    /// 1. バージョンプレフィックス
    /// 2. `kid` が既知の鍵を指すこと
    /// 3. HMAC 署名の一致（定数時間比較）
    /// 4. payload 内の `app_id` がリクエストの `app_id` と一致すること
    /// 5. `issued_at` が TTL 内かつ未来でないこと
    pub fn verify(
        &self,
        token: &str,
        expected_app_id: &AppId,
        now: u64,
    ) -> Result<VerifiedClient, AppError> {
        if token.len() > MAX_TOKEN_CHARS {
            return Err(AppError::invalid_token());
        }
        let rest = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(AppError::invalid_token)?;
        let (payload_b64, sig_b64) = rest.split_once('.').ok_or_else(AppError::invalid_token)?;

        let payload_vec = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AppError::invalid_token())?;
        let payload: [u8; PAYLOAD_BYTES] = payload_vec
            .try_into()
            .map_err(|_| AppError::invalid_token())?;
        let sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AppError::invalid_token())?;

        // 2. kid
        let key = self
            .signing_key_opt(payload[0])
            .ok_or_else(AppError::invalid_token)?;

        // 3. 署名（定数時間比較）
        let expected = truncated_hmac(key, &payload, SIG_BYTES);
        // 長さが異なる場合 subtle は Choice(0) を返すため、長さ検査は不要
        if expected.as_slice().ct_eq(sig.as_slice()).unwrap_u8() != 1 {
            return Err(AppError::invalid_token());
        }

        // 4. app_id の一致
        if payload[1..1 + APP_ID_BYTES] != expected_app_id.as_bytes()[..] {
            return Err(AppError::invalid_token());
        }

        // 5. 有効期限
        let issued_at = u32::from_be_bytes(
            payload[1 + APP_ID_BYTES..5 + APP_ID_BYTES]
                .try_into()
                .expect("slice is 4 bytes"),
        ) as u64;
        // 未来日付のトークンは、時刻源の揺らぎを考慮して60秒まで許容する
        if issued_at > now + 60 {
            return Err(AppError::invalid_token());
        }
        if now.saturating_sub(issued_at) > self.ttl_sec {
            return Err(AppError::expired_token());
        }

        Ok(VerifiedClient { payload, issued_at })
    }

    fn signing_key_for(&self, _kid: u8) -> &[u8] {
        &self.signing_key
    }

    /// 鍵ローテーション対応の余地。現状は `kid = 0` のみを既知とする。
    fn signing_key_opt(&self, kid: u8) -> Option<&[u8]> {
        (kid == CURRENT_KID).then_some(self.signing_key.as_slice())
    }
}

// ---------------------------------------------------------------------------
// ハッシュ
// ---------------------------------------------------------------------------

fn truncated_hmac(key: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let mut out = mac.finalize().into_bytes().to_vec();
    out.truncate(out_len);
    out
}

/// 生の IP アドレスは保存しない（§9.3）
pub fn ip_hash(hash_key: &[u8], ip: &str) -> Vec<u8> {
    truncated_hmac(hash_key, ip.as_bytes(), HASH_BYTES)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING: &[u8] = b"test-signing-key-0123456789abcdefghij";
    const HASHING: &[u8] = b"test-hash-key-0123456789abcdefghijklm";

    fn issuer() -> TokenIssuer {
        TokenIssuer::new(SIGNING.to_vec(), 30 * 86_400)
    }

    #[test]
    fn app_id_roundtrip() {
        let id = AppId::generate();
        let s = id.to_string();
        assert_eq!(s.len(), APP_ID_CHARS);
        assert!(s.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
        assert_eq!(AppId::parse(&s).unwrap(), id);
    }

    #[test]
    fn app_id_rejects_human_readable_values() {
        // 推測可能な値は構文レベルで拒否される（§5.2）
        for bad in ["myapp-prod", "1", "", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "AAAA"] {
            assert!(AppId::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn token_roundtrip() {
        let iss = issuer();
        let app = AppId::generate();
        let now = 1_800_000_000u64;
        let (token, exp) = iss.issue(&app, now);
        assert_eq!(exp, now + 30 * 86_400);

        let v = iss.verify(&token, &app, now + 10).unwrap();
        assert!(v.is_new(now + 10));
        assert!(!v.is_new(now + NEW_CLIENT_WINDOW_SEC + 1));
        assert_eq!(v.client_hash(HASHING).len(), HASH_BYTES);
    }

    #[test]
    fn token_is_bound_to_its_app_id() {
        // 他アプリのトークンを流用できない
        let iss = issuer();
        let (token, _) = iss.issue(&AppId::generate(), 1_800_000_000);
        let other = AppId::generate();
        assert_eq!(
            iss.verify(&token, &other, 1_800_000_000).unwrap_err().code,
            "invalid_token"
        );
    }

    #[test]
    fn forged_signature_is_rejected() {
        let iss = issuer();
        let app = AppId::generate();
        let (token, _) = iss.issue(&app, 1_800_000_000);

        // 署名部を1文字書き換える
        let parts: Vec<&str> = token.split('.').collect();
        let mut sig: Vec<char> = parts[2].chars().collect();
        sig[0] = if sig[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = sig.into_iter().collect();
        let forged = format!("{}.{}.{}", parts[0], parts[1], tampered);

        assert_eq!(
            iss.verify(&forged, &app, 1_800_000_000).unwrap_err().code,
            "invalid_token"
        );
    }

    #[test]
    fn self_asserted_client_id_is_rejected() {
        // v0.1 の穴: クライアントが好きな識別子を名乗る攻撃
        let iss = issuer();
        let app = AppId::generate();
        for fake in ["attacker-0001", "v1.AAAA.BBBB", ""] {
            assert!(iss.verify(fake, &app, 1_800_000_000).is_err());
        }
    }

    #[test]
    fn expired_token_is_distinguishable() {
        let iss = issuer();
        let app = AppId::generate();
        let now = 1_800_000_000u64;
        let (token, _) = iss.issue(&app, now);
        let err = iss.verify(&token, &app, now + 30 * 86_400 + 1).unwrap_err();
        assert_eq!(err.code, "expired_token");
    }

    #[test]
    fn distinct_tokens_yield_distinct_hashes() {
        let iss = issuer();
        let app = AppId::generate();
        let now = 1_800_000_000u64;
        let a = iss.verify(&iss.issue(&app, now).0, &app, now).unwrap();
        let b = iss.verify(&iss.issue(&app, now).0, &app, now).unwrap();
        assert_ne!(a.client_hash(HASHING), b.client_hash(HASHING));
    }
}
