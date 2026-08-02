//! 共有状態とリクエスト元IPの決定

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use sqlx::PgPool;

use crate::cold::ColdWriter;
use crate::config::Config;
use crate::hot::Hot;
use crate::token::TokenIssuer;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub hot: Hot,
    pub cold: ColdWriter,
    pub pool: PgPool,
    pub issuer: Arc<TokenIssuer>,
}

/// リクエスト元のIPアドレスを決定する。
///
/// `X-Forwarded-For` はクライアントが自由に付与できるため、**信頼できるプロキシの
/// 段数を正しく設定しないとIPを詐称され、レート制限が無力化する**（§5.4.3）。
///
/// - `hops == 0`: TCP のソースアドレスを使う（プロキシなしのローカル実行）
/// - `hops >= 1`: XFF の**右から `hops` 番目**を使う。自分のプロキシが末尾に
///   追記するため、右から数えるのが正しい。左端はクライアントが偽装できる。
///
/// XFF が短すぎる（＝期待した段数のプロキシを経ていない）場合は、詐称の可能性が
/// あるためソースアドレスにフォールバックする。
pub fn client_ip(headers: &HeaderMap, socket: SocketAddr, hops: usize) -> String {
    if hops == 0 {
        return socket.ip().to_string();
    }

    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let parts: Vec<&str> = forwarded
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    match parts.len().checked_sub(hops).and_then(|i| parts.get(i)) {
        Some(ip) => (*ip).to_string(),
        None => socket.ip().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn addr() -> SocketAddr {
        "203.0.113.9:1234".parse().unwrap()
    }

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h
    }

    #[test]
    fn uses_socket_address_when_no_proxy_is_trusted() {
        let h = headers("1.2.3.4");
        assert_eq!(client_ip(&h, addr(), 0), "203.0.113.9");
    }

    #[test]
    fn takes_nth_entry_from_the_right() {
        // 単一プロキシ配下: 末尾がプロキシの追記した実クライアントIP
        let h = headers("9.9.9.9, 198.51.100.7");
        assert_eq!(client_ip(&h, addr(), 1), "198.51.100.7");
    }

    #[test]
    fn spoofed_leading_entries_are_ignored() {
        // 攻撃者が先頭に偽のIPを並べても、右からの位置は変わらない
        let h = headers("evil-1, evil-2, evil-3, 198.51.100.7");
        assert_eq!(client_ip(&h, addr(), 1), "198.51.100.7");
    }

    #[test]
    fn falls_back_when_header_is_missing_or_too_short() {
        assert_eq!(client_ip(&HeaderMap::new(), addr(), 1), "203.0.113.9");
        // 2段のプロキシを期待しているのに1つしかない = 詐称の可能性
        let h = headers("1.2.3.4");
        assert_eq!(client_ip(&h, addr(), 2), "203.0.113.9");
    }
}
