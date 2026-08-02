//! バリデーション — 仕様書 §8.3

use crate::error::AppError;

pub const MAX_LOCATION_ID_CHARS: usize = 64;
pub const MAX_BULK_LOCATIONS: usize = 100;

/// `location_id`: 1〜64文字、`^[A-Za-z0-9._:-]+$`（ASCII のみ。Unicode 不可）
///
/// Redis のキーに直接埋め込むため、区切り文字と衝突しない文字種に限定している。
pub fn location_id(s: &str) -> Result<&str, AppError> {
    if s.is_empty() {
        return Err(AppError::invalid_location_id(
            "location_id must not be empty",
        ));
    }
    if s.len() > MAX_LOCATION_ID_CHARS {
        return Err(AppError::invalid_location_id(format!(
            "location_id must be at most {MAX_LOCATION_ID_CHARS} characters"
        )));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(AppError::invalid_location_id(
            "location_id must match ^[A-Za-z0-9._:-]+$",
        ));
    }
    Ok(s)
}

/// `window`: 符号なし10進整数。1 ≦ window ≦ MAX_WINDOW_MIN。
///
/// クエリ文字列は文字列として届くため、小数・空文字・符号・空白をここで弾く。
/// `u32::from_str` は `"+15"` を受け付けてしまうので、事前に `^[0-9]+$` を課して
/// 正準な表記だけを通す（`app_id` を正準な Base32 のみ受理するのと同じ方針）。
pub fn window(raw: &str, max_window_min: u32) -> Result<u32, AppError> {
    let invalid = || {
        AppError::invalid_window(format!(
            "window must be an integer between 1 and {max_window_min}"
        ))
    };

    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    // 桁数超過（"99999999999"）もここで弾かれる
    let parsed: u32 = raw.parse().map_err(|_| invalid())?;
    if parsed < 1 || parsed > max_window_min {
        return Err(invalid());
    }
    Ok(parsed)
}

/// `location_ids`: カンマ区切り、1〜100件。各要素は `location_id` の規則に従う。
pub fn location_ids(raw: &str) -> Result<Vec<&str>, AppError> {
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.is_empty() || parts.len() > MAX_BULK_LOCATIONS {
        return Err(AppError::too_many_locations(MAX_BULK_LOCATIONS));
    }
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        out.push(location_id(p)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_id_accepts_expected_shapes() {
        for ok in ["a", "shop-001", "poi:tokyo.station", "A_1", &"x".repeat(64)] {
            assert!(location_id(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn location_id_rejects_invalid_shapes() {
        for bad in ["", &"x".repeat(65), "渋谷", "a b", "a/b", "a*"] {
            assert!(location_id(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn window_rejects_zero_negative_and_non_integer() {
        // §8.3: 小数・0・負値・数値以外はすべて拒否
        for bad in ["0", "-1", "1.5", "15.0", "abc", "", " 15", "1441", "+15"] {
            assert!(window(bad, 1440).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn window_accepts_range_bounds() {
        assert_eq!(window("1", 1440).unwrap(), 1);
        assert_eq!(window("1440", 1440).unwrap(), 1440);
    }

    #[test]
    fn bulk_location_ids_are_capped() {
        let many = (0..=MAX_BULK_LOCATIONS)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(location_ids(&many).is_err());

        let ok = (0..MAX_BULK_LOCATIONS)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(location_ids(&ok).unwrap().len(), MAX_BULK_LOCATIONS);
    }
}
