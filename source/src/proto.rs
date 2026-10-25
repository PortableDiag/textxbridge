//! Envelopes (TextX agent-protocol §4): ids, timestamps and the replay window.

use serde_json::{json, Value};

/// How long an envelope id is remembered, and the oldest `ts` accepted
/// (LANAgent #76: the replay window is the dedupe window). A queued envelope
/// can legitimately be hours old, so this is days, not minutes.
pub const REPLAY_WINDOW_MS: i64 = 7 * 24 * 3600 * 1000;
/// Clock skew allowed for a `ts` in the future.
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Days from 1970-01-01 to a civil date, and back (Howard Hinnant's algorithms).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// `2026-10-18T22:10:00Z` (UTC, whole seconds).
pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86400));
    let s = secs.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// RFC 3339: `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`. Milliseconds since the epoch.
pub fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut i = 19;
    let mut frac_ms = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = s.get(start..i)?;
        if digits.is_empty() {
            return None;
        }
        let mut ms_str: String = digits.chars().take(3).collect();
        while ms_str.len() < 3 {
            ms_str.push('0');
        }
        frac_ms = ms_str.parse::<i64>().ok()?;
    }
    let offset_min = match s.get(i..)? {
        "Z" | "z" => 0,
        rest if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (oh * 60 + om)
        }
        _ => return None,
    };
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset_min * 60;
    Some(secs * 1000 + frac_ms)
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A ULID: 48 bits of milliseconds, 80 random bits, Crockford base32.
pub fn ulid() -> String {
    let ms = now_ms() as u128 & ((1u128 << 48) - 1);
    let mut rnd = [0u8; 10];
    let _ = getrandom::getrandom(&mut rnd);
    let mut v: u128 = ms << 80;
    for (i, b) in rnd.iter().enumerate() {
        v |= (*b as u128) << (8 * (9 - i));
    }
    (0..26)
        .map(|i| CROCKFORD[((v >> (5 * (25 - i))) & 31) as usize] as char)
        .collect()
}

pub fn envelope(kind: &str, body: Value) -> Value {
    json!({ "v": 1, "id": ulid(), "type": kind, "ts": iso(now_ms()), "body": body })
}

/// Why an incoming envelope is dropped before it is acted on.
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// Not an envelope this version reads: answer `error{code:"protocol"}`.
    Protocol(String),
    /// Outside the replay window: dropped silently, as a replay would be.
    Stale,
}

/// The fields every envelope needs, and the `ts` window. Dedupe is the
/// store's job (ids persist across restarts).
pub fn check(env: &Value, now: i64) -> Result<(String, String), Reject> {
    if env.get("v").and_then(|v| v.as_i64()) != Some(1) {
        return Err(Reject::Protocol("v must be 1".into()));
    }
    let id = env.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() || id.len() > 64 {
        return Err(Reject::Protocol("id must be 1-64 characters".into()));
    }
    let kind = env.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if kind.is_empty() {
        return Err(Reject::Protocol("no type".into()));
    }
    let ts = env
        .get("ts")
        .and_then(|v| v.as_str())
        .and_then(parse_iso)
        .ok_or_else(|| Reject::Protocol("ts must be ISO-8601".into()))?;
    if ts < now - REPLAY_WINDOW_MS || ts > now + FUTURE_SKEW_MS {
        return Err(Reject::Stale);
    }
    Ok((id.to_string(), kind.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips() {
        for ms in [0, 1_792_288_241_000, 951_782_400_000 /* 2000-02-29 */] {
            assert_eq!(parse_iso(&iso(ms)), Some(ms));
        }
        assert_eq!(iso(1_792_288_241_000), "2026-10-18T01:50:41Z");
    }

    #[test]
    fn parse_takes_fractions_and_offsets() {
        let base = parse_iso("2026-10-18T22:10:00Z").unwrap();
        assert_eq!(parse_iso("2026-10-18T22:10:00.5Z"), Some(base + 500));
        assert_eq!(parse_iso("2026-10-18T15:10:00-07:00"), Some(base));
        assert_eq!(parse_iso("2026-10-18"), None);
        assert_eq!(parse_iso("2026-13-18T22:10:00Z"), None);
    }

    #[test]
    fn ulids_are_26_crockford_and_sort_by_time() {
        let a = ulid();
        assert_eq!(a.len(), 26);
        assert!(a.bytes().all(|c| CROCKFORD.contains(&c)));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(ulid()[..10] > a[..10]);
    }

    #[test]
    fn the_window_drops_old_and_future_envelopes() {
        let now = now_ms();
        let mut e = envelope("ping", json!({}));
        assert!(check(&e, now).is_ok());
        // A queued envelope from yesterday still arrives.
        e["ts"] = json!(iso(now - 24 * 3600 * 1000));
        assert!(check(&e, now).is_ok());
        e["ts"] = json!(iso(now - REPLAY_WINDOW_MS - 1000));
        assert_eq!(check(&e, now), Err(Reject::Stale));
        e["ts"] = json!(iso(now + FUTURE_SKEW_MS + 60_000));
        assert_eq!(check(&e, now), Err(Reject::Stale));
        e["v"] = json!(2);
        assert!(matches!(check(&e, now), Err(Reject::Protocol(_))));
    }
}
