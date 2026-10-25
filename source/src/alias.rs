//! Phone numbers never reach the model (DESIGN X12).
//!
//! Every number in what the model sees (tool results, events, the user's own
//! messages) becomes a stable handle for that phone pairing, `num:K7Q2 (…22)`,
//! and a handle in what the model sends (`send_sms` recipients, replies to the
//! phone) becomes the number again. So the provider never sees a number, and
//! Hermes's own redaction (which masks anything shaped like `+15550001111`
//! in tool output) has nothing to mask that the model would need back.

use serde_json::Value;
use std::collections::BTreeMap;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// handle ("K7Q2") → normalized number, for one pairing.
pub type Book = BTreeMap<String, String>;

/// `+1 (555) 000-2222` → `+15550002222`; `555.000.2222` → `5550002222`.
pub fn normalize(s: &str) -> Option<String> {
    let t = s.trim();
    let plus = t.starts_with('+');
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 7 || digits.len() > 15 {
        return None;
    }
    if !t.chars().all(|c| c.is_ascii_digit() || " +-().".contains(c)) {
        return None;
    }
    Some(if plus { format!("+{digits}") } else { digits })
}

fn new_handle(book: &Book) -> String {
    loop {
        let mut b = [0u8; 4];
        let _ = getrandom::getrandom(&mut b);
        let h: String = b.iter().map(|x| CROCKFORD[(*x & 31) as usize] as char).collect();
        if !book.contains_key(&h) {
            return h;
        }
    }
}

/// The handle for a number, minted on first sight.
pub fn handle_for(book: &mut Book, number: &str) -> Option<String> {
    let n = normalize(number)?;
    let h = match book.iter().find(|(_, v)| **v == n) {
        Some((h, _)) => h.clone(),
        None => {
            let h = new_handle(book);
            book.insert(h.clone(), n.clone());
            h
        }
    };
    let tail = &n[n.len().saturating_sub(2)..];
    Some(format!("num:{h} (…{tail})"))
}

/// `num:K7Q2`, `num:K7Q2 (…22)`, or a plain number → the number.
pub fn resolve(book: &Book, s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("num:") {
        let h: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        return book.get(&h.to_ascii_uppercase()).cloned();
    }
    normalize(t)
}

/// Is this char run a phone number in running text? `+` and 7–15 digits, or
/// 10–11 digits with the usual separators: (555) 000-2222, 555-000-2222.
fn number_spans(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let start_ok = (b[i] == b'+' || b[i] == b'(' || b[i].is_ascii_digit())
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'));
        if !start_ok {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut digits = 0;
        let mut last_digit = i;
        while j < b.len() && (b[j].is_ascii_digit() || b" -().+".contains(&b[j])) {
            if b[j] == b'+' && j != i {
                break;
            }
            if b[j].is_ascii_digit() {
                digits += 1;
                last_digit = j;
            }
            j += 1;
        }
        let end = last_digit + 1;
        let plus = b[i] == b'+';
        // 2026-10-18 22:10 is a date, not a number.
        let span = &text[i..end];
        let is_date = span.len() >= 10
            && span.as_bytes()[..10].iter().enumerate().all(|(k, c)| if k == 4 || k == 7 { *c == b'-' } else { c.is_ascii_digit() });
        if is_date {
            i = end;
            continue;
        }
        let followed_ok = end >= b.len() || !(b[end].is_ascii_alphanumeric());
        if followed_ok && ((plus && (7..=15).contains(&digits)) || (!plus && (10..=11).contains(&digits))) {
            out.push((i, end));
            i = end;
        } else {
            i = j.max(i + 1);
        }
    }
    out
}

/// Replace every number in running text with its handle.
pub fn hide_in_text(book: &mut Book, text: &str) -> String {
    let spans = number_spans(text);
    if spans.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in spans {
        out.push_str(&text[at..s]);
        match handle_for(book, &text[s..e]) {
            Some(h) => out.push_str(&h),
            None => out.push_str(&text[s..e]),
        }
        at = e;
    }
    out.push_str(&text[at..]);
    out
}

/// Every string in a JSON value: fields that hold a number are swapped
/// whole; any other text has the numbers inside it swapped.
pub fn hide(book: &mut Book, v: &mut Value) {
    match v {
        Value::String(s) => *s = hide_in_text(book, s),
        Value::Array(a) => a.iter_mut().for_each(|x| hide(book, x)),
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                // Ids and times are the phone's references, and `*_b64` is bytes
                // (a 5 MB recording can hold "+1" and ten digits): never touched.
                if k == "id" || k.ends_with("_id") || k.ends_with("_at") || k.ends_with("_b64")
                    || ["date", "ts", "at", "until", "since", "cursor", "next", "after"].contains(&k.as_str())
                {
                    continue;
                }
                if let (true, Value::String(s)) = (k == "number", &*x) {
                    if let Some(h) = handle_for(book, s) {
                        *x = Value::String(h);
                        continue;
                    }
                }
                hide(book, x);
            }
        }
        _ => {}
    }
}

/// Handles in text the model wrote for the user become numbers again.
pub fn reveal_in_text(book: &Book, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("num:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 4..];
        let h: String = after.chars().take_while(|c| c.is_ascii_alphanumeric()).take(4).collect();
        match book.get(&h.to_ascii_uppercase()) {
            Some(n) if h.len() == 4 => {
                out.push_str(n);
                let mut tail = &after[h.len()..];
                // Drop the "(…22)" hint that followed it, if the model kept it:
                // " (…22)", or ", …22" when it moved the handle into parentheses.
                if let Some(t) = tail.strip_prefix(" (…") {
                    if let Some(close) = t.find(')') {
                        if close <= 4 {
                            tail = &t[close + 1..];
                        }
                    }
                } else if let Some(t) = tail.strip_prefix(", …").or_else(|| tail.strip_prefix(" …")) {
                    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
                    if (1..=4).contains(&digits) {
                        tail = &t[digits..];
                    }
                }
                rest = tail;
            }
            _ => {
                out.push_str("num:");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_contacts_page_masks_numbers_but_not_cursors_or_times() {
        let mut b = Book::new();
        let mut v = serde_json::json!({"contacts": [{"id": "15550001111", "name": "Sam", "numbers": ["+15550002222"],
            "updated_at": "2026-10-19T20:00:00Z"}], "next": "15550001111"});
        hide(&mut b, &mut v);
        assert_eq!(v["next"], "15550001111");
        assert_eq!(v["contacts"][0]["id"], "15550001111");
        assert_eq!(v["contacts"][0]["updated_at"], "2026-10-19T20:00:00Z");
        assert!(v["contacts"][0]["numbers"][0].as_str().unwrap().starts_with("num:"), "{v}");
    }

    #[test]
    fn a_number_gets_one_stable_handle_whatever_its_format() {
        let mut b = Book::new();
        let a = handle_for(&mut b, "+1 (555) 000-2222").unwrap();
        let c = handle_for(&mut b, "+15550002222").unwrap();
        assert_eq!(a, c);
        assert!(a.starts_with("num:") && a.ends_with("(…22)"));
        assert_eq!(resolve(&b, &a).unwrap(), "+15550002222");
        assert_eq!(resolve(&b, &a[..8]).unwrap(), "+15550002222");
        assert_eq!(resolve(&b, "555-000-1111").unwrap(), "5550001111");
        assert!(resolve(&b, "num:ZZZZ").is_none());
        // Bytes are never read as numbers, however they look.
        let mut v = serde_json::json!({"audio_b64": "AAA/+15550002222BBB", "frames": [{"data_b64": "/5550001111"}]});
        let before = v.clone();
        hide(&mut b, &mut v);
        assert_eq!(v, before);
    }

    #[test]
    fn numbers_in_text_and_fields_are_hidden_and_come_back() {
        let mut b = Book::new();
        let mut v = json!({"from": {"name": "Mom", "number": "+15550002222"},
            "text": "call +15550001111 or (555) 000-3333, code 4821, at 7:30, total $1,250.00"});
        hide(&mut b, &mut v);
        let s = v.to_string();
        assert!(!s.contains("5550002222") && !s.contains("5550001111") && !s.contains("000-3333"), "{s}");
        assert!(s.contains("code 4821") && s.contains("7:30") && s.contains("1,250.00"), "{s}");
        let handle = v["from"]["number"].as_str().unwrap().to_string();
        let back = reveal_in_text(&b, &format!("Mom is {handle}."));
        assert_eq!(back, "Mom is +15550002222.");
        let h4 = &handle[..8];
        assert_eq!(reveal_in_text(&b, &format!("Mom ({h4}, …22): hi")), "Mom (+15550002222): hi");
    }

    #[test]
    fn dates_and_short_numbers_are_left_alone() {
        let mut b = Book::new();
        for t in ["2026-10-18T22:10:00Z", "2026-10-18 22:10", "order 123456", "pin 4821", "v0.22.2", "id abc5550002222"] {
            assert_eq!(hide_in_text(&mut b, t), t);
        }
        assert!(b.is_empty());
    }

    #[test]
    fn ids_and_times_are_never_aliased() {
        let mut b = Book::new();
        let mut v = json!({"message_id": "5550002222", "thread_id": "5550002223", "date": "5550002224",
            "numbers": ["5550002225"]});
        hide(&mut b, &mut v);
        assert_eq!(v["message_id"], "5550002222");
        assert_eq!(v["thread_id"], "5550002223");
        assert_eq!(v["date"], "5550002224");
        assert!(v["numbers"][0].as_str().unwrap().starts_with("num:"));
    }

    #[test]
    fn an_unknown_handle_is_left_as_written() {
        let b = Book::new();
        assert_eq!(reveal_in_text(&b, "see num:QQQQ"), "see num:QQQQ");
    }
}
