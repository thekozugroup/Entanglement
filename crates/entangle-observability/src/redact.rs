//! Secret redaction for everything the daemon keeps for operators to read
//! back: the log ring buffers ([`crate::logs`]) and the span store
//! ([`crate::traces`]).
//!
//! Nothing here can prove a string is not a secret; the rules aim at the
//! shapes secrets take in this code base and err towards redacting:
//!
//! * a **field name** that says what it holds (`token`, `secret`,
//!   `passphrase`, `password`, `authorization`, `bearer`, `api_key`,
//!   `cookie`, `credential`, `biscuit`, `private`, `pairing_code`, ...) has
//!   its whole value replaced;
//! * in **free text** (messages, stdout/stderr lines a plugin printed, field
//!   values), `Bearer <x>`, `Basic <x>`, `name=value` / `name: value` /
//!   `"name":"value"` pairs for the same names, the userinfo of a URL, PEM
//!   private-key blocks and long base64url runs that mix upper and lower
//!   case (the shape of a biscuit capability token) are replaced.
//!
//! Hex digests (a BLAKE3 hash, a key fingerprint) are lowercase-only and are
//! deliberately kept: operators need them to correlate.

use std::borrow::Cow;

/// What a redacted value is replaced with.
pub const REDACTED: &str = "[REDACTED]";

/// Substrings of a field or key name that mark its value as secret
/// (compared case-insensitively, `-` and `.` treated as `_`).
const SENSITIVE_NAMES: &[&str] = &[
    "token",
    "secret",
    "passphrase",
    "password",
    "passwd",
    "authorization",
    "bearer",
    "api_key",
    "apikey",
    "private",
    "cookie",
    "credential",
    "biscuit",
    "pairing_code",
    "pair_code",
    "passcode",
];

/// Shortest base64url run (letters, digits, `-`, `_`, `+`, `/`, `=`) that is
/// treated as a token when it mixes upper and lower case letters.
const MIN_TOKEN_RUN: usize = 40;

/// Whether `name` (a tracing field name or a `key` in free text) names a secret.
pub fn is_sensitive_name(name: &str) -> bool {
    let n: String = name
        .chars()
        .map(|c| match c {
            '-' | '.' | ' ' => '_',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    SENSITIVE_NAMES.iter().any(|s| n.contains(s))
}

/// The value to keep for field `name` holding `value`: the whole value is
/// [`REDACTED`] when the name is sensitive, else the text rules of
/// [`redact_text`] apply.
pub fn redact_field<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
    if is_sensitive_name(name) {
        Cow::Borrowed(REDACTED)
    } else {
        redact_text(value)
    }
}

/// Apply the free-text rules to `text`.
pub fn redact_text(text: &str) -> Cow<'_, str> {
    if text.contains("PRIVATE KEY") {
        return Cow::Borrowed("[REDACTED private key material]");
    }
    let chars: Vec<char> = text.chars().collect();
    let mut hide = vec![false; chars.len()];
    mark_bearer(&chars, &mut hide);
    mark_named_values(&chars, &mut hide);
    mark_url_userinfo(&chars, &mut hide);
    mark_token_runs(&chars, &mut hide);
    if !hide.iter().any(|h| *h) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if hide[i] {
            out.push_str(REDACTED);
            while i < chars.len() && hide[i] {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    Cow::Owned(out)
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn is_value_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, ',' | ';' | '&' | ')' | '}' | ']' | '"' | '\'')
}

fn starts_with_ci(chars: &[char], at: usize, word: &str) -> bool {
    word.chars().enumerate().all(|(k, w)| {
        chars
            .get(at + k)
            .is_some_and(|c| c.eq_ignore_ascii_case(&w))
    })
}

fn mark(hide: &mut [bool], from: usize, to: usize) {
    for h in &mut hide[from..to] {
        *h = true;
    }
}

/// `Bearer <x>` / `Basic <x>`: hide `<x>`.
fn mark_bearer(chars: &[char], hide: &mut [bool]) {
    for scheme in ["bearer ", "basic "] {
        let mut i = 0;
        while i < chars.len() {
            let boundary = i == 0 || !is_ident(chars[i - 1]);
            if boundary && starts_with_ci(chars, i, scheme) {
                let start = i + scheme.len();
                let mut end = start;
                while end < chars.len() && !is_value_end(chars[end]) {
                    end += 1;
                }
                if end > start {
                    mark(hide, start, end);
                }
                i = end.max(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

/// `name=value`, `name: value`, `"name":"value"` for a sensitive `name`.
fn mark_named_values(chars: &[char], hide: &mut [bool]) {
    let mut i = 0;
    while i < chars.len() {
        if !is_ident(chars[i]) || (i > 0 && is_ident(chars[i - 1])) {
            i += 1;
            continue;
        }
        // The identifier starting here.
        let mut name_end = i;
        while name_end < chars.len() && is_ident(chars[name_end]) {
            name_end += 1;
        }
        let name: String = chars[i..name_end].iter().collect();
        let mut j = name_end;
        // Optional closing quote of a quoted key, then spaces.
        if matches!(chars.get(j), Some('"' | '\'')) {
            j += 1;
        }
        while chars.get(j) == Some(&' ') {
            j += 1;
        }
        let sep = matches!(chars.get(j), Some('=' | ':'));
        if sep && is_sensitive_name(&name) {
            j += 1;
            while chars.get(j) == Some(&' ') {
                j += 1;
            }
            let quote = match chars.get(j) {
                Some(&q @ ('"' | '\'')) => {
                    j += 1;
                    Some(q)
                }
                _ => None,
            };
            let start = j;
            let mut end = j;
            while end < chars.len() {
                let c = chars[end];
                let stop = match quote {
                    Some(q) => c == q,
                    None => is_value_end(c),
                };
                if stop {
                    break;
                }
                end += 1;
            }
            // `authorization: Bearer xyz`: the scheme word then the credential.
            if quote.is_none() {
                let word: String = chars[start..end].iter().collect();
                if word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic") {
                    end += 1; // the space
                    while end < chars.len() && !is_value_end(chars[end]) {
                        end += 1;
                    }
                    end = end.min(chars.len());
                    mark(hide, start.min(end), end);
                    i = end.max(i + 1);
                    continue;
                }
            }
            if end > start {
                mark(hide, start, end);
            }
            i = end.max(i + 1);
        } else {
            i = name_end;
        }
    }
}

/// `scheme://user:password@host/`: hide `user:password`.
fn mark_url_userinfo(chars: &[char], hide: &mut [bool]) {
    let mut i = 0;
    while i + 2 < chars.len() {
        if chars[i] == ':' && chars[i + 1] == '/' && chars[i + 2] == '/' {
            let start = i + 3;
            let mut end = start;
            while end < chars.len()
                && !matches!(chars[end], '/' | '?' | '#')
                && !chars[end].is_whitespace()
            {
                end += 1;
            }
            if let Some(at) = chars[start..end].iter().rposition(|c| *c == '@') {
                if at > 0 {
                    mark(hide, start, start + at);
                }
            }
            i = end.max(i + 3);
        } else {
            i += 1;
        }
    }
}

/// Long base64url runs mixing upper and lower case.
fn mark_token_runs(chars: &[char], hide: &mut [bool]) {
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=');
    let mut i = 0;
    while i < chars.len() {
        if !is_b64(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_b64(chars[i]) {
            i += 1;
        }
        let run = &chars[start..i];
        if run.len() >= MIN_TOKEN_RUN
            && run.iter().any(|c| c.is_ascii_uppercase())
            && run.iter().any(|c| c.is_ascii_lowercase())
            && run
                .iter()
                .any(|c| c.is_ascii_digit() || matches!(c, '-' | '_' | '+' | '/'))
        {
            mark(hide, start, i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_field_names() {
        for n in [
            "token",
            "capability_token",
            "bearer_token",
            "Authorization",
            "api-key",
            "passphrase",
            "client_secret",
            "biscuit",
            "pairing_code",
            "private_key",
        ] {
            assert!(is_sensitive_name(n), "{n}");
            assert_eq!(redact_field(n, "hunter2"), REDACTED);
        }
        for n in [
            "plugin",
            "capability",
            "error_code",
            "peer",
            "bytes",
            "event",
        ] {
            assert!(!is_sensitive_name(n), "{n}");
            assert_eq!(redact_field(n, "x"), "x");
        }
    }

    #[test]
    fn bearer_and_named_pairs_in_text() {
        assert_eq!(
            redact_text("calling with Authorization: Bearer abc.def-ghi done"),
            "calling with Authorization: [REDACTED] done"
        );
        assert_eq!(
            redact_text("login failed password=hunter2 user=bob"),
            "login failed password=[REDACTED] user=bob"
        );
        assert_eq!(
            redact_text(r#"{"token":"abc123","n":1}"#),
            r#"{"token":"[REDACTED]","n":1}"#
        );
        assert_eq!(
            redact_text("passphrase: correct horse"),
            "passphrase: [REDACTED] horse"
        );
    }

    #[test]
    fn url_userinfo_and_private_keys() {
        assert_eq!(
            redact_text("pulling https://alice:s3cr3t@registry.example/v2/x"),
            "pulling https://[REDACTED]@registry.example/v2/x"
        );
        assert_eq!(
            redact_text("-----BEGIN PRIVATE KEY-----\nMC4CAQ\n-----END PRIVATE KEY-----"),
            "[REDACTED private key material]"
        );
        assert_eq!(
            redact_text("https://registry.example/v2/x"),
            "https://registry.example/v2/x"
        );
    }

    #[test]
    fn long_mixed_case_runs_are_redacted_but_hex_digests_are_kept() {
        let biscuit =
            "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBqS1x3wB9pQ-mVf2Zr7nLo4uYtHkDeP8sXcAaNbQ0zWyI=";
        let input = format!("granted token-less cap {biscuit} ok");
        let out = redact_text(&input);
        assert!(!out.contains("En0KEwoE"), "{out}");
        assert!(out.contains(REDACTED));
        let hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(redact_text(hash), hash);
        let fp = "aabbccddeeff00112233445566778899/hello@0.1.0";
        assert_eq!(redact_text(fp), fp);
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        let s = "plugin loaded in 12ms";
        assert!(matches!(redact_text(s), Cow::Borrowed(_)));
    }
}
