//! Secret redaction for everything the daemon keeps for operators to read
//! back: the log ring buffers ([`crate::logs`]) and the span store
//! ([`crate::traces`]).
//!
//! Nothing here can prove a string is not a secret; the rules aim at the
//! shapes secrets take in this code base and err towards redacting:
//!
//! * a **field name** that says what it holds (`token`, `secret`,
//!   `passphrase`, `password`, `authorization`, `bearer`, `api_key`,
//!   `cookie`, `credential`, `biscuit`, `private`, `pairing_code`, `seed`,
//!   ...), or names a key (`key`, `signing_key`, `privkey`: a `_`-separated
//!   part ending in `key`, unless another part says it is public material or
//!   an identifier: `public_key`, `pubkey`, `key_fingerprint`, `key_id`), has
//!   its whole value replaced;
//! * in **free text** (messages, stdout/stderr lines a plugin printed, field
//!   values), `Bearer <x>`, `Basic <x>`, `name=value` / `name: value` /
//!   `"name":"value"` pairs for the same names, the userinfo of a URL, PEM
//!   private-key blocks and long base64url runs that mix upper and lower
//!   case (the shape of a biscuit capability token) are replaced. A value in
//!   a Debug or JSON shape — `Some("…")`, `Secret(…)`, `Token { … }`,
//!   `[10, 125, …]` — is replaced through its matching close bracket. A long
//!   hex run right after a sensitive word (`gateway token 3f2a…`, the shape
//!   of this code base's capability and bearer tokens) is replaced too.
//!
//! Hex digests (a BLAKE3 hash, a key fingerprint) are lowercase-only and are
//! deliberately kept when no sensitive word introduces them: operators need
//! them to correlate.

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
    "seed",
];

/// Parts of a `..key` name (split on `_`) that make it public material or an
/// identifier rather than a secret key.
const PUBLIC_KEY_PARTS: &[&str] = &["public", "pub", "pubkey", "publickey", "fingerprint", "id"];

/// Shortest hex run treated as a secret when a sensitive word introduces it
/// (capability tokens are hex-encoded protobuf; gateway bearer tokens are 64
/// hex digits).
const MIN_HEX_SECRET: usize = 32;

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
    SENSITIVE_NAMES.iter().any(|s| n.contains(s)) || names_a_secret_key(&n)
}

/// `key`, `signing_key`, `privkey` — but not `public_key`, `pubkey`,
/// `key_fingerprint`, `key_id`, `keyring`. `n` is already normalised.
fn names_a_secret_key(n: &str) -> bool {
    let mut keyish = false;
    for part in n.split('_').filter(|p| !p.is_empty()) {
        if PUBLIC_KEY_PARTS.contains(&part) {
            return false;
        }
        keyish |= part.ends_with("key");
    }
    keyish
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
    mark_hex_after_secret_word(&chars, &mut hide);
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
            // `Some("…")`, `Secret(…)`, `[10, 125, …]`: the whole value.
            if quote.is_none() {
                if let Some(close) = bracketed_value_end(chars, j) {
                    mark(hide, j, close);
                    i = close.max(i + 1);
                    continue;
                }
            }
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

/// When the value at `at` has a Debug or JSON shape — `Some(…)`,
/// `Secret(…)`, `Token { … }`, `[…]`, `(…)`, `{…}` — the index just past its
/// matching close bracket, or the end of `chars` when it is never closed (a
/// clipped line: everything after the name is hidden).
fn bracketed_value_end(chars: &[char], at: usize) -> Option<usize> {
    let mut k = at;
    while k < chars.len() && (chars[k].is_ascii_alphanumeric() || chars[k] == '_') {
        k += 1;
    }
    let open = match chars.get(k) {
        Some('(' | '[' | '{') => k,
        // `Token { … }`
        Some(' ') if k > at => {
            let mut m = k;
            while chars.get(m) == Some(&' ') {
                m += 1;
            }
            if chars.get(m) != Some(&'{') {
                return None;
            }
            m
        }
        _ => return None,
    };
    let mut depth = 0usize;
    let mut in_string = false;
    let mut i = open;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            match c {
                '\\' => i += 1,
                '"' => in_string = false,
                _ => {}
            }
        } else {
            match c {
                '"' => in_string = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    Some(chars.len())
}

/// `gateway token 3f2a…`, `bearer token: 3f2a…`: a hex run of at least
/// [`MIN_HEX_SECRET`] digits right after a sensitive word, with only a few
/// separators (spaces, `:`, `=`, quotes, `(`) between.
fn mark_hex_after_secret_word(chars: &[char], hide: &mut [bool]) {
    let mut i = 0;
    while i < chars.len() {
        if !is_ident(chars[i]) || (i > 0 && is_ident(chars[i - 1])) {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < chars.len() && is_ident(chars[end]) {
            end += 1;
        }
        let word: String = chars[i..end].iter().collect();
        if is_sensitive_name(&word) {
            let mut j = end;
            while j < chars.len()
                && j - end < 4
                && (chars[j] == ' ' || matches!(chars[j], ':' | '=' | '"' | '\'' | '('))
            {
                j += 1;
            }
            let start = j;
            while j < chars.len() && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            let whole_run = j == chars.len() || !is_ident(chars[j]);
            if j - start >= MIN_HEX_SECRET && whole_run {
                mark(hide, start, j);
            }
        }
        i = end;
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

    /// The hex shape of this code base's textual secrets: capability tokens
    /// (`grant::to_hex`) and gateway bearer tokens (64 hex).
    const HEX_TOKEN: &str = "0a7d0a1308f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091";

    #[test]
    fn debug_shaped_values_after_a_sensitive_name_are_hidden_whole() {
        for text in [
            format!(r#"Peer {{ name: "laptop", capability_token: Some("{HEX_TOKEN}") }}"#),
            format!(r#"Accept {{ capability_token_hex: Some("{HEX_TOKEN}"), peer: 1 }}"#),
            format!("token=Secret(\"{HEX_TOKEN}\") rest"),
            format!("token: Some(Token {{ bytes: \"{HEX_TOKEN}\", n: (1, 2) }})"),
        ] {
            let out = redact_text(&text);
            assert!(!out.contains(&HEX_TOKEN[..12]), "{text} -> {out}");
            assert!(out.contains(REDACTED), "{out}");
        }
        let bytes = "Cfg { api_key: Some([10, 125, 33, 47]), n: 2 }";
        assert_eq!(redact_text(bytes), "Cfg { api_key: [REDACTED], n: 2 }");
        // What follows the value is kept.
        assert_eq!(
            redact_text(r#"Peer { name: "laptop", capability_token: Some("abc"), port: 7 }"#),
            r#"Peer { name: "laptop", capability_token: [REDACTED], port: 7 }"#
        );
        // An unclosed value hides everything after the name.
        assert_eq!(
            redact_text("password: Some(\"hunter2"),
            "password: [REDACTED]"
        );
    }

    #[test]
    fn hex_tokens_after_a_secret_word_and_key_or_seed_names_are_hidden() {
        for text in [
            format!("gateway token {HEX_TOKEN}"),
            format!("issued bearer token: {HEX_TOKEN} to client"),
            format!("signing_key={HEX_TOKEN}"),
            format!("seed: {HEX_TOKEN}"),
            format!("{{\"secret_key\":\"{HEX_TOKEN}\"}}"),
        ] {
            let out = redact_text(&text);
            assert!(!out.contains(&HEX_TOKEN[..12]), "{text} -> {out}");
        }
        for n in [
            "signing_key",
            "key",
            "secretKey",
            "seed",
            "rng_seed",
            "privkey",
        ] {
            assert!(is_sensitive_name(n), "{n}");
        }
        // Public material and identifiers of keys stay readable.
        for n in [
            "public_key",
            "public_key_hex",
            "pubkey",
            "key_fingerprint",
            "key_id",
            "keyring",
        ] {
            assert!(!is_sensitive_name(n), "{n}");
        }
        // A digest that no secret word introduces is still kept.
        let digest = format!("artifact blake3 {HEX_TOKEN} verified");
        assert_eq!(redact_text(&digest), digest);
        assert_eq!(
            redact_text(&format!("public_key={HEX_TOKEN}")),
            format!("public_key={HEX_TOKEN}")
        );
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        let s = "plugin loaded in 12ms";
        assert!(matches!(redact_text(s), Cow::Borrowed(_)));
    }
}
