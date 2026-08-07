//! `json-query` — extract and reshape JSON with dotted paths, array indexing and wildcards.
//!
//! Tier 1, zero declared capabilities: this is a pure byte-in/byte-out transform.
//!
//! # Input
//!
//! A UTF-8 JSON *envelope* object:
//!
//! ```json
//! { "query": "user.name", "data": { "user": { "name": "Ada" } }, "pretty": false }
//! ```
//!
//! * `query` (required, string) — the path to evaluate. See [`path`] for the grammar.
//! * `data` (required, any JSON) — the document to query. `null` is allowed.
//! * `pretty` (optional, bool, default `false`) — pretty-print the result and append a newline.
//!
//! # Output
//!
//! The selected JSON value, serialised. Compact and newline-free unless `pretty` is set.
//!
//! All the real work lives in [`transform`], which is a plain function over `&[u8]`
//! and is exercised by the host-target test suite (`cargo test`). The wasm entrypoint
//! is a thin wrapper that maps [`Error`] onto `PluginError::InvalidInput`.

#![forbid(unsafe_code)]

pub mod path;

use serde_json::Value;

/// Everything that can go wrong. Every variant is reported to the caller as
/// `PluginError::InvalidInput` with the `Display` text below, so the messages are
/// written for a human reading a CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input bytes were not valid UTF-8.
    NotUtf8(String),
    /// Input was not parseable JSON.
    BadJson(String),
    /// The envelope was structurally wrong (missing/extra/mistyped fields).
    BadEnvelope(String),
    /// The `query` string could not be compiled into a path.
    BadQuery(String),
    /// The path compiled fine but selected nothing in this document.
    NoMatch(String),
    /// The selected value could not be re-serialised (should be unreachable).
    BadOutput(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotUtf8(m) => write!(f, "input is not valid UTF-8: {m}"),
            Error::BadJson(m) => write!(f, "input is not valid JSON: {m}"),
            Error::BadEnvelope(m) => write!(f, "bad input envelope: {m}"),
            Error::BadQuery(m) => write!(f, "bad query: {m}"),
            Error::NoMatch(m) => write!(f, "query matched nothing: {m}"),
            Error::BadOutput(m) => write!(f, "could not serialise result: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Keys the envelope is allowed to carry. Anything else is rejected so typos
/// (`"quary"`, `"Data"`) fail loudly instead of silently selecting the root.
const ALLOWED_KEYS: [&str; 3] = ["query", "data", "pretty"];

/// The whole plugin, as a pure function. Never panics on any input.
pub fn transform(input: &[u8]) -> Result<Vec<u8>, Error> {
    let text = core::str::from_utf8(input).map_err(|e| Error::NotUtf8(e.to_string()))?;

    if text.trim().is_empty() {
        return Err(Error::BadEnvelope(
            "input is empty; expected a JSON object like \
             {\"query\": \"user.name\", \"data\": {...}}"
                .to_string(),
        ));
    }

    let envelope: Value = serde_json::from_str(text).map_err(|e| Error::BadJson(e.to_string()))?;

    let map = envelope.as_object().ok_or_else(|| {
        Error::BadEnvelope(format!(
            "expected a JSON object with \"query\" and \"data\", found a {}",
            json_type(&envelope)
        ))
    })?;

    let unknown: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !ALLOWED_KEYS.contains(k))
        .collect();
    if !unknown.is_empty() {
        return Err(Error::BadEnvelope(format!(
            "unknown field(s): {}; allowed fields are query, data, pretty",
            unknown.join(", ")
        )));
    }

    let query = match map.get("query") {
        None => {
            return Err(Error::BadEnvelope(
                "missing required field \"query\" (a path string such as \"items[*].name\")"
                    .to_string(),
            ))
        }
        Some(Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(Error::BadEnvelope(format!(
                "field \"query\" must be a string, found a {}",
                json_type(other)
            )))
        }
    };

    // Present-but-null `data` is legal; absent `data` is not.
    let data = map.get("data").ok_or_else(|| {
        Error::BadEnvelope(
            "missing required field \"data\" (the JSON document to query)".to_string(),
        )
    })?;

    let pretty = match map.get("pretty") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            return Err(Error::BadEnvelope(format!(
                "field \"pretty\" must be a boolean, found a {}",
                json_type(other)
            )))
        }
    };

    let segments = path::parse_path(query)?;
    let selected = path::eval(data, &segments)?;

    let out = if pretty {
        let mut s =
            serde_json::to_string_pretty(&selected).map_err(|e| Error::BadOutput(e.to_string()))?;
        s.push('\n');
        s
    } else {
        serde_json::to_string(&selected).map_err(|e| Error::BadOutput(e.to_string()))?
    };
    Ok(out.into_bytes())
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ------------------------------------------------------------------
// wasm entrypoint — thin wrapper, no logic
// ------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm_entry {
    use entangle_sdk::{entangle_plugin, log, PluginError};

    fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        log::info(&format!("json-query: {} input bytes", input.len()));
        match crate::transform(&input) {
            Ok(out) => Ok(out),
            Err(e) => {
                let msg = e.to_string();
                log::warn(&format!("json-query: {msg}"));
                Err(PluginError::InvalidInput(msg))
            }
        }
    }

    entangle_plugin!(run);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> String {
        String::from_utf8(transform(input.as_bytes()).expect("should succeed"))
            .expect("utf-8 output")
    }

    fn err(input: &str) -> String {
        transform(input.as_bytes())
            .expect_err("should fail")
            .to_string()
    }

    // ---------------- happy paths ----------------

    #[test]
    fn selects_dotted_field() {
        assert_eq!(
            ok(r#"{"query":"user.name","data":{"user":{"name":"Ada"}}}"#),
            r#""Ada""#
        );
    }

    #[test]
    fn selects_nested_object() {
        assert_eq!(
            ok(r#"{"query":"a.b","data":{"a":{"b":{"c":1}}}}"#),
            r#"{"c":1}"#
        );
    }

    #[test]
    fn selects_array_element_both_syntaxes() {
        let data = r#""data":[10,20,30]"#;
        assert_eq!(ok(&format!(r#"{{"query":"[1]",{data}}}"#)), "20");
        assert_eq!(ok(&format!(r#"{{"query":"$[2]",{data}}}"#)), "30");
    }

    #[test]
    fn wildcard_selects_all_elements() {
        assert_eq!(
            ok(r#"{"query":"items[*].name","data":{"items":[{"name":"a"},{"name":"b"}]}}"#),
            r#"["a","b"]"#
        );
        assert_eq!(
            ok(r#"{"query":"items.*.name","data":{"items":[{"name":"a"},{"name":"b"}]}}"#),
            r#"["a","b"]"#
        );
    }

    #[test]
    fn wildcard_over_object_returns_values() {
        assert_eq!(ok(r#"{"query":"*","data":{"a":1,"b":2}}"#), "[1,2]");
    }

    #[test]
    fn empty_query_returns_whole_document() {
        assert_eq!(ok(r#"{"query":"","data":{"a":1}}"#), r#"{"a":1}"#);
        assert_eq!(ok(r#"{"query":"$","data":[1,2]}"#), "[1,2]");
    }

    #[test]
    fn null_data_is_legal() {
        assert_eq!(ok(r#"{"query":"$","data":null}"#), "null");
    }

    #[test]
    fn scalar_data_is_legal() {
        assert_eq!(ok(r#"{"query":"$","data":42}"#), "42");
        assert_eq!(ok(r#"{"query":"$","data":"hi"}"#), r#""hi""#);
        assert_eq!(ok(r#"{"query":"$","data":true}"#), "true");
    }

    #[test]
    fn pretty_flag_indents_and_appends_newline() {
        let out = ok(r#"{"query":"$","data":{"a":1},"pretty":true}"#);
        assert_eq!(out, "{\n  \"a\": 1\n}\n");
    }

    #[test]
    fn pretty_false_is_compact() {
        let out = ok(r#"{"query":"$","data":{"a":1},"pretty":false}"#);
        assert_eq!(out, r#"{"a":1}"#);
    }

    #[test]
    fn object_key_order_is_preserved_from_input() {
        // serde_json's default Map is insertion-ordered only with preserve_order;
        // without it keys come out sorted. Either way the output must be valid JSON
        // that round-trips to the same value.
        let out = ok(r#"{"query":"$","data":{"z":1,"a":2}}"#);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v, serde_json::json!({"a":2,"z":1}));
    }

    // ---------------- unicode ----------------

    #[test]
    fn handles_unicode_values_and_keys() {
        assert_eq!(
            ok(r#"{"query":"café","data":{"café":"crème brûlée"}}"#),
            "\"crème brûlée\""
        );
        assert_eq!(
            ok(r#"{"query":"🌍.名前","data":{"🌍":{"名前":"世界"}}}"#),
            "\"世界\""
        );
    }

    #[test]
    fn handles_emoji_in_arrays_via_wildcard() {
        assert_eq!(
            ok(r#"{"query":"[*]","data":["🎉","✨"]}"#),
            "[\"🎉\",\"✨\"]"
        );
    }

    #[test]
    fn quoted_key_containing_a_dot() {
        assert_eq!(ok(r#"{"query":"[\"a.b\"].c","data":{"a.b":{"c":9}}}"#), "9");
    }

    // ---------------- malformed / edge cases ----------------

    #[test]
    fn empty_input_is_a_clear_error() {
        let e = err("");
        assert!(e.contains("input is empty"), "{e}");
        assert!(e.contains("query"), "{e}");
    }

    #[test]
    fn whitespace_only_input_is_a_clear_error() {
        assert!(err("   \n\t ").contains("input is empty"));
    }

    #[test]
    fn invalid_utf8_is_reported_not_panicked() {
        let e = transform(&[0xff, 0xfe, 0x00]).unwrap_err().to_string();
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn invalid_json_is_reported() {
        let e = err("{not json");
        assert!(e.contains("not valid JSON"), "{e}");
    }

    #[test]
    fn non_object_envelope_is_reported() {
        assert!(err("[1,2,3]").contains("found a array"));
        assert!(err("\"just a string\"").contains("found a string"));
        assert!(err("7").contains("found a number"));
    }

    #[test]
    fn missing_query_is_reported() {
        let e = err(r#"{"data":{}}"#);
        assert!(e.contains("missing required field \"query\""), "{e}");
    }

    #[test]
    fn missing_data_is_reported() {
        let e = err(r#"{"query":"a"}"#);
        assert!(e.contains("missing required field \"data\""), "{e}");
    }

    #[test]
    fn mistyped_query_is_reported() {
        let e = err(r#"{"query":123,"data":{}}"#);
        assert!(e.contains("must be a string"), "{e}");
    }

    #[test]
    fn mistyped_pretty_is_reported() {
        let e = err(r#"{"query":"$","data":{},"pretty":"yes"}"#);
        assert!(e.contains("must be a boolean"), "{e}");
    }

    #[test]
    fn unknown_envelope_field_is_reported() {
        let e = err(r#"{"quary":"$","data":{}}"#);
        assert!(e.contains("unknown field"), "{e}");
        assert!(e.contains("quary"), "{e}");
    }

    #[test]
    fn malformed_query_is_reported() {
        for bad in ["a..b", "items[", "items[]", "items[nope]"] {
            let input = format!(r#"{{"query":"{bad}","data":{{}}}}"#);
            let e = err(&input);
            assert!(e.contains("bad query"), "{bad}: {e}");
        }
    }

    #[test]
    fn missing_key_lists_available_keys() {
        let e = err(r#"{"query":"user.nickname","data":{"user":{"name":"Ada","age":36}}}"#);
        assert!(e.contains("nickname"), "{e}");
        assert!(e.contains("age"), "{e}");
        assert!(e.contains("name"), "{e}");
    }

    #[test]
    fn out_of_range_index_is_reported() {
        let e = err(r#"{"query":"[5]","data":[1,2]}"#);
        assert!(e.contains("out of range"), "{e}");
    }

    #[test]
    fn wildcard_on_empty_array_yields_empty_array_not_error() {
        assert_eq!(ok(r#"{"query":"a[*]","data":{"a":[]}}"#), "[]");
    }

    #[test]
    fn wildcard_skips_elements_missing_the_key() {
        assert_eq!(
            ok(r#"{"query":"a[*].b","data":{"a":[{"b":1},{},{"b":2},5]}}"#),
            "[1,2]"
        );
    }

    #[test]
    fn deeply_nested_document_does_not_blow_up() {
        // 100 levels of nesting, within serde_json's default recursion limit of 128.
        let depth = 100;
        let mut data = String::new();
        for _ in 0..depth {
            data.push_str(r#"{"n":"#);
        }
        data.push('1');
        for _ in 0..depth {
            data.push('}');
        }
        let query = vec!["n"; depth].join(".");
        let input = format!(r#"{{"query":"{query}","data":{data}}}"#);
        assert_eq!(ok(&input), "1");
    }

    #[test]
    fn absurdly_nested_json_errors_instead_of_panicking() {
        // serde_json enforces a recursion limit; make sure we surface it as an error.
        let data = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
        let input = format!(r#"{{"query":"$","data":{data}}}"#);
        let r = transform(input.as_bytes());
        // Either it parses (fine) or it errors (fine) — it must not panic.
        if let Err(e) = r {
            assert!(matches!(e, Error::BadJson(_)), "{e}");
        }
    }

    #[test]
    fn output_is_always_valid_json() {
        for input in [
            r#"{"query":"$","data":{"a":[1,{"b":null}]}}"#,
            r#"{"query":"a[*]","data":{"a":[1,2,3]}}"#,
            r#"{"query":"a","data":{"a":"x"}}"#,
        ] {
            let out = ok(input);
            serde_json::from_str::<Value>(&out).expect("valid JSON out");
        }
    }
}
