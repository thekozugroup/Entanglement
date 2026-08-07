//! Path parsing and evaluation for `json-query`.
//!
//! Grammar (whitespace around brackets is ignored):
//!
//! ```text
//! path     := '$'? first? rest*
//! first    := name | bracket
//! rest     := '.' name | '.' bracket | bracket
//! bracket  := '[' ( integer | '*' | '"' key '"' | '\'' key '\'' ) ']'
//! name     := any run of characters except '.' and '['   ("*" means wildcard)
//! ```
//!
//! Everything here is pure and unit-tested on the host target — no wasm needed.

use serde_json::Value;

use crate::Error;

/// One step of a compiled query path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Look up an object key.
    Key(String),
    /// Index into an array.
    Index(usize),
    /// Fan out over every element of an array (or every value of an object).
    Wildcard,
}

impl Segment {
    fn render(&self) -> String {
        match self {
            Segment::Key(k) => format!(".{k}"),
            Segment::Index(i) => format!("[{i}]"),
            Segment::Wildcard => "[*]".to_string(),
        }
    }
}

/// Render `$` + the first `n` segments, for error messages.
fn render_prefix(segs: &[Segment], n: usize) -> String {
    let mut out = String::from("$");
    for s in segs.iter().take(n) {
        out.push_str(&s.render());
    }
    out
}

/// Human-readable JSON type name, for error messages.
fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Compile a query string into a segment list.
///
/// An empty query (or `"$"`) compiles to zero segments, i.e. "the whole document".
pub fn parse_path(query: &str) -> Result<Vec<Segment>, Error> {
    let chars: Vec<char> = query.trim().chars().collect();
    let mut i = 0usize;
    let mut segs = Vec::new();

    // Optional leading `$`.
    if chars.first() == Some(&'$') {
        i += 1;
    }

    let mut first = true;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                if chars.get(i) == Some(&'[') {
                    segs.push(parse_bracket(&chars, &mut i, query)?);
                } else {
                    segs.push(parse_name(&chars, &mut i, query)?);
                }
            }
            '[' => segs.push(parse_bracket(&chars, &mut i, query)?),
            _ if first => segs.push(parse_name(&chars, &mut i, query)?),
            c => {
                return Err(Error::BadQuery(format!(
                    "unexpected character {c:?} at position {i} in query {query:?}; \
                     path segments are separated by '.' or written as '[...]'"
                )))
            }
        }
        first = false;
    }

    Ok(segs)
}

/// Parse a bare `name` segment starting at `*i` (which must not be `.` or `[`).
fn parse_name(chars: &[char], i: &mut usize, query: &str) -> Result<Segment, Error> {
    let start = *i;
    while *i < chars.len() && chars[*i] != '.' && chars[*i] != '[' {
        *i += 1;
    }
    let name: String = chars[start..*i].iter().collect();
    if name.is_empty() {
        return Err(Error::BadQuery(format!(
            "empty path segment at position {start} in query {query:?}; \
             use [\"\"] if you really mean the empty-string key"
        )));
    }
    if name == "*" {
        return Ok(Segment::Wildcard);
    }
    Ok(Segment::Key(name))
}

/// Parse a `[...]` segment; `*i` points at the opening `[`.
fn parse_bracket(chars: &[char], i: &mut usize, query: &str) -> Result<Segment, Error> {
    debug_assert_eq!(chars[*i], '[');
    let open = *i;
    *i += 1;
    while chars.get(*i).is_some_and(|c| c.is_whitespace()) {
        *i += 1;
    }
    let seg = match chars.get(*i) {
        None => {
            return Err(Error::BadQuery(format!(
                "unterminated '[' at position {open} in query {query:?}"
            )))
        }
        Some('*') => {
            *i += 1;
            Segment::Wildcard
        }
        Some(q @ ('"' | '\'')) => {
            let quote = *q;
            *i += 1;
            let mut key = String::new();
            loop {
                match chars.get(*i) {
                    None => {
                        return Err(Error::BadQuery(format!(
                            "unterminated quoted key starting at position {open} in query {query:?}"
                        )))
                    }
                    Some('\\') => {
                        *i += 1;
                        match chars.get(*i) {
                            Some(c) => {
                                key.push(*c);
                                *i += 1;
                            }
                            None => {
                                return Err(Error::BadQuery(format!(
                                    "query {query:?} ends with a dangling backslash escape"
                                )))
                            }
                        }
                    }
                    Some(c) if *c == quote => {
                        *i += 1;
                        break;
                    }
                    Some(c) => {
                        key.push(*c);
                        *i += 1;
                    }
                }
            }
            Segment::Key(key)
        }
        Some(c) if c.is_ascii_digit() => {
            let start = *i;
            while chars.get(*i).is_some_and(|c| c.is_ascii_digit()) {
                *i += 1;
            }
            let digits: String = chars[start..*i].iter().collect();
            let idx = digits.parse::<usize>().map_err(|_| {
                Error::BadQuery(format!(
                    "array index {digits:?} in query {query:?} is too large"
                ))
            })?;
            Segment::Index(idx)
        }
        Some(c) => {
            return Err(Error::BadQuery(format!(
                "invalid character {c:?} inside '[...]' at position {i} in query {query:?}; \
                 expected a number, '*', or a quoted key"
            )))
        }
    };
    while chars.get(*i).is_some_and(|c| c.is_whitespace()) {
        *i += 1;
    }
    match chars.get(*i) {
        Some(']') => {
            *i += 1;
            Ok(seg)
        }
        _ => Err(Error::BadQuery(format!(
            "missing ']' for the '[' at position {open} in query {query:?}"
        ))),
    }
}

/// Evaluate a compiled path against `root`.
///
/// * A path with no [`Segment::Wildcard`] selects exactly one value; a missing key
///   or out-of-range index is an error (the caller asked for something specific).
/// * A path containing a wildcard always yields a JSON array. Once fanned out,
///   values that do not have the requested key/index are silently skipped rather
///   than failing the whole query.
pub fn eval(root: &Value, segs: &[Segment]) -> Result<Value, Error> {
    let mut current: Vec<&Value> = vec![root];
    let mut fanned = false;

    for (n, seg) in segs.iter().enumerate() {
        let mut next: Vec<&Value> = Vec::new();
        match seg {
            Segment::Key(k) => {
                for v in &current {
                    match v {
                        Value::Object(map) => match map.get(k) {
                            Some(child) => next.push(child),
                            None if fanned => {}
                            None => {
                                let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
                                keys.sort_unstable();
                                let hint = if keys.is_empty() {
                                    "the object is empty".to_string()
                                } else {
                                    format!("available keys: {}", keys.join(", "))
                                };
                                return Err(Error::NoMatch(format!(
                                    "{} has no key {k:?} ({hint})",
                                    render_prefix(segs, n)
                                )));
                            }
                        },
                        other if fanned => {
                            let _ = other; // skipped: fanned-out non-objects
                        }
                        other => {
                            return Err(Error::NoMatch(format!(
                                "cannot read key {k:?}: {} is a {}, not an object",
                                render_prefix(segs, n),
                                type_name(other)
                            )));
                        }
                    }
                }
            }
            Segment::Index(idx) => {
                for v in &current {
                    match v {
                        Value::Array(arr) => match arr.get(*idx) {
                            Some(child) => next.push(child),
                            None if fanned => {}
                            None => {
                                return Err(Error::NoMatch(format!(
                                    "index {idx} is out of range: {} has {} element(s)",
                                    render_prefix(segs, n),
                                    arr.len()
                                )));
                            }
                        },
                        other if fanned => {
                            let _ = other;
                        }
                        other => {
                            return Err(Error::NoMatch(format!(
                                "cannot index [{idx}]: {} is a {}, not an array",
                                render_prefix(segs, n),
                                type_name(other)
                            )));
                        }
                    }
                }
            }
            Segment::Wildcard => {
                for v in &current {
                    match v {
                        Value::Array(arr) => next.extend(arr.iter()),
                        Value::Object(map) => next.extend(map.values()),
                        other if fanned => {
                            let _ = other;
                        }
                        other => {
                            return Err(Error::NoMatch(format!(
                                "cannot expand '*': {} is a {}, not an array or object",
                                render_prefix(segs, n),
                                type_name(other)
                            )));
                        }
                    }
                }
                fanned = true;
            }
        }
        current = next;
    }

    if fanned {
        Ok(Value::Array(current.into_iter().cloned().collect()))
    } else {
        // Non-wildcard paths always keep exactly one value alive (or error above).
        match current.into_iter().next() {
            Some(v) => Ok(v.clone()),
            None => Err(Error::NoMatch(format!(
                "{} matched nothing",
                render_prefix(segs, segs.len())
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(q: &str) -> Vec<Segment> {
        parse_path(q).expect("should parse")
    }

    fn key(k: &str) -> Segment {
        Segment::Key(k.to_string())
    }

    #[test]
    fn parses_empty_and_root() {
        assert_eq!(p(""), vec![]);
        assert_eq!(p("$"), vec![]);
        assert_eq!(p("   "), vec![]);
        // A trailing dot is *not* tolerated — see `rejects_malformed_paths`.
        assert!(parse_path("$.").is_err());
    }

    #[test]
    fn parses_dotted_paths() {
        assert_eq!(p("user"), vec![key("user")]);
        assert_eq!(p("user.name"), vec![key("user"), key("name")]);
        assert_eq!(p("$.user.name"), vec![key("user"), key("name")]);
    }

    #[test]
    fn parses_indices_both_syntaxes() {
        assert_eq!(p("items[0]"), vec![key("items"), Segment::Index(0)]);
        assert_eq!(p("items.0"), vec![key("items"), key("0")]);
        assert_eq!(p("[2]"), vec![Segment::Index(2)]);
        assert_eq!(p("[ 12 ]"), vec![Segment::Index(12)]);
    }

    #[test]
    fn parses_wildcards_both_syntaxes() {
        assert_eq!(p("items[*]"), vec![key("items"), Segment::Wildcard]);
        assert_eq!(p("items.*"), vec![key("items"), Segment::Wildcard]);
        assert_eq!(
            p("items[*].name"),
            vec![key("items"), Segment::Wildcard, key("name")]
        );
    }

    #[test]
    fn parses_quoted_keys_with_dots_and_escapes() {
        assert_eq!(p(r#"["a.b"]"#), vec![key("a.b")]);
        assert_eq!(p(r#"x["a.b"].c"#), vec![key("x"), key("a.b"), key("c")]);
        assert_eq!(p(r#"['single']"#), vec![key("single")]);
        assert_eq!(p(r#"["a\"b"]"#), vec![key("a\"b")]);
        assert_eq!(p(r#"[""]"#), vec![key("")]);
    }

    #[test]
    fn parses_unicode_keys() {
        assert_eq!(p("café.naïve"), vec![key("café"), key("naïve")]);
        assert_eq!(p("données.🌍"), vec![key("données"), key("🌍")]);
    }

    #[test]
    fn rejects_malformed_paths() {
        for bad in [
            "a..b",
            "items[",
            "items[]",
            "items[abc]",
            "items[0",
            r#"items["oops]"#,
            "a.",
            r#"a["b\"#,
        ] {
            assert!(
                parse_path(bad).is_err(),
                "expected {bad:?} to be rejected, got {:?}",
                parse_path(bad)
            );
        }
    }

    #[test]
    fn rejects_oversized_index() {
        let huge = format!("a[{}]", "9".repeat(40));
        assert!(parse_path(&huge).is_err());
    }

    fn doc() -> Value {
        serde_json::json!({
            "user": { "name": "Ada", "age": 36, "tags": ["math", "engine"] },
            "items": [
                { "id": 1, "name": "first" },
                { "id": 2, "name": "second" },
                { "id": 3 }
            ],
            "empty": [],
            "nothing": null
        })
    }

    #[test]
    fn eval_root_returns_whole_document() {
        assert_eq!(eval(&doc(), &p("$")).unwrap(), doc());
    }

    #[test]
    fn eval_dotted_and_indexed() {
        let d = doc();
        assert_eq!(eval(&d, &p("user.name")).unwrap(), serde_json::json!("Ada"));
        assert_eq!(eval(&d, &p("user.age")).unwrap(), serde_json::json!(36));
        assert_eq!(
            eval(&d, &p("items[1].name")).unwrap(),
            serde_json::json!("second")
        );
        assert_eq!(
            eval(&d, &p("user.tags[0]")).unwrap(),
            serde_json::json!("math")
        );
        assert_eq!(eval(&d, &p("nothing")).unwrap(), Value::Null);
    }

    #[test]
    fn eval_wildcard_over_array() {
        let d = doc();
        assert_eq!(
            eval(&d, &p("items[*].id")).unwrap(),
            serde_json::json!([1, 2, 3])
        );
        // items[2] has no "name" -> skipped, not an error.
        assert_eq!(
            eval(&d, &p("items[*].name")).unwrap(),
            serde_json::json!(["first", "second"])
        );
    }

    #[test]
    fn eval_wildcard_over_object_yields_values() {
        let d = serde_json::json!({"a": 1, "b": 2, "c": 3});
        assert_eq!(eval(&d, &p("*")).unwrap(), serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn eval_wildcard_on_empty_array_is_empty_array() {
        assert_eq!(eval(&doc(), &p("empty[*]")).unwrap(), serde_json::json!([]));
    }

    #[test]
    fn eval_nested_wildcards_flatten() {
        let d = serde_json::json!({"rows": [[1, 2], [3], []]});
        assert_eq!(
            eval(&d, &p("rows[*][*]")).unwrap(),
            serde_json::json!([1, 2, 3])
        );
    }

    #[test]
    fn eval_missing_key_errors_with_available_keys() {
        let err = eval(&doc(), &p("user.nope")).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
        assert!(err.contains("age"), "{err}");
        assert!(err.contains("$.user"), "{err}");
    }

    #[test]
    fn eval_out_of_range_index_errors() {
        let err = eval(&doc(), &p("items[9]")).unwrap_err().to_string();
        assert!(err.contains("out of range"), "{err}");
        assert!(err.contains('3'), "{err}");
    }

    #[test]
    fn eval_type_mismatch_errors() {
        let e1 = eval(&doc(), &p("user.name.deeper"))
            .unwrap_err()
            .to_string();
        assert!(e1.contains("string"), "{e1}");
        let e2 = eval(&doc(), &p("user[0]")).unwrap_err().to_string();
        assert!(e2.contains("not an array"), "{e2}");
        let e3 = eval(&doc(), &p("user.age[*]")).unwrap_err().to_string();
        assert!(e3.contains("not an array or object"), "{e3}");
    }

    #[test]
    fn eval_quoted_key_with_dot() {
        let d = serde_json::json!({"a.b": {"c": 7}});
        assert_eq!(eval(&d, &p(r#"["a.b"].c"#)).unwrap(), serde_json::json!(7));
    }
}
