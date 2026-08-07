//! `csv-stats` — profile a CSV and return per-column statistics as JSON.
//!
//! Tier 1, zero declared capabilities: pure byte-in/byte-out compute.
//!
//! # Input
//!
//! Raw UTF-8 CSV bytes. The **first row is always treated as the header**.
//! RFC-4180 quoting is honoured (`"a,b"`, `""` for an embedded quote, newlines
//! inside quotes). A leading UTF-8 BOM is stripped. The delimiter is `,`.
//!
//! # Output
//!
//! ```json
//! {
//!   "rows": 2,
//!   "columns": [
//!     {"name":"age","type":"numeric","count":2,"nulls":0,
//!      "min":30.0,"max":41.0,"mean":35.5,"sum":71.0},
//!     {"name":"city","type":"text","count":2,"nulls":0,"distinct":2},
//!     {"name":"note","type":"empty","count":0,"nulls":2}
//!   ]
//! }
//! ```
//!
//! * `rows` — number of **data** rows (the header is not counted).
//! * `count` — non-empty values in the column; `nulls` — empty/whitespace-only values.
//! * `type` is `numeric` when every non-empty value parses as a finite number,
//!   `empty` when the column has no non-empty values at all, otherwise `text`.
//! * numeric columns carry `min`/`max`/`mean`/`sum`; text columns carry `distinct`
//!   (the number of distinct non-empty values).
//!
//! All the real work lives in [`transform`], a plain function over `&[u8]` that is
//! covered by the host-target test suite (`cargo test`). Ragged rows, bad UTF-8 and
//! empty input are reported as errors — this crate never panics on input.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use serde_json::{json, Map, Number, Value};

/// Everything that can go wrong. Surfaced to the caller as
/// `PluginError::InvalidInput` using the `Display` text below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input contained no CSV at all.
    Empty,
    /// Input bytes were not valid UTF-8.
    NotUtf8(String),
    /// A data row had a different field count than the header.
    Ragged {
        /// 1-based line number of the offending row (the header is line 1).
        line: u64,
        /// Number of fields the header declared.
        expected: usize,
        /// Number of fields found on this row.
        found: usize,
    },
    /// Any other CSV syntax problem (unclosed quote, stray quote, ...).
    Csv(String),
    /// The statistics could not be serialised (should be unreachable).
    BadOutput(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Empty => write!(
                f,
                "input is empty; expected CSV text whose first row is a header, \
                 e.g. \"name,age\\nAda,36\""
            ),
            Error::NotUtf8(m) => write!(f, "input is not valid UTF-8: {m}"),
            Error::Ragged {
                line,
                expected,
                found,
            } => write!(
                f,
                "ragged CSV: line {line} has {found} field(s) but the header declares \
                 {expected}; every row must have the same number of fields"
            ),
            Error::Csv(m) => write!(f, "could not parse CSV: {m}"),
            Error::BadOutput(m) => write!(f, "could not serialise statistics: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Running statistics for one column.
#[derive(Debug, Default)]
struct Column {
    name: String,
    /// Non-empty values seen.
    count: u64,
    /// Empty / whitespace-only values seen.
    nulls: u64,
    /// Still a candidate for `numeric` (flipped off by the first unparseable value).
    numeric: bool,
    min: f64,
    max: f64,
    sum: f64,
    distinct: HashSet<String>,
}

impl Column {
    fn new(name: String) -> Self {
        Column {
            name,
            count: 0,
            nulls: 0,
            numeric: true,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            sum: 0.0,
            distinct: HashSet::new(),
        }
    }

    fn observe(&mut self, raw: &str) {
        let v = raw.trim();
        if v.is_empty() {
            self.nulls += 1;
            return;
        }
        self.count += 1;
        self.distinct.insert(v.to_string());
        if self.numeric {
            match parse_number(v) {
                Some(n) => {
                    if n < self.min {
                        self.min = n;
                    }
                    if n > self.max {
                        self.max = n;
                    }
                    self.sum += n;
                }
                None => self.numeric = false,
            }
        }
    }

    fn kind(&self) -> &'static str {
        if self.count == 0 {
            "empty"
        } else if self.numeric {
            "numeric"
        } else {
            "text"
        }
    }

    fn to_json(&self) -> Result<Value, Error> {
        let mut obj = Map::new();
        obj.insert("name".into(), Value::String(self.name.clone()));
        obj.insert("type".into(), Value::String(self.kind().into()));
        obj.insert("count".into(), json!(self.count));
        obj.insert("nulls".into(), json!(self.nulls));
        match self.kind() {
            "numeric" => {
                let mean = self.sum / self.count as f64;
                obj.insert("min".into(), num(self.min)?);
                obj.insert("max".into(), num(self.max)?);
                obj.insert("mean".into(), num(mean)?);
                obj.insert("sum".into(), num(self.sum)?);
            }
            "text" => {
                obj.insert("distinct".into(), json!(self.distinct.len()));
            }
            _ => {}
        }
        Ok(Value::Object(obj))
    }
}

/// Parse a numeric cell. Deliberately rejects `inf`/`nan`/hex so that a column
/// containing them is classified as `text` rather than producing unrepresentable JSON.
fn parse_number(s: &str) -> Option<f64> {
    // Reject anything that isn't a plain decimal / exponent literal.
    if !s
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E'))
    {
        return None;
    }
    if !s.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: f64 = s.parse().ok()?;
    if n.is_finite() {
        Some(n)
    } else {
        None
    }
}

/// Wrap an `f64` as a JSON number, keeping the "no NaN/Inf in JSON" invariant explicit.
fn num(x: f64) -> Result<Value, Error> {
    Number::from_f64(x)
        .map(Value::Number)
        .ok_or_else(|| Error::BadOutput(format!("{x} is not representable in JSON")))
}

/// The whole plugin, as a pure function. Never panics on any input.
pub fn transform(input: &[u8]) -> Result<Vec<u8>, Error> {
    // Strip a UTF-8 BOM so `\u{feff}name` does not become a column called "\u{feff}name".
    let bytes = input.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(input);

    let text = core::str::from_utf8(bytes).map_err(|e| Error::NotUtf8(e.to_string()))?;
    if text.trim().is_empty() {
        return Err(Error::Empty);
    }

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(text.as_bytes());

    let headers = reader.headers().map_err(map_csv_err)?.clone();
    if headers.is_empty() {
        return Err(Error::Empty);
    }
    let width = headers.len();

    let mut columns: Vec<Column> = headers
        .iter()
        .map(|h| Column::new(h.trim().to_string()))
        .collect();

    let mut rows: u64 = 0;
    for record in reader.records() {
        let record = record.map_err(map_csv_err)?;
        // `flexible(false)` already rejects ragged rows, but belt-and-braces: never index
        // out of bounds if a future csv version changes behaviour.
        if record.len() != width {
            return Err(Error::Ragged {
                line: record.position().map(|p| p.line()).unwrap_or(rows + 2),
                expected: width,
                found: record.len(),
            });
        }
        rows += 1;
        for (i, field) in record.iter().enumerate() {
            columns[i].observe(field);
        }
    }

    let cols: Result<Vec<Value>, Error> = columns.iter().map(Column::to_json).collect();
    let out = json!({ "rows": rows, "columns": cols? });
    let mut s = serde_json::to_string_pretty(&out).map_err(|e| Error::BadOutput(e.to_string()))?;
    s.push('\n');
    Ok(s.into_bytes())
}

/// Translate a `csv::Error` into our error vocabulary, preserving line numbers.
fn map_csv_err(e: csv::Error) -> Error {
    match e.kind() {
        csv::ErrorKind::UnequalLengths {
            pos,
            expected_len,
            len,
        } => Error::Ragged {
            line: pos.as_ref().map(|p| p.line()).unwrap_or(0),
            expected: *expected_len as usize,
            found: *len as usize,
        },
        csv::ErrorKind::Utf8 { err, .. } => Error::NotUtf8(err.to_string()),
        _ => Error::Csv(e.to_string()),
    }
}

// ------------------------------------------------------------------
// wasm entrypoint — thin wrapper, no logic
// ------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm_entry {
    use entangle_sdk::{entangle_plugin, log, PluginError};

    fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        log::info(&format!("csv-stats: {} input bytes", input.len()));
        match crate::transform(&input) {
            Ok(out) => Ok(out),
            Err(e) => {
                let msg = e.to_string();
                log::warn(&format!("csv-stats: {msg}"));
                Err(PluginError::InvalidInput(msg))
            }
        }
    }

    entangle_plugin!(run);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(csv_text: &str) -> Value {
        let out = transform(csv_text.as_bytes()).expect("should succeed");
        serde_json::from_slice(&out).expect("output must be valid JSON")
    }

    fn err(csv_text: &str) -> String {
        transform(csv_text.as_bytes())
            .expect_err("should fail")
            .to_string()
    }

    fn col<'a>(v: &'a Value, name: &str) -> &'a Value {
        v["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == json!(name))
            .unwrap_or_else(|| panic!("no column {name} in {v}"))
    }

    // ---------------- happy paths ----------------

    #[test]
    fn numeric_and_text_columns() {
        let v = stats("name,age\nAda,36\nGrace,45\nAlan,41\n");
        assert_eq!(v["rows"], json!(3));

        let name = col(&v, "name");
        assert_eq!(name["type"], json!("text"));
        assert_eq!(name["count"], json!(3));
        assert_eq!(name["nulls"], json!(0));
        assert_eq!(name["distinct"], json!(3));
        assert!(name.get("mean").is_none());

        let age = col(&v, "age");
        assert_eq!(age["type"], json!("numeric"));
        assert_eq!(age["count"], json!(3));
        assert_eq!(age["min"], json!(36.0));
        assert_eq!(age["max"], json!(45.0));
        assert_eq!(age["sum"], json!(122.0));
        assert_eq!(age["mean"].as_f64().unwrap(), 122.0 / 3.0);
        assert!(age.get("distinct").is_none());
    }

    #[test]
    fn column_order_matches_header_order() {
        let v = stats("c,a,b\n1,2,3\n");
        let names: Vec<&str> = v["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["c", "a", "b"]);
    }

    #[test]
    fn distinct_counts_repeats_once() {
        let v = stats("city\nOslo\nOslo\nBergen\nOslo\n");
        assert_eq!(col(&v, "city")["distinct"], json!(2));
        assert_eq!(col(&v, "city")["count"], json!(4));
    }

    #[test]
    fn negative_decimal_and_exponent_numbers() {
        let v = stats("x\n-1.5\n2e3\n+0.5\n");
        let x = col(&v, "x");
        assert_eq!(x["type"], json!("numeric"));
        assert_eq!(x["min"], json!(-1.5));
        assert_eq!(x["max"], json!(2000.0));
        assert_eq!(x["sum"], json!(1999.0));
    }

    #[test]
    fn integers_are_reported_as_numbers_not_strings() {
        let v = stats("n\n1\n2\n");
        assert!(col(&v, "n")["sum"].is_number());
        assert_eq!(col(&v, "n")["sum"].as_f64().unwrap(), 3.0);
    }

    #[test]
    fn single_row_single_column() {
        let v = stats("only\n7\n");
        assert_eq!(v["rows"], json!(1));
        let c = col(&v, "only");
        assert_eq!(c["min"], c["max"]);
        assert_eq!(c["mean"], json!(7.0));
    }

    #[test]
    fn header_only_reports_zero_rows_and_empty_columns() {
        let v = stats("a,b,c");
        assert_eq!(v["rows"], json!(0));
        for name in ["a", "b", "c"] {
            let c = col(&v, name);
            assert_eq!(c["type"], json!("empty"));
            assert_eq!(c["count"], json!(0));
            assert_eq!(c["nulls"], json!(0));
            assert!(c.get("distinct").is_none());
            assert!(c.get("mean").is_none());
        }
    }

    #[test]
    fn all_blank_column_is_empty_type() {
        let v = stats("a,b\n1,\n2,   \n");
        assert_eq!(col(&v, "b")["type"], json!("empty"));
        assert_eq!(col(&v, "b")["nulls"], json!(2));
        assert_eq!(col(&v, "b")["count"], json!(0));
    }

    #[test]
    fn blanks_are_nulls_and_excluded_from_numeric_stats() {
        let v = stats("n,tag\n1,a\n,b\n3,c\n");
        let c = col(&v, "n");
        assert_eq!(v["rows"], json!(3));
        assert_eq!(c["type"], json!("numeric"));
        assert_eq!(c["count"], json!(2));
        assert_eq!(c["nulls"], json!(1));
        assert_eq!(c["sum"], json!(4.0));
        assert_eq!(c["mean"], json!(2.0));
    }

    #[test]
    fn wholly_blank_lines_are_skipped_not_counted_as_rows() {
        // RFC-4180-ish behaviour inherited from the `csv` crate: a line with no
        // characters at all is not a record.
        let v = stats("n\n1\n\n3\n");
        assert_eq!(v["rows"], json!(2));
        assert_eq!(col(&v, "n")["count"], json!(2));
        assert_eq!(col(&v, "n")["nulls"], json!(0));
    }

    #[test]
    fn mixed_numeric_and_text_column_is_text() {
        let v = stats("v\n1\n2\nN/A\n");
        let c = col(&v, "v");
        assert_eq!(c["type"], json!("text"));
        assert_eq!(c["distinct"], json!(3));
        assert!(c.get("sum").is_none());
    }

    #[test]
    fn inf_and_nan_literals_make_a_column_text() {
        for bad in ["inf", "-inf", "NaN", "infinity"] {
            let v = stats(&format!("v\n1\n{bad}\n"));
            assert_eq!(col(&v, "v")["type"], json!("text"), "for {bad}");
        }
    }

    #[test]
    fn surrounding_whitespace_in_numbers_is_tolerated() {
        let v = stats("n\n 1 \n\t2\t\n");
        assert_eq!(col(&v, "n")["type"], json!("numeric"));
        assert_eq!(col(&v, "n")["sum"], json!(3.0));
    }

    // ---------------- quoting ----------------

    #[test]
    fn quoted_fields_with_commas() {
        let v = stats("name,note\nAda,\"math, engines\"\nGrace,\"compilers\"\n");
        assert_eq!(v["rows"], json!(2));
        assert_eq!(col(&v, "note")["distinct"], json!(2));
        assert_eq!(col(&v, "note")["count"], json!(2));
    }

    #[test]
    fn quoted_fields_with_escaped_quotes_and_newlines() {
        let v = stats("q\n\"a \"\"b\"\" c\"\n\"line1\nline2\"\n");
        assert_eq!(v["rows"], json!(2));
        assert_eq!(col(&v, "q")["distinct"], json!(2));
    }

    #[test]
    fn quoted_header_names_are_unquoted() {
        let v = stats("\"first name\",\"age\"\nAda,36\n");
        assert_eq!(col(&v, "first name")["type"], json!("text"));
        assert_eq!(col(&v, "age")["type"], json!("numeric"));
    }

    #[test]
    fn quoted_numbers_still_count_as_numeric() {
        let v = stats("n\n\"1\"\n\"2\"\n");
        assert_eq!(col(&v, "n")["type"], json!("numeric"));
        assert_eq!(col(&v, "n")["sum"], json!(3.0));
    }

    // ---------------- unicode ----------------

    #[test]
    fn unicode_headers_and_values() {
        let v = stats("ville,température\nZürich,12\n東京,31\n");
        assert_eq!(col(&v, "ville")["distinct"], json!(2));
        let t = col(&v, "température");
        assert_eq!(t["type"], json!("numeric"));
        assert_eq!(t["max"], json!(31.0));
    }

    #[test]
    fn emoji_values_are_distinct_by_grapheme_bytes() {
        let v = stats("mood\n🎉\n✨\n🎉\n");
        assert_eq!(col(&v, "mood")["distinct"], json!(2));
        assert_eq!(col(&v, "mood")["count"], json!(3));
    }

    #[test]
    fn utf8_bom_is_stripped_from_the_first_header() {
        let v = stats("\u{feff}name,age\nAda,36\n");
        assert_eq!(col(&v, "name")["type"], json!("text"));
    }

    // ---------------- line endings ----------------

    #[test]
    fn crlf_line_endings() {
        let v = stats("a,b\r\n1,x\r\n2,y\r\n");
        assert_eq!(v["rows"], json!(2));
        assert_eq!(col(&v, "a")["sum"], json!(3.0));
        assert_eq!(col(&v, "b")["distinct"], json!(2));
    }

    #[test]
    fn missing_trailing_newline() {
        let v = stats("a\n1\n2");
        assert_eq!(v["rows"], json!(2));
    }

    // ---------------- errors ----------------

    #[test]
    fn empty_input_is_reported() {
        let e = err("");
        assert!(e.contains("input is empty"), "{e}");
        assert!(e.contains("header"), "{e}");
    }

    #[test]
    fn whitespace_only_input_is_reported() {
        assert!(err("  \n\n \t").contains("input is empty"));
    }

    #[test]
    fn invalid_utf8_is_reported_not_panicked() {
        let e = transform(&[b'a', b'\n', 0xff, 0xfe])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn ragged_row_too_long_is_reported_with_line_number() {
        let e = err("a,b\n1,2\n1,2,3\n");
        assert!(e.contains("ragged CSV"), "{e}");
        assert!(e.contains("line 3"), "{e}");
        assert!(e.contains("3 field"), "{e}");
        assert!(e.contains("2"), "{e}");
    }

    #[test]
    fn ragged_row_too_short_is_reported() {
        let e = err("a,b,c\n1,2\n");
        assert!(e.contains("ragged CSV"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn unclosed_quote_is_reported_not_panicked() {
        // An unterminated quote swallows the rest of the file into one field, which
        // makes the row ragged -> reported as an error, never a panic.
        let r = transform(b"a,b\n\"oops,1\n2,3\n");
        assert!(r.is_err(), "expected an error, got {r:?}");
    }

    #[test]
    fn ragged_input_never_panics_on_a_fuzz_ish_corpus() {
        for raw in [
            b"\x00\x01\x02".as_slice(),
            b",,,".as_slice(),
            b"\"".as_slice(),
            b"\"\"\"\"".as_slice(),
            b"a\n\"".as_slice(),
            b"a,b\n\"\"\"\n".as_slice(),
            b"\n\n\n".as_slice(),
            b"a\r\r\r".as_slice(),
        ] {
            // The only contract here is: returns, does not panic.
            let _ = transform(raw);
        }
    }

    // ---------------- output shape ----------------

    #[test]
    fn output_is_pretty_printed_json_ending_in_newline() {
        let out = transform(b"a\n1\n").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.ends_with('\n'), "{s:?}");
        assert!(s.contains("\n  \"rows\""), "{s:?}");
        serde_json::from_str::<Value>(&s).unwrap();
    }

    #[test]
    fn duplicate_header_names_are_kept_as_separate_columns() {
        let v = stats("a,a\n1,2\n");
        assert_eq!(v["columns"].as_array().unwrap().len(), 2);
    }
}
