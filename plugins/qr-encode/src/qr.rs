//! Pure, host-testable QR encoding core. No SDK, no wasm, no I/O.

use crate::error::{Error, Result};
use core::fmt::Write as _;
use qrcode::types::Color as Module;
use qrcode::{EcLevel, QrCode, Version};

/// Sentinel that marks an options line at offset 0.
pub const SENTINEL: &str = "#!qr";

/// Hard ceiling on input size. Above every QR capacity — the densest possible
/// symbol is 7089 numeric digits at version 40 / ECC L — so anything larger is a
/// caller mistake we can name before touching the encoder.
pub const MAX_INPUT: usize = 8192;

/// Largest `scale=` (SVG pixels per module).
pub const MAX_SCALE: u32 = 32;

/// Largest `quiet=` (quiet-zone width in modules).
pub const MAX_QUIET: u32 = 16;

/// Version-40 capacity per ECC level, as `(bytes, alphanumeric chars, digits)`.
///
/// Which column applies depends on the encoding mode the optimiser picks, so this
/// is only used to build a helpful "too long" message — never to pre-reject input
/// (an all-digit payload legitimately beats the byte-mode figure by 2.4x).
const CAPACITY: [(EcLevel, usize, usize, usize); 4] = [
    (EcLevel::L, 2953, 4296, 7089),
    (EcLevel::M, 2331, 3391, 5596),
    (EcLevel::Q, 1663, 2420, 3993),
    (EcLevel::H, 1273, 1852, 2953),
];

/// `(bytes, alphanumeric, numeric)` capacity of a version-40 symbol at `ecc`.
fn capacity_of(ecc: EcLevel) -> (usize, usize, usize) {
    CAPACITY
        .iter()
        .find(|(l, ..)| *l == ecc)
        .map(|&(_, b, a, n)| (b, a, n))
        // Unreachable: the table covers every EcLevel variant. Fall back to the
        // most conservative row rather than panicking.
        .unwrap_or((1273, 1852, 2953))
}

/// Human-readable capacity advice for the "does not fit" error paths.
fn capacity_hint(ecc: EcLevel) -> String {
    let (b, a, n) = capacity_of(ecc);
    format!(
        "a version-40 symbol at ECC {} holds at most {b} bytes, {a} alphanumeric \
         characters, or {n} digits",
        ecc_name(ecc)
    )
}

fn ecc_name(ecc: EcLevel) -> &'static str {
    match ecc {
        EcLevel::L => "L",
        EcLevel::M => "M",
        EcLevel::Q => "Q",
        EcLevel::H => "H",
    }
}

/// Requested output serialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Scalable vector graphic. The default.
    Svg,
    /// Unicode block art, one `██` pair per dark module.
    Txt,
    /// A JSON description of the module matrix.
    Json,
}

/// Everything the encoder needs, after options parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Output serialisation.
    pub format: Format,
    /// Error-correction level.
    pub ecc: EcLevel,
    /// SVG pixels per module.
    pub scale: u32,
    /// Quiet-zone width, in modules, on every side.
    pub quiet: u32,
    /// Fill for dark modules (SVG only).
    pub dark: String,
    /// Fill for the background (SVG only). `"none"` renders transparent.
    pub light: String,
    /// Force a specific normal QR version (1..=40); `None` picks the smallest fit.
    pub version: Option<i16>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            format: Format::Svg,
            ecc: EcLevel::M,
            scale: 4,
            quiet: 4,
            dark: "#000000".into(),
            light: "#ffffff".into(),
            version: None,
        }
    }
}

/// Split the optional `#!qr ...` options line off `input`.
///
/// Returns the parsed options and the payload text. When no options line is
/// present the whole input is the payload and defaults apply.
pub fn parse_envelope(input: &[u8]) -> Result<(Options, &str)> {
    if input.is_empty() {
        return Err(Error::InvalidInput(
            "empty input: expected UTF-8 text to encode, optionally preceded by a \
             `#!qr ...` options line"
                .into(),
        ));
    }
    if input.len() > MAX_INPUT {
        return Err(Error::InvalidInput(format!(
            "input is {} bytes; no QR version can hold more than {MAX_INPUT} bytes of any \
             kind ({})",
            input.len(),
            capacity_hint(EcLevel::L)
        )));
    }

    let has_line = input.starts_with(SENTINEL.as_bytes())
        && matches!(
            input.get(SENTINEL.len()),
            None | Some(b'\n') | Some(b' ') | Some(b'\t')
        );

    if !has_line {
        let text = as_text(input)?;
        return Ok((Options::default(), text));
    }

    let nl = input.iter().position(|&b| b == b'\n').ok_or_else(|| {
        Error::InvalidInput(format!(
            "input starts with the {SENTINEL:?} options sentinel but has no newline \
             terminating the options line"
        ))
    })?;
    let line = as_text(&input[..nl])?;
    let opts = parse_options(&line[SENTINEL.len()..])?;
    let text = as_text(&input[nl + 1..])?;
    if text.is_empty() {
        return Err(Error::InvalidInput(
            "options line was given but the text after it is empty".into(),
        ));
    }
    Ok((opts, text))
}

fn as_text(bytes: &[u8]) -> Result<&str> {
    core::str::from_utf8(bytes).map_err(|e| {
        Error::InvalidInput(format!(
            "input is not valid UTF-8 (byte {}): {e}",
            e.valid_up_to()
        ))
    })
}

/// Parse the whitespace-separated `key=value` tail of an options line.
pub fn parse_options(tail: &str) -> Result<Options> {
    let mut o = Options::default();
    for tok in tail.split_whitespace() {
        let (key, value) = tok.split_once('=').ok_or_else(|| {
            Error::InvalidInput(format!(
                "option {tok:?} is not a `key=value` pair; valid keys are \
                 format, ecc, scale, quiet, dark, light, version"
            ))
        })?;
        match key {
            "format" => {
                o.format = match value {
                    "svg" => Format::Svg,
                    "txt" | "text" => Format::Txt,
                    "json" => Format::Json,
                    other => {
                        return Err(Error::InvalidInput(format!(
                            "unknown format {other:?}; expected svg, txt or json"
                        )))
                    }
                }
            }
            "ecc" => {
                o.ecc = match value {
                    "l" | "L" => EcLevel::L,
                    "m" | "M" => EcLevel::M,
                    "q" | "Q" => EcLevel::Q,
                    "h" | "H" => EcLevel::H,
                    other => {
                        return Err(Error::InvalidInput(format!(
                            "unknown ecc level {other:?}; expected l, m, q or h"
                        )))
                    }
                }
            }
            "scale" => {
                let n = parse_u32(key, value)?;
                if n == 0 || n > MAX_SCALE {
                    return Err(Error::InvalidInput(format!(
                        "scale={n} out of range; expected 1..={MAX_SCALE}"
                    )));
                }
                o.scale = n;
            }
            "quiet" => {
                let n = parse_u32(key, value)?;
                if n > MAX_QUIET {
                    return Err(Error::InvalidInput(format!(
                        "quiet={n} out of range; expected 0..={MAX_QUIET}"
                    )));
                }
                o.quiet = n;
            }
            "dark" => o.dark = validate_color(key, value)?,
            "light" => o.light = validate_color(key, value)?,
            "version" => {
                let n = parse_u32(key, value)?;
                if !(1..=40).contains(&n) {
                    return Err(Error::InvalidInput(format!(
                        "version={n} out of range; expected 1..=40"
                    )));
                }
                o.version = Some(n as i16);
            }
            other => {
                return Err(Error::InvalidInput(format!(
                    "unknown option key {other:?}; valid keys are \
                     format, ecc, scale, quiet, dark, light, version"
                )))
            }
        }
    }
    Ok(o)
}

fn parse_u32(key: &str, value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| Error::InvalidInput(format!("{key}={value:?} is not a non-negative integer")))
}

/// Accept only shapes that cannot escape an SVG attribute: `none`, `#` plus
/// 3/4/6/8 hex digits, or a bare alphabetic CSS colour name.
fn validate_color(key: &str, value: &str) -> Result<String> {
    let ok = if value == "none" {
        true
    } else if let Some(hex) = value.strip_prefix('#') {
        matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        !value.is_empty() && value.len() <= 24 && value.bytes().all(|b| b.is_ascii_alphabetic())
    };
    if !ok {
        return Err(Error::InvalidInput(format!(
            "{key}={value:?} is not an accepted colour; expected `none`, `#RGB`, \
             `#RGBA`, `#RRGGBB`, `#RRGGBBAA`, or a plain colour name"
        )));
    }
    Ok(value.to_string())
}

/// The encoded symbol: a square bitmap of modules plus its metadata.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Modules per side, excluding the quiet zone.
    pub modules: usize,
    /// `true` = dark. Row-major, `modules * modules` entries.
    pub dark: Vec<bool>,
    /// QR version actually used.
    pub version: i16,
    /// Error-correction level used.
    pub ecc: EcLevel,
}

impl Symbol {
    /// Is the module at `(x, y)` dark? Out-of-range coordinates are light.
    pub fn at(&self, x: usize, y: usize) -> bool {
        if x >= self.modules || y >= self.modules {
            return false;
        }
        self.dark[y * self.modules + x]
    }
}

/// Encode `text` into a QR symbol, translating every `qrcode` error into an
/// actionable [`Error::InvalidInput`].
pub fn encode(text: &str, opts: &Options) -> Result<Symbol> {
    if text.is_empty() {
        return Err(Error::InvalidInput("nothing to encode: text is empty".into()));
    }
    let bytes = text.as_bytes();

    // Capacity is mode-dependent (numeric beats alphanumeric beats byte), so we
    // let the encoder decide rather than pre-rejecting, and turn its terse
    // `DataTooLong` into something the caller can act on.
    let code = match opts.version {
        None => QrCode::with_error_correction_level(bytes, opts.ecc).map_err(|e| {
            Error::InvalidInput(format!(
                "cannot encode {} bytes at ECC {}: {e} — {}; shorten the text or lower \
                 `ecc` (l holds the most)",
                bytes.len(),
                ecc_name(opts.ecc),
                capacity_hint(opts.ecc)
            ))
        })?,
        Some(v) => QrCode::with_version(bytes, Version::Normal(v), opts.ecc).map_err(|e| {
            Error::InvalidInput(format!(
                "cannot encode {} bytes into QR version {v} at ECC {}: {e}; \
                 try a higher version or omit `version=` to auto-size",
                bytes.len(),
                ecc_name(opts.ecc)
            ))
        })?,
    };

    let modules = code.width();
    let version = match code.version() {
        Version::Normal(v) => v,
        Version::Micro(v) => v,
    };
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == Module::Dark)
        .collect::<Vec<bool>>();
    if dark.len() != modules * modules {
        return Err(Error::Internal(format!(
            "encoder returned {} modules for a {modules}x{modules} symbol",
            dark.len()
        )));
    }
    Ok(Symbol {
        modules,
        dark,
        version,
        ecc: opts.ecc,
    })
}

/// Render `sym` as SVG. Horizontal runs of dark modules are merged into single
/// path segments, which keeps the output small for dense codes.
pub fn render_svg(sym: &Symbol, opts: &Options) -> String {
    let q = opts.quiet as usize;
    let side = sym.modules + 2 * q;
    let px = side as u32 * opts.scale;

    let mut path = String::new();
    for y in 0..sym.modules {
        let mut x = 0;
        while x < sym.modules {
            if !sym.at(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < sym.modules && sym.at(x, y) {
                x += 1;
            }
            let run = x - start;
            // `write!` into a String cannot fail; ignore the Result rather than
            // unwrap so a panic is structurally impossible.
            let _ = write!(path, "M{} {}h{run}v1H{}z", start + q, y + q, start + q);
        }
    }

    let mut svg = String::with_capacity(path.len() + 512);
    svg.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" \
         width=\"{px}\" height=\"{px}\" viewBox=\"0 0 {side} {side}\" \
         shape-rendering=\"crispEdges\" role=\"img\" \
         aria-label=\"QR code, version {} ECC {}\">\n",
        sym.version,
        ecc_name(sym.ecc)
    );
    if opts.light != "none" {
        let _ = write!(
            svg,
            "<rect x=\"0\" y=\"0\" width=\"{side}\" height=\"{side}\" fill=\"{}\"/>\n",
            opts.light
        );
    }
    let _ = write!(svg, "<path fill=\"{}\" d=\"{path}\"/>\n", opts.dark);
    svg.push_str("</svg>\n");
    svg
}

/// Render `sym` as Unicode block art: `██` per dark module, two spaces per light
/// one, so the result is roughly square in a monospace terminal.
pub fn render_txt(sym: &Symbol, opts: &Options) -> String {
    let q = opts.quiet as usize;
    let side = sym.modules + 2 * q;
    let mut out = String::with_capacity(side * (side * 6 + 1));
    for y in 0..side {
        for x in 0..side {
            let dark = y >= q && x >= q && sym.at(x - q, y - q);
            out.push_str(if dark { "██" } else { "  " });
        }
        out.push('\n');
    }
    out
}

/// Render `sym` as JSON: metadata plus one `'0'`/`'1'` string per row (quiet zone
/// excluded — it is reported as a field so the consumer can add its own).
pub fn render_json(sym: &Symbol, opts: &Options) -> String {
    let mut out = String::with_capacity(sym.modules * (sym.modules + 8) + 128);
    let _ = write!(
        out,
        "{{\"version\":{},\"ecc\":\"{}\",\"modules\":{},\"quiet_zone\":{},\"matrix\":[",
        sym.version,
        ecc_name(sym.ecc),
        sym.modules,
        opts.quiet
    );
    for y in 0..sym.modules {
        if y > 0 {
            out.push(',');
        }
        out.push('"');
        for x in 0..sym.modules {
            out.push(if sym.at(x, y) { '1' } else { '0' });
        }
        out.push('"');
    }
    out.push_str("]}\n");
    out
}

/// Top-level entrypoint: parse the envelope, encode, render.
pub fn process(input: &[u8]) -> Result<Vec<u8>> {
    let (opts, text) = parse_envelope(input)?;
    let sym = encode(text, &opts)?;
    let out = match opts.format {
        Format::Svg => render_svg(&sym, &opts),
        Format::Txt => render_txt(&sym, &opts),
        Format::Json => render_json(&sym, &opts),
    };
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svg_of(input: &[u8]) -> String {
        String::from_utf8(process(input).expect("process")).expect("utf8")
    }

    #[test]
    fn plain_text_produces_plausible_svg() {
        let svg = svg_of(b"https://entanglement.example/hello");
        assert!(svg.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"), "{svg:.60}");
        assert!(svg.contains("xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("viewBox=\"0 0 "));
        assert!(svg.contains("shape-rendering=\"crispEdges\""));
        assert!(svg.contains("<path fill=\"#000000\" d=\"M"));
        assert!(svg.trim_end().ends_with("</svg>"));
        // A real symbol has many path segments, not a handful.
        assert!(svg.matches('M').count() > 20, "too few runs: {}", svg.matches('M').count());
    }

    #[test]
    fn svg_geometry_matches_version_and_quiet_zone() {
        // Version 1 = 21 modules; default quiet 4 → side 29, scale 4 → 116 px.
        let svg = svg_of(b"HI");
        assert!(svg.contains("viewBox=\"0 0 29 29\""), "{svg:.400}");
        assert!(svg.contains("width=\"116\" height=\"116\""), "{svg:.400}");
    }

    #[test]
    fn options_line_is_honoured() {
        let svg = svg_of(b"#!qr ecc=h scale=8 quiet=0 dark=#112233 light=none\nDATA");
        assert!(svg.contains("width=\"168\""), "{svg:.400}"); // 21 modules * 8
        assert!(svg.contains("viewBox=\"0 0 21 21\""), "{svg:.400}");
        assert!(svg.contains("fill=\"#112233\""));
        assert!(!svg.contains("<rect"), "light=none must omit the background rect");
        assert!(svg.contains("ECC H"));
    }

    #[test]
    fn option_order_and_whitespace_are_flexible() {
        let a = svg_of(b"#!qr scale=6 ecc=q\nX");
        let b = svg_of(b"#!qr   ecc=q    scale=6\nX");
        assert_eq!(a, b);
    }

    #[test]
    fn bare_sentinel_line_escapes_literal_text() {
        // Encoding text that itself starts with "#!qr" requires an options line.
        let svg = svg_of(b"#!qr\n#!qr is the sentinel");
        assert!(svg.contains("<svg"));
        let (opts, text) = parse_envelope(b"#!qr\n#!qr is the sentinel").unwrap();
        assert_eq!(text, "#!qr is the sentinel");
        assert_eq!(opts, Options::default());
    }

    #[test]
    fn sentinel_only_matches_at_a_word_boundary() {
        // "#!qrx" is text, not an options line.
        let (opts, text) = parse_envelope(b"#!qrx nope").unwrap();
        assert_eq!(text, "#!qrx nope");
        assert_eq!(opts, Options::default());
    }

    #[test]
    fn txt_output_is_a_square_block_grid() {
        let out = String::from_utf8(process(b"#!qr format=txt quiet=2\nHI").unwrap()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let side = 21 + 4; // 21 modules + quiet 2 on each side
        assert_eq!(lines.len(), side);
        for (i, l) in lines.iter().enumerate() {
            assert_eq!(l.chars().count(), side * 2, "row {i}: {l:?}");
        }
        assert!(out.contains('█'), "no dark modules rendered");
        // The top-left quiet zone must be blank.
        assert!(lines[0].trim().is_empty());
    }

    #[test]
    fn json_output_shape() {
        let out = String::from_utf8(process(b"#!qr format=json ecc=l\nHI").unwrap()).unwrap();
        assert!(out.starts_with("{\"version\":1,\"ecc\":\"L\",\"modules\":21,\"quiet_zone\":4,\"matrix\":[\""), "{out:.90}");
        assert!(out.trim_end().ends_with("]}"));
        let rows = out.matches('"').count();
        // 4 quoted keys+value ("version" is unquoted) → count rows via commas in matrix instead.
        assert!(rows >= 21, "expected >= 21 quoted tokens, got {rows}");
        // Finder pattern: the top-left 7x7 corner starts with seven dark modules.
        let first_row_start = out
            .split("\"matrix\":[\"")
            .nth(1)
            .and_then(|s| s.get(..7))
            .unwrap_or("");
        assert_eq!(first_row_start, "1111111", "finder pattern missing: {first_row_start:?}");
    }

    #[test]
    fn higher_ecc_needs_a_bigger_symbol() {
        let payload = "x".repeat(200);
        let l = encode(&payload, &Options { ecc: EcLevel::L, ..Default::default() }).unwrap();
        let h = encode(&payload, &Options { ecc: EcLevel::H, ..Default::default() }).unwrap();
        assert!(h.version > l.version, "L={} H={}", l.version, h.version);
        assert_eq!(h.dark.len(), h.modules * h.modules);
    }

    #[test]
    fn forced_version_is_respected() {
        let sym = encode("HI", &Options { version: Some(10), ..Default::default() }).unwrap();
        assert_eq!(sym.version, 10);
        assert_eq!(sym.modules, 57); // 4*10 + 17
    }

    #[test]
    fn byte_mode_capacity_boundary_is_exact() {
        // Lowercase letters are outside the alphanumeric charset, so these force
        // 8-bit byte mode and land exactly on the documented capacity.
        for (ecc, bytes, _, _) in CAPACITY {
            let sym = encode(&"a".repeat(bytes), &Options { ecc, ..Default::default() })
                .unwrap_or_else(|e| panic!("ECC {} at {bytes} bytes: {e}", ecc_name(ecc)));
            assert_eq!(sym.version, 40, "ECC {}", ecc_name(ecc));
            assert_eq!(sym.modules, 177);
            assert_eq!(sym.dark.len(), 177 * 177);

            let err = encode(&"a".repeat(bytes + 1), &Options { ecc, ..Default::default() })
                .unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "ECC {}: {err:?}", ecc_name(ecc));
        }
    }

    #[test]
    fn denser_modes_beat_the_byte_capacity() {
        // 2000 digits exceed the 1273-byte ECC-H byte capacity but fit in numeric
        // mode (2953). Pre-rejecting on byte capacity would wrongly refuse this.
        let digits = "1234567890".repeat(200);
        assert_eq!(digits.len(), 2000);
        let sym = encode(&digits, &Options { ecc: EcLevel::H, ..Default::default() })
            .expect("numeric mode should fit 2000 digits at ECC H");
        assert!((1..=40).contains(&sym.version), "version {}", sym.version);
        // Same story for alphanumeric mode (1852 at ECC H).
        let alnum = "ABCDEFGHIJ".repeat(150);
        assert!(encode(&alnum, &Options { ecc: EcLevel::H, ..Default::default() }).is_ok());
    }

    // ---- error paths: nothing below may panic ----

    #[test]
    fn empty_input_is_invalid_input() {
        let err = process(b"").unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert!(err.to_string().contains("empty input"), "{err}");
    }

    #[test]
    fn over_long_input_errors_with_capacity_advice() {
        // Past the absolute QR ceiling: rejected during envelope parsing.
        let err = process(&vec![b'a'; MAX_INPUT + 1]).unwrap_err();
        assert!(err.to_string().contains("no QR version can hold more"), "{err}");

        // Inside MAX_INPUT but past the byte-mode capacity of the chosen ECC level.
        let mut input = b"#!qr ecc=h\n".to_vec();
        input.extend(std::iter::repeat(b'a').take(1274));
        let err = process(&input).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert!(err.to_string().contains("1274 bytes"), "{err}");
        assert!(err.to_string().contains("data too long"), "{err}");
        assert!(err.to_string().contains("1273 bytes"), "{err}");
        assert!(err.to_string().contains("lower `ecc`"), "{err}");

        // And one byte less fits, proving the boundary is exact.
        let mut ok = b"#!qr ecc=h\n".to_vec();
        ok.extend(std::iter::repeat(b'a').take(1273));
        assert!(process(&ok).is_ok());
    }

    #[test]
    fn forced_version_too_small_errors_clearly() {
        let err = encode(
            &"y".repeat(300),
            &Options { version: Some(1), ..Default::default() },
        )
        .unwrap_err();
        assert!(err.to_string().contains("QR version 1"), "{err}");
        assert!(err.to_string().contains("auto-size"), "{err}");
    }

    #[test]
    fn non_utf8_input_is_rejected() {
        let err = process(&[0xff, 0xfe, 0x00]).unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn options_line_without_newline_is_rejected() {
        let err = process(b"#!qr scale=4").unwrap_err();
        assert!(err.to_string().contains("no newline"), "{err}");
    }

    #[test]
    fn options_line_with_empty_text_is_rejected() {
        let err = process(b"#!qr scale=4\n").unwrap_err();
        assert!(err.to_string().contains("text after it is empty"), "{err}");
    }

    #[test]
    fn bad_options_are_rejected() {
        let cases: &[(&[u8], &str)] = &[
            (b"#!qr nonsense\nX", "not a `key=value` pair"),
            (b"#!qr bogus=1\nX", "unknown option key"),
            (b"#!qr format=pdf\nX", "unknown format"),
            (b"#!qr ecc=z\nX", "unknown ecc level"),
            (b"#!qr scale=0\nX", "scale=0 out of range"),
            (b"#!qr scale=99\nX", "scale=99 out of range"),
            (b"#!qr scale=abc\nX", "not a non-negative integer"),
            (b"#!qr quiet=17\nX", "quiet=17 out of range"),
            (b"#!qr version=0\nX", "version=0 out of range"),
            (b"#!qr version=41\nX", "version=41 out of range"),
        ];
        for (input, needle) in cases {
            let err = process(input).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "{:?}: expected {needle:?}, got {err}",
                core::str::from_utf8(input)
            );
        }
    }

    #[test]
    fn colour_options_cannot_inject_svg_markup() {
        for bad in [
            "#!qr dark=\"/><script>alert(1)</script>\nX".as_bytes(),
            b"#!qr light=#12\nX",
            b"#!qr dark=#gggggg\nX",
            b"#!qr dark=rgb(1,2,3)\nX",
        ] {
            let err = process(bad).unwrap_err();
            assert!(
                err.to_string().contains("not an accepted colour")
                    || err.to_string().contains("not a `key=value` pair"),
                "{:?} -> {err}",
                core::str::from_utf8(bad)
            );
        }
        // Named colours and every accepted hex width do pass.
        for good in ["red", "#f00", "#f00a", "#ff0000", "#ff0000aa", "none"] {
            let input = format!("#!qr light={good}\nX");
            assert!(process(input.as_bytes()).is_ok(), "rejected {good:?}");
        }
        // And nothing that reaches the output can close an attribute.
        let svg = svg_of(b"#!qr dark=darkslateblue\nX");
        assert_eq!(svg.matches("<path").count(), 1);
        assert!(svg.contains("fill=\"darkslateblue\""));
    }

    #[test]
    fn text_containing_svg_metacharacters_is_fine() {
        // Payload bytes never reach the SVG body, so `<` and `&` cannot escape.
        let svg = svg_of(b"<a href='x'>&amp;</a>");
        assert_eq!(svg.matches("<svg").count(), 1);
        assert!(!svg.contains("href"));
    }

    #[test]
    fn single_character_and_unicode_payloads_work() {
        for text in ["X", "\u{1f600}", "\u{4f60}\u{597d}\u{4e16}\u{754c}"] {
            let out = process(text.as_bytes()).unwrap_or_else(|e| panic!("{text:?}: {e}"));
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn symbol_at_is_bounds_safe() {
        let sym = encode("HI", &Options::default()).unwrap();
        assert!(!sym.at(sym.modules, 0));
        assert!(!sym.at(0, sym.modules));
        assert!(!sym.at(usize::MAX, usize::MAX));
    }
}
