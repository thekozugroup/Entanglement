//! Relative L2 distance between two numeric vectors.
//!
//! # Input encoding
//!
//! Each replica output is **UTF-8 text** holding a flat list of decimal
//! numbers:
//!
//! * numbers are separated by a comma (with optional surrounding whitespace)
//!   or by whitespace alone — `1, 2, 3`, `1 2 3` and `1,2\n3` are the same
//!   vector;
//! * the whole list may be wrapped in one pair of square brackets, so a flat
//!   JSON array of numbers (`[1.5, -2, 3e-4]`) works as-is;
//! * each number uses Rust's `f64` grammar (`1`, `-0.5`, `6.02e23`) and must be
//!   finite — `NaN` and `inf` are refused;
//! * an empty list (`""`, `"[]"`) is the empty vector.
//!
//! Anything else — invalid UTF-8, an empty field (`1,,2`), a stray bracket, a
//! non-number — makes the output *unparseable*.
//!
//! # Distance
//!
//! ```text
//! d(a, b) = ||a - b||₂ / max(||a||₂, ||b||₂)
//! ```
//!
//! * symmetric, scale-invariant (`d(ka, kb) = d(a, b)` for `k != 0`), and in
//!   `[0, 2]`;
//! * two zero vectors (or two empty vectors) are at distance 0;
//! * computed on values pre-scaled by the largest magnitude present, so
//!   vectors near `f64::MAX` neither overflow nor lose the answer;
//! * vectors of different lengths, or an unparseable output, are
//!   **incomparable**: `+inf`, which the metric contract defines as "never
//!   agrees". The result is never `NaN` or negative.

/// Parse one output into a vector (see the module docs), or `None` if it is
/// not a well-formed list of finite numbers.
pub fn parse_vector(bytes: &[u8]) -> Option<Vec<f64>> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    let body = match (text.strip_prefix('['), text.ends_with(']')) {
        (Some(rest), true) => rest.strip_suffix(']')?,
        (None, false) => text,
        // One bracket without the other.
        _ => return None,
    };
    if body.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for field in body.split(',') {
        let mut any = false;
        for word in field.split_whitespace() {
            let v: f64 = word.parse().ok()?;
            if !v.is_finite() {
                return None;
            }
            out.push(v);
            any = true;
        }
        if !any {
            // `1,,2`, a leading or a trailing comma.
            return None;
        }
    }
    Some(out)
}

/// `||a - b|| / max(||a||, ||b||)` for equal-length vectors, or `+inf` when
/// the lengths differ.
pub fn relative_l2(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        return f64::INFINITY;
    }
    let scale = a
        .iter()
        .chain(b.iter())
        .fold(0.0_f64, |m, v| m.max(v.abs()));
    if scale == 0.0 {
        return 0.0;
    }
    let (mut diff, mut na, mut nb) = (0.0_f64, 0.0_f64, 0.0_f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (x / scale, y / scale);
        diff += (x - y) * (x - y);
        na += x * x;
        nb += y * y;
    }
    // scale > 0 means some |value| == scale, so one of the norms is >= 1.
    diff.sqrt() / na.max(nb).sqrt()
}

/// The metric: [`relative_l2`] of the two parsed outputs, `+inf` if either
/// does not parse.
pub fn distance(a: &[u8], b: &[u8]) -> f64 {
    match (parse_vector(a), parse_vector(b)) {
        (Some(x), Some(y)) => relative_l2(&x, &y),
        _ => f64::INFINITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    #[test]
    fn parses_json_arrays_and_separated_lists() {
        assert_eq!(parse_vector(b"[1.5, -2, 3e2]"), Some(vec![1.5, -2.0, 300.0]));
        assert_eq!(parse_vector(b"1 2 3"), Some(vec![1.0, 2.0, 3.0]));
        assert_eq!(parse_vector(b" 1,2\n3 , 4 "), Some(vec![1.0, 2.0, 3.0, 4.0]));
        assert_eq!(parse_vector(b"[]"), Some(vec![]));
        assert_eq!(parse_vector(b"  "), Some(vec![]));
    }

    #[test]
    fn refuses_malformed_input() {
        for bad in [
            &b"1,,2"[..],
            b"1,2,",
            b",1",
            b"[1, 2",
            b"1, 2]",
            b"[[1]]",
            b"one, two",
            b"NaN",
            b"1, inf",
            b"\xff\xfe",
        ] {
            assert_eq!(parse_vector(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn identical_vectors_are_at_distance_zero() {
        assert_eq!(distance(b"[1, 2, 3]", b"1 2 3"), 0.0);
        assert_eq!(distance(b"[0, 0]", b"[0, 0]"), 0.0);
        assert_eq!(distance(b"[]", b""), 0.0);
    }

    #[test]
    fn matches_hand_computed_values() {
        // Orthogonal unit vectors: sqrt(2) / 1.
        assert!(close(distance(b"[1, 0]", b"[0, 1]"), 2.0_f64.sqrt()));
        // Opposite vectors: the maximum, 2.
        assert!(close(distance(b"[3, 4]", b"[-3, -4]"), 2.0));
        // A small perturbation: ||(0, 0.1)|| / ||(3, 4.1)||.
        let want = 0.1 / (9.0_f64 + 4.1 * 4.1).sqrt();
        assert!((distance(b"[3, 4]", b"[3, 4.1]") - want).abs() < 1e-12);
        // Against zero: ||a|| / ||a|| = 1.
        assert!(close(distance(b"[0, 0]", b"[5, 0]"), 1.0));
    }

    #[test]
    fn symmetric_and_scale_invariant() {
        let a = [1.0, -2.5, 3.25, 7.0];
        let b = [1.1, -2.4, 3.0, 6.5];
        let d = relative_l2(&a, &b);
        assert!(close(d, relative_l2(&b, &a)));
        for k in [1e-200, 1e-3, 7.0, 1e200] {
            let ka: Vec<f64> = a.iter().map(|x| x * k).collect();
            let kb: Vec<f64> = b.iter().map(|x| x * k).collect();
            assert!((relative_l2(&ka, &kb) - d).abs() < 1e-9, "k = {k}");
        }
    }

    #[test]
    fn extreme_magnitudes_do_not_overflow() {
        let d = distance(b"[1e308, -1e308]", b"[-1e308, 1e308]");
        assert!(close(d, 2.0), "{d}");
    }

    #[test]
    fn incomparable_outputs_are_infinitely_far() {
        assert_eq!(distance(b"[1, 2]", b"[1, 2, 3]"), f64::INFINITY);
        assert_eq!(distance(b"[1, 2]", b"not numbers"), f64::INFINITY);
        assert_eq!(distance(b"oops", b"oops"), f64::INFINITY);
    }

    #[test]
    fn never_nan_or_negative() {
        let samples: [&[u8]; 6] = [b"", b"[0]", b"[1e308]", b"[-1e-308]", b"[1, 2]", b"x"];
        for a in samples {
            for b in samples {
                let d = distance(a, b);
                assert!(!d.is_nan() && d >= 0.0, "{d}");
            }
        }
    }
}
