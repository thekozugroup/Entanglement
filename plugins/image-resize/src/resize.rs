//! Pure, host-testable image-resize core. No SDK, no wasm, no I/O beyond
//! in-memory cursors.

use crate::error::{Error, Result};
use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use serde::Deserialize;
use std::io::Cursor;

/// Largest accepted input payload (header + encoded image).
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;

/// Longest accepted JSON header line.
pub const MAX_HEADER_BYTES: usize = 4096;

/// Largest source image we will decode, in pixels. 16 MP is 64 MiB as RGBA8; the
/// wasm store is capped at 256 MiB and we also need room for the resize output
/// and the encoder buffer.
pub const MAX_SRC_PIXELS: u64 = 16_000_000;

/// Largest output image we will produce, in pixels.
pub const MAX_DST_PIXELS: u64 = 16_000_000;

/// Largest accepted single dimension, source or target.
pub const MAX_DIM: u32 = 20_000;

/// Decoder allocation ceiling handed to `image`, as defence in depth behind the
/// pixel budget.
const MAX_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

/// How a target box is filled when both `width` and `height` are given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fit {
    /// Stretch to exactly `width` x `height`, ignoring the source aspect ratio.
    /// The default when both dimensions are given.
    Exact,
    /// Scale to fit *inside* the box, preserving aspect. The result may be
    /// smaller than the box on one axis.
    Contain,
    /// Scale to *cover* the box, preserving aspect, then centre-crop to exactly
    /// `width` x `height`.
    Cover,
}

/// Output container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutFormat {
    /// PNG. Lossless, alpha preserved.
    Png,
    /// Baseline JPEG. Lossy, alpha flattened away.
    Jpeg,
}

impl OutFormat {
    /// Lowercase name as accepted in the header.
    pub fn name(self) -> &'static str {
        match self {
            OutFormat::Png => "png",
            OutFormat::Jpeg => "jpeg",
        }
    }
}

/// The JSON header envelope. Unknown keys are rejected so typos surface instead
/// of being silently ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Target width in pixels. At least one of `width` / `height` is required.
    pub width: Option<u32>,
    /// Target height in pixels.
    pub height: Option<u32>,
    /// Output container: `"png"` or `"jpeg"` (`"jpg"` accepted). Defaults to the
    /// source format.
    pub format: Option<String>,
    /// JPEG quality, 1..=100. Ignored for PNG. Defaults to 85.
    pub quality: Option<u8>,
    /// Resampling filter. Defaults to `"lanczos3"`.
    pub filter: Option<String>,
    /// Box-filling strategy when both dimensions are given. Defaults to `exact`.
    pub fit: Option<Fit>,
}

/// A fully resolved plan: what to decode, what size to produce, how to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Target width.
    pub width: u32,
    /// Target height.
    pub height: u32,
    /// Resampling filter.
    pub filter: FilterType,
    /// Box-filling strategy.
    pub fit: Fit,
    /// Output container.
    pub format: OutFormat,
    /// JPEG quality (unused for PNG).
    pub quality: u8,
}

/// Split the newline-terminated JSON header off `input`.
///
/// Returns the parsed header and the encoded-image bytes that follow it.
pub fn split_envelope(input: &[u8]) -> Result<(Header, &[u8])> {
    if input.is_empty() {
        return Err(Error::InvalidInput(
            "empty input: expected a JSON header line such as {\"width\":800} \
             followed by a newline and then the PNG or JPEG bytes"
                .into(),
        ));
    }
    if input.len() > MAX_INPUT_BYTES {
        return Err(Error::ResourceExhausted(format!(
            "input is {} bytes, over the {MAX_INPUT_BYTES}-byte budget",
            input.len()
        )));
    }
    if input[0] != b'{' {
        return Err(Error::InvalidInput(format!(
            "input must begin with a JSON object header, but the first byte is 0x{:02x}; \
             expected something like {{\"width\":800}}\\n<image bytes>",
            input[0]
        )));
    }
    let scan = &input[..input.len().min(MAX_HEADER_BYTES)];
    let nl = scan.iter().position(|&b| b == b'\n').ok_or_else(|| {
        Error::InvalidInput(format!(
            "no newline found in the first {} bytes: the JSON header must be a single \
             line terminated by \\n, immediately followed by the image bytes",
            scan.len()
        ))
    })?;

    let header_bytes = &input[..nl];
    let header: Header = serde_json::from_slice(header_bytes).map_err(|e| {
        Error::InvalidInput(format!(
            "header is not a valid JSON object with the expected keys \
             (width, height, format, quality, filter, fit): {e}"
        ))
    })?;

    let body = &input[nl + 1..];
    if body.is_empty() {
        return Err(Error::InvalidInput(
            "header parsed, but there are no image bytes after the newline".into(),
        ));
    }
    Ok((header, body))
}

fn parse_filter(name: &str) -> Result<FilterType> {
    match name.to_ascii_lowercase().as_str() {
        "nearest" => Ok(FilterType::Nearest),
        "triangle" | "linear" => Ok(FilterType::Triangle),
        "catmullrom" | "catmull-rom" | "cubic" => Ok(FilterType::CatmullRom),
        "gaussian" => Ok(FilterType::Gaussian),
        "lanczos3" | "lanczos" => Ok(FilterType::Lanczos3),
        other => Err(Error::InvalidInput(format!(
            "unknown filter {other:?}; expected nearest, triangle, catmullrom, \
             gaussian or lanczos3"
        ))),
    }
}

fn parse_out_format(name: &str) -> Result<OutFormat> {
    match name.to_ascii_lowercase().as_str() {
        "png" => Ok(OutFormat::Png),
        "jpeg" | "jpg" => Ok(OutFormat::Jpeg),
        other => Err(Error::InvalidInput(format!(
            "unknown output format {other:?}; this plugin encodes png and jpeg only"
        ))),
    }
}

/// Scale `value` by `num / den`, rounding to nearest and clamping to at least 1.
fn scale_dim(value: u32, num: u32, den: u32) -> u32 {
    if den == 0 {
        return 1;
    }
    let v = (u64::from(value) * u64::from(num) + u64::from(den) / 2) / u64::from(den);
    v.clamp(1, u64::from(MAX_DIM)) as u32
}

/// Resolve a [`Header`] against the source dimensions into a concrete [`Plan`].
///
/// Aspect ratio is preserved whenever exactly one of `width` / `height` is given.
/// When both are given, `fit` decides (default `exact`).
pub fn plan(header: &Header, src_format: OutFormat, src_w: u32, src_h: u32) -> Result<Plan> {
    if src_w == 0 || src_h == 0 {
        return Err(Error::InvalidInput(format!(
            "source image has a zero dimension ({src_w}x{src_h})"
        )));
    }

    for (label, v) in [("width", header.width), ("height", header.height)] {
        if let Some(v) = v {
            if v == 0 {
                return Err(Error::InvalidInput(format!(
                    "{label} must be at least 1, got 0"
                )));
            }
            if v > MAX_DIM {
                return Err(Error::InvalidInput(format!(
                    "{label}={v} exceeds the {MAX_DIM}-pixel per-side limit"
                )));
            }
        }
    }

    let (width, height, fit) = match (header.width, header.height) {
        (None, None) => {
            return Err(Error::InvalidInput(
                "header must set at least one of \"width\" or \"height\"; the missing \
                 one is derived from the source aspect ratio"
                    .into(),
            ))
        }
        (Some(w), None) => (w, scale_dim(src_h, w, src_w), Fit::Exact),
        (None, Some(h)) => (scale_dim(src_w, h, src_h), h, Fit::Exact),
        (Some(w), Some(h)) => (w, h, header.fit.unwrap_or(Fit::Exact)),
    };

    let dst_pixels = u64::from(width) * u64::from(height);
    if dst_pixels > MAX_DST_PIXELS {
        return Err(Error::ResourceExhausted(format!(
            "target {width}x{height} is {dst_pixels} pixels, over the \
             {MAX_DST_PIXELS}-pixel output budget"
        )));
    }

    let filter = match header.filter.as_deref() {
        None => FilterType::Lanczos3,
        Some(name) => parse_filter(name)?,
    };
    let format = match header.format.as_deref() {
        None => src_format,
        Some(name) => parse_out_format(name)?,
    };
    let quality = match header.quality {
        None => 85,
        Some(q) if (1..=100).contains(&q) => q,
        Some(q) => {
            return Err(Error::InvalidInput(format!(
                "quality={q} out of range; expected 1..=100"
            )))
        }
    };

    Ok(Plan {
        width,
        height,
        filter,
        fit,
        format,
        quality,
    })
}

fn reader(data: &[u8]) -> Result<ImageReader<Cursor<&[u8]>>> {
    let mut r = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| Error::InvalidInput(format!("could not read the image container: {e}")))?;
    // `Limits` is #[non_exhaustive]; build from Default and override our fields.
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIM);
    limits.max_image_height = Some(MAX_DIM);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    r.limits(limits);
    Ok(r)
}

/// Sniff the container and read the pixel dimensions *without* decoding.
///
/// This is what keeps a malicious or merely huge image from being allocated: the
/// pixel budget is enforced from the header alone.
pub fn probe(data: &[u8]) -> Result<(OutFormat, u32, u32)> {
    let r = reader(data)?;
    let format = match r.format() {
        Some(ImageFormat::Png) => OutFormat::Png,
        Some(ImageFormat::Jpeg) => OutFormat::Jpeg,
        Some(other) => {
            return Err(Error::InvalidInput(format!(
                "input looks like {other:?}, but this plugin only decodes PNG and JPEG"
            )))
        }
        None => {
            return Err(Error::InvalidInput(
                "could not identify the image format from its magic bytes; expected PNG or JPEG"
                    .into(),
            ))
        }
    };
    let (w, h) = r.into_dimensions().map_err(|e| {
        Error::InvalidInput(format!(
            "could not read the {} header dimensions: {e}",
            format.name()
        ))
    })?;
    if w == 0 || h == 0 {
        return Err(Error::InvalidInput(format!(
            "image declares a zero dimension ({w}x{h})"
        )));
    }
    let pixels = u64::from(w) * u64::from(h);
    if pixels > MAX_SRC_PIXELS {
        return Err(Error::ResourceExhausted(format!(
            "source image is {w}x{h} = {pixels} pixels, over the {MAX_SRC_PIXELS}-pixel \
             budget ({} MiB as RGBA8); downscale it before sending",
            pixels * 4 / (1024 * 1024)
        )));
    }
    Ok((format, w, h))
}

/// Decode, resize according to `plan`, and re-encode.
pub fn transform(data: &[u8], p: &Plan) -> Result<Vec<u8>> {
    let img = reader(data)?
        .decode()
        .map_err(|e| Error::InvalidInput(format!("could not decode the image: {e}")))?;

    let resized: DynamicImage = match p.fit {
        Fit::Exact => img.resize_exact(p.width, p.height, p.filter),
        Fit::Contain => img.resize(p.width, p.height, p.filter),
        Fit::Cover => img.resize_to_fill(p.width, p.height, p.filter),
    };
    drop(img);

    encode(&resized, p)
}

/// Serialise `img` into `p.format`.
pub fn encode(img: &DynamicImage, p: &Plan) -> Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::<u8>::new());
    match p.format {
        OutFormat::Png => img
            .write_to(&mut out, ImageFormat::Png)
            .map_err(|e| Error::Internal(format!("PNG encoding failed: {e}")))?,
        OutFormat::Jpeg => {
            // JPEG has no alpha channel; flatten to RGB8 rather than letting the
            // encoder reject the buffer.
            let rgb = img.to_rgb8();
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, p.quality);
            enc.encode_image(&rgb)
                .map_err(|e| Error::Internal(format!("JPEG encoding failed: {e}")))?;
        }
    }
    Ok(out.into_inner())
}

/// Top-level entrypoint: split the envelope, probe, plan, transform.
pub fn process(input: &[u8]) -> Result<Vec<u8>> {
    let (header, body) = split_envelope(input)?;
    let (src_format, src_w, src_h) = probe(body)?;
    let p = plan(&header, src_format, src_w, src_h)?;
    transform(body, &p)
}

/// Human-readable one-liner for host-side logging.
pub fn describe(p: &Plan, src_w: u32, src_h: u32) -> String {
    format!(
        "{src_w}x{src_h} -> {}x{} ({:?}, {:?}) as {}{}",
        p.width,
        p.height,
        p.fit,
        p.filter,
        p.format.name(),
        if p.format == OutFormat::Jpeg {
            format!(" q{}", p.quality)
        } else {
            String::new()
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgba, RgbaImage};

    /// A deterministic gradient with a fully transparent corner, so alpha
    /// handling is observable.
    fn sample(w: u32, h: u32) -> DynamicImage {
        let img = RgbaImage::from_fn(w, h, |x, y| {
            if x < w / 4 && y < h / 4 {
                Rgba([0, 0, 0, 0])
            } else {
                Rgba([(x * 255 / w.max(1)) as u8, (y * 255 / h.max(1)) as u8, 128, 255])
            }
        });
        DynamicImage::ImageRgba8(img)
    }

    fn as_png(img: &DynamicImage) -> Vec<u8> {
        let mut c = Cursor::new(Vec::new());
        img.write_to(&mut c, ImageFormat::Png).expect("encode png");
        c.into_inner()
    }

    fn as_jpeg(img: &DynamicImage) -> Vec<u8> {
        let mut c = Cursor::new(Vec::new());
        let rgb = img.to_rgb8();
        let mut e = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut c, 90);
        e.encode_image(&rgb).expect("encode jpeg");
        c.into_inner()
    }

    fn envelope(header: &str, body: &[u8]) -> Vec<u8> {
        let mut v = header.as_bytes().to_vec();
        v.push(b'\n');
        v.extend_from_slice(body);
        v
    }

    /// Decode plugin output back into `(format, width, height)`.
    fn decoded(out: &[u8]) -> (ImageFormat, u32, u32) {
        let r = ImageReader::new(Cursor::new(out))
            .with_guessed_format()
            .expect("guess format");
        let fmt = r.format().expect("format");
        let img = r.decode().expect("decode output");
        (fmt, img.width(), img.height())
    }

    // ---- happy paths ----

    #[test]
    fn png_resized_to_both_dimensions() {
        let src = as_png(&sample(120, 80));
        let out = process(&envelope(r#"{"width":60,"height":40}"#, &src)).expect("process");
        assert_eq!(decoded(&out), (ImageFormat::Png, 60, 40));
    }

    #[test]
    fn width_only_preserves_aspect_ratio() {
        let src = as_png(&sample(200, 100));
        let out = process(&envelope(r#"{"width":50}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 50, 25));
    }

    #[test]
    fn height_only_preserves_aspect_ratio() {
        let src = as_png(&sample(200, 100));
        let out = process(&envelope(r#"{"height":25}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 50, 25));
    }

    #[test]
    fn aspect_derivation_rounds_and_never_reaches_zero() {
        // 100x3 scaled to width 10 -> height round(0.3) = 0, clamped to 1.
        let src = as_png(&sample(100, 3));
        let out = process(&envelope(r#"{"width":10}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 10, 1));

        // Rounding is to nearest: 100x7 at width 10 -> 0.7 -> 1.
        let src = as_png(&sample(100, 7));
        let out = process(&envelope(r#"{"height":1}"#, &src)).unwrap();
        assert_eq!(decoded(&out).1, 14); // round(100 * 1 / 7) = 14
    }

    #[test]
    fn upscaling_works_too() {
        let src = as_png(&sample(10, 10));
        let out = process(&envelope(r#"{"width":100}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 100, 100));
    }

    #[test]
    fn jpeg_input_round_trips_and_defaults_to_jpeg_output() {
        let src = as_jpeg(&sample(64, 64));
        let out = process(&envelope(r#"{"width":32}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Jpeg, 32, 32));
    }

    #[test]
    fn format_can_be_switched_in_both_directions() {
        let png = as_png(&sample(40, 40));
        let out = process(&envelope(r#"{"width":20,"format":"jpeg","quality":70}"#, &png)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Jpeg, 20, 20));

        let jpg = as_jpeg(&sample(40, 40));
        let out = process(&envelope(r#"{"width":20,"format":"png"}"#, &jpg)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 20, 20));

        // "jpg" is accepted as an alias.
        let out = process(&envelope(r#"{"width":20,"format":"jpg"}"#, &png)).unwrap();
        assert_eq!(decoded(&out).0, ImageFormat::Jpeg);
    }

    #[test]
    fn jpeg_quality_changes_output_size() {
        let src = as_png(&sample(160, 160));
        let lo = process(&envelope(r#"{"width":160,"format":"jpeg","quality":10}"#, &src)).unwrap();
        let hi = process(&envelope(r#"{"width":160,"format":"jpeg","quality":95}"#, &src)).unwrap();
        assert!(
            lo.len() < hi.len(),
            "q10 ({} bytes) should be smaller than q95 ({} bytes)",
            lo.len(),
            hi.len()
        );
    }

    #[test]
    fn fit_contain_preserves_aspect_inside_the_box() {
        let src = as_png(&sample(200, 100)); // 2:1
        let out = process(&envelope(r#"{"width":50,"height":50,"fit":"contain"}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 50, 25));
    }

    #[test]
    fn fit_cover_fills_the_box_exactly() {
        let src = as_png(&sample(200, 100));
        let out = process(&envelope(r#"{"width":50,"height":50,"fit":"cover"}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 50, 50));
    }

    #[test]
    fn fit_exact_is_the_default_and_stretches() {
        let src = as_png(&sample(200, 100));
        let a = process(&envelope(r#"{"width":50,"height":50}"#, &src)).unwrap();
        let b = process(&envelope(r#"{"width":50,"height":50,"fit":"exact"}"#, &src)).unwrap();
        assert_eq!(decoded(&a), (ImageFormat::Png, 50, 50));
        assert_eq!(a, b);
    }

    #[test]
    fn every_filter_name_is_accepted() {
        let src = as_png(&sample(40, 40));
        for name in [
            "nearest", "triangle", "linear", "catmullrom", "catmull-rom", "cubic", "gaussian",
            "lanczos3", "lanczos", "LANCZOS3",
        ] {
            let h = format!(r#"{{"width":20,"filter":"{name}"}}"#);
            let out = process(&envelope(&h, &src)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(decoded(&out).1, 20, "{name}");
        }
    }

    #[test]
    fn png_output_keeps_the_alpha_channel() {
        let src = as_png(&sample(64, 64));
        let out = process(&envelope(r#"{"width":32,"filter":"nearest"}"#, &src)).unwrap();
        let img = image::load_from_memory(&out).unwrap();
        assert!(
            img.color().has_alpha(),
            "expected an alpha channel, got {:?}",
            img.color()
        );
        // The transparent top-left corner survives.
        assert_eq!(img.to_rgba8().get_pixel(1, 1)[3], 0);
    }

    #[test]
    fn one_by_one_target_is_allowed() {
        let src = as_png(&sample(50, 50));
        let out = process(&envelope(r#"{"width":1,"height":1}"#, &src)).unwrap();
        assert_eq!(decoded(&out), (ImageFormat::Png, 1, 1));
    }

    #[test]
    fn plan_resolution_is_pure_and_predictable() {
        let h: Header = serde_json::from_str(r#"{"width":100}"#).unwrap();
        let p = plan(&h, OutFormat::Png, 400, 300).unwrap();
        assert_eq!(
            p,
            Plan {
                width: 100,
                height: 75,
                filter: FilterType::Lanczos3,
                fit: Fit::Exact,
                format: OutFormat::Png,
                quality: 85,
            }
        );
        assert!(describe(&p, 400, 300).contains("400x300 -> 100x75"));
    }

    // ---- error paths: nothing below may panic ----

    #[test]
    fn empty_input_is_invalid_input() {
        let err = process(b"").unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert!(err.to_string().contains("empty input"), "{err}");
    }

    #[test]
    fn missing_header_is_named_clearly() {
        let src = as_png(&sample(10, 10));
        let err = process(&src).unwrap_err();
        assert!(err.to_string().contains("must begin with a JSON object header"), "{err}");
        assert!(err.to_string().contains("width"), "{err}");
    }

    #[test]
    fn header_without_newline_is_rejected() {
        let err = process(br#"{"width":10}"#).unwrap_err();
        assert!(err.to_string().contains("no newline found"), "{err}");
    }

    #[test]
    fn header_with_no_image_bytes_is_rejected() {
        let err = process(b"{\"width\":10}\n").unwrap_err();
        assert!(err.to_string().contains("no image bytes after the newline"), "{err}");
    }

    #[test]
    fn malformed_json_header_is_rejected() {
        let src = as_png(&sample(10, 10));
        for h in [r#"{"width":10"#, r#"{width:10}"#, r#"{"width":"big"}"#, "{}}"] {
            let err = process(&envelope(h, &src)).unwrap_err();
            assert!(
                err.to_string().contains("not a valid JSON object")
                    || err.to_string().contains("no newline found"),
                "{h}: {err}"
            );
        }
    }

    #[test]
    fn unknown_header_key_is_rejected() {
        let src = as_png(&sample(10, 10));
        let err = process(&envelope(r#"{"width":10,"widht":20}"#, &src)).unwrap_err();
        assert!(err.to_string().contains("not a valid JSON object"), "{err}");
        assert!(err.to_string().contains("widht"), "{err}");
    }

    #[test]
    fn no_dimensions_at_all_is_rejected() {
        let src = as_png(&sample(10, 10));
        let err = process(&envelope(r#"{"filter":"nearest"}"#, &src)).unwrap_err();
        assert!(err.to_string().contains("at least one of"), "{err}");
    }

    #[test]
    fn zero_and_oversize_dimensions_are_rejected() {
        let src = as_png(&sample(10, 10));
        let cases: &[(&str, &str)] = &[
            (r#"{"width":0}"#, "width must be at least 1"),
            (r#"{"height":0}"#, "height must be at least 1"),
            (r#"{"width":20001}"#, "width=20001 exceeds"),
            (r#"{"height":99999}"#, "height=99999 exceeds"),
        ];
        for (h, needle) in cases {
            let err = process(&envelope(h, &src)).unwrap_err();
            assert!(err.to_string().contains(needle), "{h}: expected {needle:?}, got {err}");
        }
    }

    #[test]
    fn oversize_target_area_is_resource_exhausted() {
        let src = as_png(&sample(10, 10));
        // 20000 x 20000 = 400 MP, well past MAX_DST_PIXELS but under MAX_DIM.
        let err = process(&envelope(r#"{"width":20000,"height":20000}"#, &src)).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "{err:?}");
        assert!(err.to_string().contains("output budget"), "{err}");
    }

    /// PNG chunk CRC-32 (IEEE, reflected), so the synthetic header below is
    /// well-formed enough for the decoder to read its dimensions.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        let mut body = Vec::with_capacity(4 + data.len());
        body.extend_from_slice(kind);
        body.extend_from_slice(data);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    }

    /// A structurally valid PNG that declares `w` x `h` but carries no pixel data:
    /// enough for the decoder to report dimensions, far too little to decode.
    fn png_header_only(w: u32, h: u32) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png_chunk(&mut png, b"IHDR", &ihdr);
        png_chunk(&mut png, b"IDAT", &[]);
        png_chunk(&mut png, b"IEND", &[]);
        png
    }

    #[test]
    fn oversize_source_is_rejected_without_decoding() {
        // A PNG whose IHDR claims 19000x19000 (361 MP) but which carries no pixel
        // data at all. `probe` reads only the header, so the pixel budget must
        // reject this before anything is allocated.
        let png = png_header_only(19_000, 19_000);
        assert!(png.len() < 100, "header-only PNG should be tiny, got {}", png.len());
        let err = process(&envelope(r#"{"width":100}"#, &png)).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "{err:?}");
        assert!(err.to_string().contains("19000x19000"), "{err}");
        assert!(err.to_string().contains("pixel"), "{err}");
    }

    #[test]
    fn source_just_inside_the_pixel_budget_passes_probe() {
        // 4000x4000 = 16 MP, exactly MAX_SRC_PIXELS. probe() accepts it (decoding
        // then fails, since there is no IDAT — which is the point: the budget is
        // not what rejected it).
        let png = png_header_only(4000, 4000);
        assert_eq!(probe(&png).unwrap(), (OutFormat::Png, 4000, 4000));
        // One pixel more, and the budget bites.
        let err = probe(&png_header_only(4000, 4001)).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "{err:?}");
    }

    #[test]
    fn source_wider_than_max_dim_is_rejected_by_the_decoder_limits() {
        let err = probe(&png_header_only(MAX_DIM + 1, 2)).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn bad_quality_and_filter_and_format_are_rejected() {
        let src = as_png(&sample(10, 10));
        let cases: &[(&str, &str)] = &[
            (r#"{"width":5,"quality":0}"#, "quality=0 out of range"),
            (r#"{"width":5,"quality":101}"#, "quality=101 out of range"),
            (r#"{"width":5,"quality":9999}"#, "not a valid JSON object"), // past u8
            (r#"{"width":5,"quality":-1}"#, "not a valid JSON object"),
            (r#"{"width":5,"filter":"bicubic"}"#, "unknown filter"),
            (r#"{"width":5,"format":"webp"}"#, "unknown output format"),
            (r#"{"width":5,"fit":"squish"}"#, "not a valid JSON object"),
            (r#"{"width":-5}"#, "not a valid JSON object"),
        ];
        for (h, needle) in cases {
            let err = process(&envelope(h, &src)).unwrap_err();
            assert!(err.to_string().contains(needle), "{h}: expected {needle:?}, got {err}");
        }
        // Both ends of the valid quality range work.
        assert!(process(&envelope(r#"{"width":5,"quality":100}"#, &src)).is_ok());
        assert!(process(&envelope(r#"{"width":5,"quality":1}"#, &src)).is_ok());
    }

    #[test]
    fn unrecognised_image_bytes_are_rejected() {
        let err = process(&envelope(r#"{"width":10}"#, b"this is definitely not an image")).unwrap_err();
        assert!(
            err.to_string().contains("could not identify the image format"),
            "{err}"
        );
    }

    #[test]
    fn truncated_png_is_rejected_not_panicked() {
        let src = as_png(&sample(64, 64));
        for frac in [2usize, 4, 8] {
            let cut = src.len() / frac;
            let err = process(&envelope(r#"{"width":10}"#, &src[..cut])).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "cut 1/{frac}: {err:?}");
        }
    }

    #[test]
    fn header_only_png_magic_with_no_ihdr_is_rejected() {
        let err = process(&envelope(
            r#"{"width":10}"#,
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        ))
        .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn corrupt_png_body_is_rejected() {
        let mut src = as_png(&sample(64, 64));
        // Scribble over the IDAT payload, leaving the IHDR intact so probe passes
        // and the failure lands in the decoder.
        let n = src.len();
        for b in src[n / 2..n - 12].iter_mut() {
            *b ^= 0x5a;
        }
        let err = process(&envelope(r#"{"width":10}"#, &src)).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert!(err.to_string().contains("decode"), "{err}");
    }

    #[test]
    fn oversize_input_payload_is_resource_exhausted() {
        let big = vec![b'{'; MAX_INPUT_BYTES + 1];
        let err = process(&big).unwrap_err();
        assert!(matches!(err, Error::ResourceExhausted(_)), "{err:?}");
        assert!(err.to_string().contains("byte budget"), "{err}");
    }

    #[test]
    fn absurdly_long_header_line_is_rejected() {
        let src = as_png(&sample(10, 10));
        let mut h = String::from("{\"width\":10,\"filter\":\"");
        h.push_str(&"x".repeat(MAX_HEADER_BYTES));
        h.push_str("\"}");
        let err = process(&envelope(&h, &src)).unwrap_err();
        assert!(err.to_string().contains("no newline found"), "{err}");
    }

    #[test]
    fn plan_rejects_zero_source_dimensions() {
        let h: Header = serde_json::from_str(r#"{"width":10}"#).unwrap();
        let err = plan(&h, OutFormat::Png, 0, 10).unwrap_err();
        assert!(err.to_string().contains("zero dimension"), "{err}");
    }

    #[test]
    fn scale_dim_is_saturating_and_never_panics() {
        assert_eq!(scale_dim(0, 5, 5), 1);
        assert_eq!(scale_dim(10, 1, 0), 1);
        assert_eq!(scale_dim(u32::MAX, u32::MAX, 1), MAX_DIM);
        assert_eq!(scale_dim(100, 1, 3), 33);
        assert_eq!(scale_dim(100, 2, 3), 67);
    }
}
