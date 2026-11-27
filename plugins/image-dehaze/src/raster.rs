use std::io::{self, Cursor, Write};

use png::{BitDepth, ColorType, Decoder, DecodingError, Encoder, EncodingError, ScaledFloat};

use crate::{area, Error, MAX_BYTES};

const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const LINEAR_GAMMA: u32 = 100_000;
const CHROMATICITIES: [u32; 8] = [31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000];

pub(crate) struct Raster {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) pixels: Vec<[u16; 3]>,
}

pub(crate) fn read_rgb16(bytes: &[u8; 6]) -> [u16; 3] {
    let &[r_hi, r_lo, g_hi, g_lo, b_hi, b_lo] = bytes;
    [
        u16::from_be_bytes([r_hi, r_lo]),
        u16::from_be_bytes([g_hi, g_lo]),
        u16::from_be_bytes([b_hi, b_lo]),
    ]
}

pub(crate) fn decode(input: &[u8]) -> Result<Raster, Error> {
    let chromaticities_present = validate_profile(input)?;

    let mut decoder = Decoder::new(Cursor::new(input));
    decoder.set_limits(png::Limits {
        bytes: 32 * 1024 * 1024,
    });
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let info = decoder.read_header_info().map_err(decode_error)?;
    let (width, height) = (info.width as usize, info.height as usize);
    let count = area(width, height)?;
    if info.color_type != ColorType::Rgb || info.bit_depth != BitDepth::Sixteen {
        return Err(Error::InvalidInput("expected an RGB16 PNG".into()));
    }

    let mut reader = decoder.read_info().map_err(decode_error)?;
    let info = reader.info();
    if info.gama_chunk != Some(ScaledFloat::from_scaled(LINEAR_GAMMA))
        || info.chrm_chunk.is_some() != chromaticities_present
    {
        return Err(Error::InvalidInput("PNG has invalid color metadata".into()));
    }
    let mut samples = vec![0; count * 6];
    let frame = reader.next_frame(&mut samples).map_err(decode_error)?;
    if frame.buffer_size() != samples.len() {
        return Err(Error::InvalidInput("unexpected PNG raster length".into()));
    }
    reader.finish().map_err(decode_error)?;
    drop(reader);

    let pixels = samples.as_chunks::<6>().0.iter().map(read_rgb16).collect();
    Ok(Raster {
        width,
        height,
        pixels,
    })
}

fn decode_error(error: DecodingError) -> Error {
    match error {
        DecodingError::LimitsExceeded => {
            Error::ResourceExhausted("PNG decoder budget exceeded".into())
        }
        error => Error::InvalidInput(format!("invalid PNG: {error}")),
    }
}

fn validate_profile(input: &[u8]) -> Result<bool, Error> {
    fn malformed() -> Error {
        Error::InvalidInput("invalid PNG chunk boundaries".into())
    }

    let mut chunks = input
        .strip_prefix(SIGNATURE)
        .ok_or_else(|| Error::InvalidInput("expected a PNG image".into()))?;
    let mut gamma_seen = false;
    let mut chromaticities_seen = false;
    let mut image_started = false;
    // Walk the chunk framing without inflating ICC or ancillary text. The PNG
    // decoder still handles scanlines, chunk structure and the required CRCs.
    loop {
        let (size, rest) = chunks.split_first_chunk::<4>().ok_or_else(malformed)?;
        let size = u32::from_be_bytes(*size) as usize;
        let (tag, rest) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        let (data, rest) = rest.split_at_checked(size).ok_or_else(malformed)?;
        chunks = rest.get(4..).ok_or_else(malformed)?;
        match tag {
            b"gAMA" => {
                if image_started || gamma_seen || data != LINEAR_GAMMA.to_be_bytes() {
                    return Err(Error::InvalidInput(
                        "PNG must have one linear gAMA chunk (100000) before IDAT".into(),
                    ));
                }
                gamma_seen = true;
            }
            b"cHRM" => {
                let (coefficients, remainder) = data.as_chunks::<4>();
                if image_started
                    || chromaticities_seen
                    || !remainder.is_empty()
                    || !coefficients
                        .iter()
                        .copied()
                        .map(u32::from_be_bytes)
                        .eq(CHROMATICITIES)
                {
                    return Err(Error::InvalidInput(
                        "PNG chromaticities must match sRGB primaries and white point".into(),
                    ));
                }
                chromaticities_seen = true;
            }
            b"sRGB" | b"iCCP" | b"cICP" | b"tRNS" | b"acTL" | b"fcTL" | b"fdAT" => {
                return Err(Error::InvalidInput(
                    "PNG cannot use a competing color profile, transparency, or animation".into(),
                ));
            }
            b"IDAT" => image_started = true,
            b"IEND" => {
                if !data.is_empty() || !chunks.is_empty() {
                    return Err(malformed());
                }
                if !gamma_seen {
                    return Err(Error::InvalidInput(
                        "PNG must explicitly declare linear gAMA (100000)".into(),
                    ));
                }
                return Ok(chromaticities_seen);
            }
            _ => {}
        }
    }
}

pub(crate) fn encode(width: usize, height: usize, pixels: &[[u16; 3]]) -> Result<Vec<u8>, Error> {
    let mut samples = Vec::with_capacity(6 * pixels.len());
    for pixel in pixels {
        for sample in pixel {
            samples.extend_from_slice(&sample.to_be_bytes());
        }
    }

    let mut encoded = BoundedPng(Vec::new());
    let mut encoder = Encoder::new(&mut encoded, width as u32, height as u32);
    encoder.set_color(ColorType::Rgb);
    encoder.set_depth(BitDepth::Sixteen);
    encoder.set_compression(png::Compression::Fast);
    encoder.set_source_gamma(ScaledFloat::from_scaled(LINEAR_GAMMA));
    let [wx, wy, rx, ry, gx, gy, bx, by] = CHROMATICITIES.map(ScaledFloat::from_scaled);
    encoder.set_source_chromaticities(png::SourceChromaticities {
        white: (wx, wy),
        red: (rx, ry),
        green: (gx, gy),
        blue: (bx, by),
    });
    let mut writer = encoder.write_header().map_err(encode_error)?;
    writer.write_image_data(&samples).map_err(encode_error)?;
    writer.finish().map_err(encode_error)?;
    Ok(encoded.0)
}

fn encode_error(error: EncodingError) -> Error {
    match error {
        EncodingError::IoError(ref source) if source.kind() == io::ErrorKind::WriteZero => {
            Error::ResourceExhausted("encoded PNG exceeds 16 MiB".into())
        }
        error => Error::Internal(format!("could not encode PNG: {error}")),
    }
}

struct BoundedPng(Vec<u8>);

impl Write for BoundedPng {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
