//! Bounded, linear-light RGB16 rasters for the camera RAW dehaze command.

use anyhow::{bail, ensure, Context, Result};
use png::{BitDepth, ColorType, ScaledFloat, SourceChromaticities};
use std::fs::OpenOptions;
use std::io::{BufReader, Cursor, Read, Write};
use std::path::Path;

pub(super) const MAX_PIXELS: usize = 32_000_000;
pub(super) const MAX_DIMENSION: u32 = 32_768;
pub(super) const DEFAULT_TILE_EDGE: u32 = 1024;
pub(super) const MAX_TILE_EDGE: u32 = 1536;
const MIN_TILE_EDGE: u32 = 16;
const RADIUS: usize = 7;
const WINDOW: usize = 2 * RADIUS + 1;
const HEADER_LIMIT: usize = 1024;
const WIRE_LIMIT: usize = 16 * 1024 * 1024;

fn pixel_count(width: u32, height: u32) -> Result<usize> {
    ensure!(
        (1..=MAX_DIMENSION).contains(&width) && (1..=MAX_DIMENSION).contains(&height),
        "raster dimensions {width} by {height} are out of range"
    );
    let count = width as usize * height as usize;
    ensure!(count <= MAX_PIXELS, "raster exceeds {MAX_PIXELS} pixels");
    Ok(count)
}

pub(super) struct Raster {
    width: u32,
    height: u32,
    pixels: Vec<u16>,
}

impl Raster {
    pub(super) fn open_ppm(path: &Path) -> Result<Self> {
        let mut open = OpenOptions::new();
        open.read(true);
        #[cfg(unix)]
        {
            use rustix::fs::OFlags;
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
        }
        let file = open.open(path).context("opening RAW decoder output")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= (MAX_PIXELS * 6 + HEADER_LIMIT) as u64,
            "decoder output must be a bounded regular P6 file"
        );
        Self::decode_ppm(file)
    }

    pub(super) fn decode_ppm(reader: impl Read) -> Result<Self> {
        let mut reader = BufReader::new(reader);
        let mut used = 0;
        let (magic, _) = header_token(&mut reader, &mut used)?;
        ensure!(magic == "P6", "expected binary P6 decoder output");
        let (width, _) = header_token(&mut reader, &mut used)?;
        let (height, _) = header_token(&mut reader, &mut used)?;
        let (maximum, delimiter) = header_token(&mut reader, &mut used)?;
        ensure!(
            maximum == "65535" && delimiter.is_ascii_whitespace(),
            "expected full-scale 16-bit P6 samples"
        );
        ensure!(
            width
                .bytes()
                .chain(height.bytes())
                .all(|b| b.is_ascii_digit()),
            "P6 dimensions must be decimal integers"
        );
        let width = width.parse::<u32>()?;
        let height = height.parse::<u32>()?;
        let count = pixel_count(width, height)?;
        let mut pixels = Vec::new();
        pixels.try_reserve_exact(count * 3)?;
        let mut row = vec![0; width as usize * 6];
        for _ in 0..height {
            reader
                .read_exact(&mut row)
                .context("truncated 16-bit P6 raster")?;
            pixels.extend(
                row.chunks_exact(2)
                    .map(|v| u16::from_be_bytes([v[0], v[1]])),
            );
        }
        ensure!(reader.read(&mut [0])? == 0, "trailing data after P6 raster");
        Self::from_linear_rgb16(width, height, pixels)
    }

    pub(super) fn from_linear_rgb16(width: u32, height: u32, pixels: Vec<u16>) -> Result<Self> {
        ensure!(
            pixels.len() == pixel_count(width, height)? * 3,
            "RGB16 sample count mismatch"
        );
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    pub(super) fn width(&self) -> u32 {
        self.width
    }

    pub(super) fn height(&self) -> u32 {
        self.height
    }

    pub(super) fn tiles(&self, edge: u32) -> Result<Vec<Tile>> {
        ensure!(
            (MIN_TILE_EDGE..=MAX_TILE_EDGE).contains(&edge),
            "tile edge must be {MIN_TILE_EDGE}..={MAX_TILE_EDGE}"
        );
        let mut result = Vec::new();
        for y in (0..self.height).step_by(edge as usize) {
            for x in (0..self.width).step_by(edge as usize) {
                result.push(Tile {
                    ordinal: result.len(),
                    x,
                    y,
                    width: edge.min(self.width - x),
                    height: edge.min(self.height - y),
                    edge,
                    source: (self.width, self.height),
                });
            }
        }
        Ok(result)
    }

    /// Select the brightest original pixel among the top 0.1% of dark-channel values.
    /// A histogram finds the cutoff; two row-major passes resolve both ties deterministically.
    pub(super) fn atmosphere(&self) -> [u16; 3] {
        let count = self.pixels.len() / 3;
        let k = (count / 1000).max(1);
        let mut histogram = vec![0u32; 1 << 16];
        self.visit_dark(|_, value| histogram[value as usize] += 1);
        let mut at_cutoff = k;
        let cutoff = (0..histogram.len())
            .rev()
            .find(|&value| {
                if histogram[value] as usize >= at_cutoff {
                    true
                } else {
                    at_cutoff -= histogram[value] as usize;
                    false
                }
            })
            .expect("nonempty verified raster") as u16;
        let mut best_sum = None;
        let mut best = [0; 3];
        self.visit_dark(|index, value| {
            if value < cutoff || (value == cutoff && at_cutoff == 0) {
                return;
            }
            if value == cutoff {
                at_cutoff -= 1;
            }
            let rgb = &self.pixels[index * 3..index * 3 + 3];
            let sum = u32::from(rgb[0]) + u32::from(rgb[1]) + u32::from(rgb[2]);
            if best_sum.is_none_or(|previous| sum > previous) {
                best_sum = Some(sum);
                best.copy_from_slice(rgb);
            }
        });
        best
    }

    fn visit_dark(&self, mut visit: impl FnMut(usize, u16)) {
        let (w, h) = (self.width as usize, self.height as usize);
        let mut columns = vec![SlidingMin::default(); w];
        let mut row = vec![0; w];
        for y in 0..h + RADIUS {
            if y < h {
                let mut line = SlidingMin::default();
                for x in 0..w + RADIUS {
                    let v = (x < w).then(|| {
                        let i = (y * w + x) * 3;
                        self.pixels[i]
                            .min(self.pixels[i + 1])
                            .min(self.pixels[i + 2])
                    });
                    let min = line.advance(x, v);
                    if x >= RADIUS {
                        row[x - RADIUS] = min;
                    }
                }
            }
            for (x, col) in columns.iter_mut().enumerate() {
                let min = col.advance(y, (y < h).then_some(row[x]));
                if y >= RADIUS {
                    visit((y - RADIUS) * w + x, min);
                }
            }
        }
    }

    pub(super) fn encode_tile(&self, tile: &Tile, atmosphere: [u16; 3]) -> Result<Vec<u8>> {
        tile.check(self.width, self.height)?;
        let (left, top, w, h) = tile.extent();
        let mut out = Vec::from(*b"EDH1");
        for channel in atmosphere {
            out.extend_from_slice(&channel.to_be_bytes());
        }
        let mut writer = encoder(&mut out, w, h).write_header()?;
        let mut row = vec![0u8; w as usize * 6];
        {
            let mut stream = writer.stream_writer()?;
            for y in top..top + h {
                let start = ((y * self.width + left) * 3) as usize;
                let src = &self.pixels[start..start + w as usize * 3];
                for (dst, sample) in row.chunks_exact_mut(2).zip(src) {
                    dst.copy_from_slice(&sample.to_be_bytes());
                }
                stream.write_all(&row)?;
            }
            stream.finish()?;
        }
        writer.finish()?;
        ensure!(
            out.len() <= WIRE_LIMIT,
            "encoded tile exceeds scheduler input cap"
        );
        Ok(out)
    }
}

/// Tokenizer consumes exactly one delimiter after Maxval: whitespace and '#' in the raster are data.
fn header_token(reader: &mut impl Read, used: &mut usize) -> Result<(String, u8)> {
    let mut token = Vec::new();
    let mut comment = false;
    loop {
        ensure!(
            *used < HEADER_LIMIT,
            "P6 header exceeds {HEADER_LIMIT} bytes"
        );
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .context("truncated P6 header")?;
        *used += 1;
        let b = byte[0];
        if comment {
            if b == b'\n' {
                comment = false;
            }
            continue;
        }
        if b.is_ascii_whitespace() {
            if !token.is_empty() {
                return Ok((String::from_utf8(token)?, b));
            }
        } else if b == b'#' && token.is_empty() {
            comment = true;
        } else {
            ensure!(
                b.is_ascii_graphic() && token.len() < 16,
                "invalid P6 header token"
            );
            token.push(b);
        }
    }
}

#[derive(Clone, Default)]
struct SlidingMin {
    positions: [usize; WINDOW],
    values: [u16; WINDOW],
    front: usize,
    len: usize,
}

impl SlidingMin {
    /// Expire the oldest position at the front and discard larger values at the back.
    fn advance(&mut self, pos: usize, input: Option<u16>) -> u16 {
        if self.len > 0 && pos - self.positions[self.front] >= WINDOW {
            self.front = (self.front + 1) % WINDOW;
            self.len -= 1;
        }
        if let Some(value) = input {
            while self.len > 0 && self.values[(self.front + self.len - 1) % WINDOW] >= value {
                self.len -= 1;
            }
            let tail = (self.front + self.len) % WINDOW;
            self.positions[tail] = pos;
            self.values[tail] = value;
            self.len += 1;
        }
        self.values[self.front]
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Tile {
    pub(super) ordinal: usize,
    pub(super) x: u32,
    pub(super) y: u32,
    pub(super) width: u32,
    pub(super) height: u32,
    edge: u32,
    source: (u32, u32),
}

impl Tile {
    fn check(&self, w: u32, h: u32) -> Result<()> {
        ensure!(
            self.source == (w, h) && (MIN_TILE_EDGE..=MAX_TILE_EDGE).contains(&self.edge),
            "tile belongs to different raster geometry"
        );
        let columns = w.div_ceil(self.edge);
        ensure!(
            self.ordinal < (columns * h.div_ceil(self.edge)) as usize,
            "invalid tile ordinal"
        );
        let x = (self.ordinal as u32 % columns) * self.edge;
        let y = (self.ordinal as u32 / columns) * self.edge;
        ensure!(
            (self.x, self.y, self.width, self.height)
                == (x, y, self.edge.min(w - x), self.edge.min(h - y)),
            "invalid tile core geometry"
        );
        Ok(())
    }

    fn extent(&self) -> (u32, u32, u32, u32) {
        let r = RADIUS as u32;
        let left = self.x.saturating_sub(r);
        let top = self.y.saturating_sub(r);
        let right = (self.x + self.width + r).min(self.source.0);
        let bottom = (self.y + self.height + r).min(self.source.1);
        (left, top, right - left, bottom - top)
    }
}

fn primaries() -> SourceChromaticities {
    let pair = |x, y| (ScaledFloat::from_scaled(x), ScaledFloat::from_scaled(y));
    SourceChromaticities {
        white: pair(31270, 32900),
        red: pair(64000, 33000),
        green: pair(30000, 60000),
        blue: pair(15000, 6000),
    }
}

fn encoder<W: Write>(writer: W, w: u32, h: u32) -> png::Encoder<'static, W> {
    let mut encoder = png::Encoder::new(writer, w, h);
    encoder.set_color(ColorType::Rgb);
    encoder.set_depth(BitDepth::Sixteen);
    encoder.set_source_gamma(ScaledFloat::from_scaled(100_000));
    encoder.set_source_chromaticities(primaries());
    encoder.set_compression(png::Compression::Fast);
    encoder
}

pub(super) struct RasterOutput {
    width: u32,
    height: u32,
    data: Vec<u8>,
    edge: Option<u32>,
    placed: Vec<bool>,
}

impl RasterOutput {
    pub(super) fn new(raster: &Raster) -> Result<Self> {
        let len = raster.pixels.len() * 2;
        let mut data = Vec::new();
        data.try_reserve_exact(len)?;
        data.resize(len, 0);
        Ok(Self {
            width: raster.width,
            height: raster.height,
            data,
            edge: None,
            placed: Vec::new(),
        })
    }

    pub(super) fn place(&mut self, tile: &Tile, bytes: &[u8]) -> Result<()> {
        tile.check(self.width, self.height)?;
        if let Some(edge) = self.edge {
            ensure!(edge == tile.edge, "inconsistent tile grid");
        } else {
            self.edge = Some(tile.edge);
            self.placed.resize(
                (self.width.div_ceil(tile.edge) * self.height.div_ceil(tile.edge)) as usize,
                false,
            );
        }
        ensure!(
            !self.placed[tile.ordinal],
            "duplicate tile {}",
            tile.ordinal
        );
        let (left, top, w, h) = tile.extent();
        checked_png_chunks(bytes)?;
        let mut decoder = png::Decoder::new(Cursor::new(bytes));
        decoder.set_limits(png::Limits {
            bytes: 32 * 1024 * 1024,
        });
        let header = decoder.read_header_info()?;
        ensure!(
            header.width == w
                && header.height == h
                && header.bit_depth == BitDepth::Sixteen
                && header.color_type == ColorType::Rgb
                && !header.interlaced,
            "tile geometry or format differs from request"
        );
        let mut reader = decoder.read_info()?;
        let info = reader.info();
        ensure!(
            info.gama_chunk == Some(ScaledFloat::from_scaled(100_000))
                && info.chrm_chunk == Some(primaries()),
            "tile linear RGB16 profile differs from request"
        );
        let skip = ((tile.x - left) * 6) as usize;
        let len = (tile.width * 6) as usize;
        for y in top..top + h {
            let row = reader.next_row()?.context("missing dehazed tile row")?;
            ensure!(
                row.data().len() == w as usize * 6,
                "invalid tile row length"
            );
            if (tile.y..tile.y + tile.height).contains(&y) {
                let dest = ((y * self.width + tile.x) * 6) as usize;
                self.data[dest..dest + len].copy_from_slice(&row.data()[skip..skip + len]);
            }
        }
        reader.finish()?;
        self.placed[tile.ordinal] = true;
        Ok(())
    }

    pub(super) fn write_png(self, output: impl Write) -> Result<()> {
        ensure!(
            !self.placed.is_empty() && self.placed.iter().all(|x| *x),
            "cannot publish incomplete dehazed raster"
        );
        let mut writer = encoder(output, self.width, self.height).write_header()?;
        {
            let mut stream = writer.stream_writer()?;
            for row in self.data.chunks_exact(self.width as usize * 6) {
                stream.write_all(row)?;
            }
            stream.finish()?;
        }
        writer.finish()?;
        Ok(())
    }
}

/// The fixed guest emits these five chunks. Reject other metadata before the decoder can expand it.
fn checked_png_chunks(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= WIRE_LIMIT && bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "invalid or oversized guest PNG"
    );
    let mut chunks = &bytes[8..];
    let mut header = false;
    let mut gamma = false;
    let mut chroma = false;
    let mut data = false;
    while chunks.len() >= 12 {
        let n = u32::from_be_bytes(chunks[..4].try_into()?) as usize;
        ensure!(n <= chunks.len() - 12, "truncated guest PNG chunk");
        match &chunks[4..8] {
            b"IHDR" if !header && chunks.len() == bytes.len() - 8 && n == 13 => header = true,
            b"gAMA" if header && !data && !gamma && n == 4 => gamma = true,
            b"cHRM" if header && !data && !chroma && n == 32 => chroma = true,
            b"IDAT" if header && gamma && chroma => data = true,
            b"IEND" if data && n == 0 && chunks.len() == 12 => return Ok(()),
            _ => bail!("unexpected or invalid guest PNG chunk"),
        }
        chunks = &chunks[12 + n..];
    }
    bail!("missing guest PNG end marker")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;

    fn scene(w: u32, h: u32) -> Raster {
        let pixels = (0..w * h)
            .flat_map(|i| {
                let x = i % w;
                let y = i / w;
                [
                    ((x * 1777 + y * 311) % 65536) as u16,
                    ((x * 613 + y * 2093) % 65536) as u16,
                    ((x * 2857 + y * 665) % 65536) as u16,
                ]
            })
            .collect();
        Raster::from_linear_rgb16(w, h, pixels).unwrap()
    }

    fn minimum(r: &Raster, i: usize, value: impl Fn(&[u16]) -> u16) -> u16 {
        let w = r.width as usize;
        let h = r.height as usize;
        let x = i % w;
        let y = i / w;
        let mut min = u16::MAX;
        for py in y.saturating_sub(RADIUS)..=(y + RADIUS).min(h - 1) {
            for px in x.saturating_sub(RADIUS)..=(x + RADIUS).min(w - 1) {
                let at = (py * w + px) * 3;
                min = min.min(value(&r.pixels[at..at + 3]));
            }
        }
        min
    }

    fn oracle_air(r: &Raster) -> [u16; 3] {
        let mut order = (0..r.pixels.len() / 3)
            .map(|i| (Reverse(minimum(r, i, |v| *v.iter().min().unwrap())), i))
            .collect::<Vec<_>>();
        order.sort_unstable();
        let best = order
            .iter()
            .take((order.len() / 1000).max(1))
            .map(|&(_, i)| {
                (
                    r.pixels[i * 3..i * 3 + 3]
                        .iter()
                        .copied()
                        .map(u32::from)
                        .sum::<u32>(),
                    Reverse(i),
                )
            })
            .max()
            .unwrap()
            .1
             .0;
        r.pixels[best * 3..best * 3 + 3].try_into().unwrap()
    }

    fn naive_dehaze(r: &Raster, a: [u16; 3]) -> Vec<u16> {
        let mut out = Vec::with_capacity(r.pixels.len());
        for (i, rgb) in r.pixels.chunks_exact(3).enumerate() {
            let dark = minimum(r, i, |v| {
                (0..3)
                    .map(|c| {
                        let denom = u64::from(a[c]).max(1);
                        ((u64::from(v[c]) * 65535 + denom / 2) / denom).min(65535) as u16
                    })
                    .min()
                    .unwrap()
            });
            let t = (65535 - (95 * i64::from(dark) + 50) / 100).max(6554);
            for c in 0..3 {
                let d = i64::from(rgb[c]) - i64::from(a[c]);
                let reconstructed = i64::from(a[c]) + d.signum() * ((d.abs() * 65535 + t / 2) / t);
                out.push(reconstructed.clamp(0, 65535) as u16);
            }
        }
        out
    }

    fn pack(w: u32, h: u32, samples: &[u16]) -> Vec<u8> {
        let mut png = Vec::new();
        let mut writer = encoder(&mut png, w, h).write_header().unwrap();
        writer
            .write_image_data(
                &samples
                    .iter()
                    .flat_map(|p| p.to_be_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        writer.finish().unwrap();
        png
    }

    fn unpack(png: &[u8]) -> Raster {
        let mut decoder = png::Decoder::new(Cursor::new(png)).read_info().unwrap();
        let (w, h) = (decoder.info().width, decoder.info().height);
        let mut data = vec![0; decoder.output_buffer_size().unwrap()];
        decoder.next_frame(&mut data).unwrap();
        Raster::from_linear_rgb16(
            w,
            h,
            data.chunks_exact(2)
                .map(|v| u16::from_be_bytes([v[0], v[1]]))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn full_frame_dark_channel_ranks_match_naive_oracle_with_borders_and_ties() {
        for (w, h) in [(1, 1), (1, 23), (28, 1), (16, 15), (37, 81)] {
            let r = scene(w, h);
            r.visit_dark(|i, value| {
                assert_eq!(value, minimum(&r, i, |v| *v.iter().min().unwrap()))
            });
            assert_eq!(r.atmosphere(), oracle_air(&r));
        }
        // Equal dark channels: the two earliest pixels advance, and their original sums break the tie.
        let mut r = Raster::from_linear_rgb16(50, 40, vec![12; 6000]).unwrap();
        r.pixels[3] = 451;
        r.pixels[6] = 65_535;
        assert_eq!(r.atmosphere(), [451, 12, 12]);
    }

    #[test]
    fn haloed_tiles_stitch_exactly_to_full_frame_reference_in_any_completion_order() {
        let r = scene(55, 37);
        let air = oracle_air(&r);
        let expected = naive_dehaze(&r, air);
        for edge in [16, 25, DEFAULT_TILE_EDGE] {
            let mut dst = RasterOutput::new(&r).unwrap();
            for tile in r.tiles(edge).unwrap().into_iter().rev() {
                let input = r.encode_tile(&tile, air).unwrap();
                assert_eq!(&input[..4], b"EDH1");
                assert_eq!(
                    input[4..10],
                    air.iter().flat_map(|v| v.to_be_bytes()).collect::<Vec<_>>()
                );
                let local = unpack(&input[10..]);
                let dehazed_tile = pack(local.width(), local.height(), &naive_dehaze(&local, air));
                dst.place(&tile, &dehazed_tile).unwrap();
            }
            let mut result = Vec::new();
            dst.write_png(&mut result).unwrap();
            assert_eq!(unpack(&result).pixels, expected);
        }
    }

    #[test]
    fn raw_boundary_preserves_binary_prefix_and_rejects_unsupported_ranges() {
        let mut ppm = b"P6\n# decoder profile\n1 1\n65535\n".to_vec();
        ppm.extend_from_slice(&[b'#', b'\n', 0, 34, 255, 255]);
        assert_eq!(
            Raster::decode_ppm(&ppm[..]).unwrap().pixels,
            [0x230a, 34, 65535]
        );
        ppm.push(0);
        assert!(Raster::decode_ppm(&ppm[..]).is_err());
        for invalid in [
            b"P6\n1 1\n255\n".as_slice(),
            b"P6\n1 1\n65535\n\0",
            b"P6\n10000 10000\n65535\n",
            b"P6\n32769 1\n65535\n",
            b"P6\n0 1\n65535\n",
        ] {
            assert!(Raster::decode_ppm(invalid).is_err());
        }
        let oversize = format!("P6\n#{}\n1 1\n65535\n", "c".repeat(HEADER_LIMIT));
        assert!(Raster::decode_ppm(oversize.as_bytes()).is_err());
    }

    #[test]
    fn guest_tile_requires_expected_profile_geometry_and_complete_unique_grid() {
        let r = scene(17, 16);
        let tiles = r.tiles(16).unwrap();
        let mut output = RasterOutput::new(&r).unwrap();
        let good = pack(17, 16, &r.pixels);
        let mut wrong_gamma = Vec::new();
        let mut config = encoder(&mut wrong_gamma, 17, 16);
        config.set_source_gamma(ScaledFloat::from_scaled(45455));
        let mut writer = config.write_header().unwrap();
        writer.write_image_data(&vec![0; 17 * 16 * 6]).unwrap();
        writer.finish().unwrap();
        assert!(output.place(&tiles[0], &wrong_gamma).is_err());
        assert!(output.place(&tiles[0], &pack(1, 1, &[0; 3])).is_err());
        assert!(output.place(&tiles[0], &good[..good.len() - 1]).is_err());
        output.place(&tiles[0], &good).unwrap();
        assert!(output.place(&tiles[0], &good).is_err());
        assert!(output.write_png(Vec::new()).is_err());
    }
}
