use super::*;
use std::io::Cursor;

fn png_samples(width: u32, height: u32, depth: png::BitDepth, gamma: Option<u32>) -> Vec<u8> {
    let mut png = Vec::new();
    let mut encoder = png::Encoder::new(&mut png, width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(depth);
    if let Some(gamma) = gamma {
        encoder.set_source_gamma(png::ScaledFloat::from_scaled(gamma));
    }
    let mut writer = encoder.write_header().unwrap();
    // Invalid image data lets these fixtures check what is rejected at the header.
    writer.write_chunk(png::chunk::IDAT, &[0]).unwrap();
    // Dropping the writer appends the IEND chunk.
    drop(writer);
    png
}

fn with_atmosphere(png: &[u8], atmosphere: [u16; 3]) -> Vec<u8> {
    let mut payload = TILE_MAGIC.to_vec();
    for sample in atmosphere {
        payload.extend_from_slice(&sample.to_be_bytes());
    }
    payload.extend_from_slice(png);
    payload
}

#[test]
fn preserves_geometry_and_emits_linear_rgb16_png() {
    let width = 2;
    let height = 3;
    let pixels = vec![[12_345, 33_000, 54_321]; width * height];
    let input = raster::encode(width, height, &pixels).unwrap();
    let output = process(&input).unwrap();
    assert_eq!(process(&input).unwrap(), output);
    let reader = png::Decoder::new(Cursor::new(&output)).read_info().unwrap();
    let info = reader.info();
    assert_eq!((info.width, info.height), (2, 3));
    assert_eq!(info.color_type, png::ColorType::Rgb);
    assert_eq!(info.bit_depth, png::BitDepth::Sixteen);
    assert_eq!(info.gama_chunk.unwrap().into_scaled(), 100_000);
    assert!(info.srgb.is_none());
    let chroma = info.chrm_chunk.unwrap();
    let to_scaled =
        |(x, y): (png::ScaledFloat, png::ScaledFloat)| (x.into_scaled(), y.into_scaled());
    assert_eq!(to_scaled(chroma.white), (31270, 32900));
    assert_eq!(to_scaled(chroma.red), (64000, 33000));
    assert_eq!(to_scaled(chroma.green), (30000, 60000));
    assert_eq!(to_scaled(chroma.blue), (15000, 6000));
    assert_eq!(raster::decode(&output).unwrap().pixels, pixels);

    let mut untagged_primaries = input;
    let chroma_kind = untagged_primaries
        .windows(4)
        .position(|tag| tag == b"cHRM")
        .unwrap();
    untagged_primaries.drain(chroma_kind - 4..chroma_kind + 40);
    assert_eq!(process(&untagged_primaries).unwrap(), output);
}

fn reference_dark(pixels: &[[u16; 3]], width: usize, height: usize) -> Vec<u16> {
    let mut dark = Vec::new();
    for y in 0..height {
        for x in 0..width {
            let mut value = u16::MAX;
            for row in y.saturating_sub(7)..=(y + 7).min(height - 1) {
                for col in x.saturating_sub(7)..=(x + 7).min(width - 1) {
                    for sample in pixels[row * width + col] {
                        value = value.min(sample);
                    }
                }
            }
            dark.push(value);
        }
    }
    dark
}

fn reference_atmosphere(pixels: &[[u16; 3]], width: usize, height: usize) -> [u16; 3] {
    let dark = reference_dark(pixels, width, height);
    let mut indices: Vec<_> = (0..pixels.len()).collect();
    indices.sort_unstable_by_key(|&index| (std::cmp::Reverse(dark[index]), index));
    indices.truncate((pixels.len() / 1000).max(1));
    let index = indices
        .into_iter()
        .min_by_key(|&index| {
            (
                std::cmp::Reverse(pixels[index].into_iter().map(u32::from).sum::<u32>()),
                index,
            )
        })
        .unwrap();
    pixels[index]
}

fn reference_recovery(
    pixels: &[[u16; 3]],
    width: usize,
    height: usize,
    air: [u16; 3],
) -> Vec<[u16; 3]> {
    let normalized: Vec<_> = pixels
        .iter()
        .map(|rgb| {
            std::array::from_fn(|c| {
                let normalized = f64::from(rgb[c]) * 65_535. / f64::from(air[c].max(1));
                normalized.round().clamp(0., 65_535.) as u16
            })
        })
        .collect();
    let dark = reference_dark(&normalized, width, height);
    pixels
        .iter()
        .zip(dark)
        .map(|(rgb, d)| {
            let remaining = (65_535. - (f64::from(d) * 95. / 100.).round()).max(6554.);
            std::array::from_fn(|c| {
                let correction = (f64::from(rgb[c]) - f64::from(air[c])) * 65_535. / remaining;
                (f64::from(air[c]) + correction.round()).clamp(0., 65_535.) as u16
            })
        })
        .collect()
}

fn scene(width: usize, height: usize) -> Vec<[u16; 3]> {
    let mut state = 97u32;
    (0..width * height)
        .map(|_| {
            std::array::from_fn(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 16) as u16
            })
        })
        .collect()
}

#[test]
fn compares_to_slow_reference_at_borders_and_zero_atmosphere() {
    for (width, height) in [(1, 1), (1, 17), (17, 1), (7, 3), (47, 43)] {
        let mut pixels = scene(width, height);
        pixels[0] = [0, u16::MAX, 1];
        let estimated = estimate_atmosphere(&pixels, width, height).unwrap();
        assert_eq!(estimated, reference_atmosphere(&pixels, width, height));
        let png = raster::encode(width, height, &pixels).unwrap();
        for air in [[0, 0, 0], [0, 1, 65535], estimated] {
            let expected = reference_recovery(&pixels, width, height, air);
            let output = process(&with_atmosphere(&png, air)).unwrap();
            assert_eq!(raster::decode(&output).unwrap().pixels, expected);
        }
    }
}

#[test]
fn ranks_dark_channel_and_brightness_ties_in_row_major_order() {
    let mut pixels = vec![[1, 200, 300]; 3000];
    pixels[1] = [300, 200, 1];
    pixels[2] = [1, 200, 401];
    pixels[3] = [1, 21_000, 42_000];
    assert_eq!(estimate_atmosphere(&pixels, 60, 50).unwrap(), pixels[2]);
    pixels[2] = [200, 300, 1];
    assert_eq!(estimate_atmosphere(&pixels, 60, 50).unwrap(), pixels[0]);
}

#[test]
fn removes_constructed_haze() {
    let width = 128;
    let height = 96;
    let atmosphere = [56_360, 60_947, 65_535];
    let palette = [
        [0, 22_937, 52_428],
        [13_107, 32_768, 0],
        [55_705, 0, 42_598],
    ];
    let clear: Vec<_> = (0..width * height)
        .map(|i| palette[(i % width / 8 + i / width / 8) % 3])
        .collect();
    let hazy: Vec<_> = clear
        .iter()
        .enumerate()
        .map(|(i, color)| {
            if i / width < 24 {
                atmosphere
            } else {
                std::array::from_fn(|c| {
                    ((3 * u32::from(color[c]) + 2 * u32::from(atmosphere[c]) + 2) / 5) as u16
                })
            }
        })
        .collect();
    assert_eq!(
        estimate_atmosphere(&hazy, width, height).unwrap(),
        atmosphere
    );
    let out = process(&raster::encode(width, height, &hazy).unwrap()).unwrap();
    let output = raster::decode(&out).unwrap();
    let error = |image: &[[u16; 3]]| -> u64 {
        image[32 * width..]
            .iter()
            .zip(&clear[32 * width..])
            .map(|(a, b)| (0..3).map(|c| u64::from(a[c].abs_diff(b[c]))).sum::<u64>())
            .sum()
    };
    assert!(error(&output.pixels) * 5 < error(&hazy));
}

#[test]
fn fixed_atmosphere_with_halo_matches_whole_image() {
    let (width, height) = (53, 37);
    let pixels = scene(width, height);
    let air = estimate_atmosphere(&pixels, width, height).unwrap();
    let whole = process(&raster::encode(width, height, &pixels).unwrap()).unwrap();
    let whole = raster::decode(&whole).unwrap();
    for &[x0, y0, x1, y1] in &[
        [0usize, 0usize, 26, 20],
        [26, 0, 53, 20],
        [0, 20, 26, 37],
        [26, 20, 53, 37],
    ] {
        let (left, top) = (
            x0.saturating_sub(WINDOW_RADIUS),
            y0.saturating_sub(WINDOW_RADIUS),
        );
        let (right, bottom) = (
            (x1 + WINDOW_RADIUS).min(width),
            (y1 + WINDOW_RADIUS).min(height),
        );
        let haloed: Vec<_> = (top..bottom)
            .flat_map(|row| {
                pixels[row * width + left..row * width + right]
                    .iter()
                    .copied()
            })
            .collect();
        let tile = raster::encode(right - left, bottom - top, &haloed).unwrap();
        let actual = process(&with_atmosphere(&tile, air)).unwrap();
        let actual = raster::decode(&actual).unwrap();
        for row in y0..y1 {
            let actual_start = (row - top) * actual.width + x0 - left;
            assert_eq!(
                &actual.pixels[actual_start..actual_start + x1 - x0],
                &whole.pixels[row * width + x0..row * width + x1]
            );
        }
    }
}

#[test]
fn rejects_unsupported_or_malformed_input() {
    let png = raster::encode(1, 1, &[[1, 2, 3]]).unwrap();
    for input in [
        b"".as_slice(),
        b"EDH1\0",
        b"EDH1\0\0\0\0\0\0",
        &png[..png.len() - 2],
        b"not an image",
    ] {
        assert!(matches!(process(input), Err(Error::InvalidInput(_))));
    }
    let mut trailing = png.clone();
    trailing.push(0);
    assert!(matches!(process(&trailing), Err(Error::InvalidInput(_))));
    let mut checksum = png.clone();
    *checksum.last_mut().unwrap() ^= 1;
    assert!(matches!(process(&checksum), Err(Error::InvalidInput(_))));

    let gamma_kind = png.windows(4).position(|tag| tag == b"gAMA").unwrap();
    let mut corrupt_gamma = png.clone();
    corrupt_gamma[gamma_kind + 8] ^= 1;
    assert!(matches!(
        process(&corrupt_gamma),
        Err(Error::InvalidInput(_))
    ));
    let mut late_gamma = png.clone();
    let gamma: Vec<_> = late_gamma.drain(gamma_kind - 4..gamma_kind + 12).collect();
    let end = late_gamma.len() - 12;
    late_gamma.splice(end..end, gamma);
    let failure = process(&late_gamma).unwrap_err();
    assert!(matches!(failure, Error::InvalidInput(message) if message.contains("before IDAT")));

    for (depth, gamma, reason) in [
        (png::BitDepth::Eight, Some(100_000), "RGB16"),
        (png::BitDepth::Sixteen, None, "gAMA"),
        (png::BitDepth::Sixteen, Some(45_455), "gAMA"),
    ] {
        let failure = process(&png_samples(1, 1, depth, gamma)).unwrap_err();
        assert!(matches!(failure, Error::InvalidInput(message) if message.contains(reason)));
    }
    for tag in [b"sRGB", b"iCCP", b"cICP", b"tRNS", b"acTL"] {
        let mut tagged = png.clone();
        // Insert an empty ancillary chunk before the first real profile chunk.
        // It should be refused by type without parsing its payload or checksum.
        tagged.splice(33..33, [0, 0, 0, 0].into_iter().chain(*tag).chain([0; 4]));
        let failure = process(&tagged).unwrap_err();
        assert!(
            matches!(failure, Error::InvalidInput(message) if message.contains("color profile"))
        );
    }
}

#[test]
fn enforces_wire_and_image_budgets_before_decoding() {
    for (width, height) in [(4097, 1), (1582, 1582)] {
        let input = png_samples(width, height, png::BitDepth::Sixteen, Some(100_000));
        assert!(matches!(process(&input), Err(Error::ResourceExhausted(_))));
    }
    assert!(matches!(
        process(&vec![0; MAX_BYTES + 1]),
        Err(Error::ResourceExhausted(_))
    ));
    assert!(matches!(
        estimate_atmosphere(&[], usize::MAX, 2),
        Err(Error::ResourceExhausted(_))
    ));
    assert!(matches!(
        estimate_atmosphere(&[], 1, 1),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        estimate_atmosphere(&[], 1, 0),
        Err(Error::InvalidInput(_))
    ));
}
