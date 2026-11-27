use std::collections::VecDeque;

use crate::{area, Error, WINDOW_RADIUS};

const SCALE: u32 = u16::MAX as u32;
const MIN_TRANSMISSION: u32 = 6554;

/// Select atmospheric light from the brightest of the top 0.1% dark-channel
/// pixels. `pixels` contains RGB16 triplets in row-major order. The positive
/// geometry and buffer length must agree and are subject to the guest's limits.
/// Rank equal dark-channel samples by row-major order. On equal RGB sums,
/// choose the first selected pixel in row-major order.
pub fn estimate_atmosphere(
    pixels: &[[u16; 3]],
    width: usize,
    height: usize,
) -> Result<[u16; 3], Error> {
    let area = area(width, height)?;
    if pixels.len() != area {
        return Err(Error::InvalidInput(
            "RGB buffer does not match image dimensions".into(),
        ));
    }
    let channel: Vec<_> = pixels.iter().map(|&[r, g, b]| r.min(g).min(b)).collect();
    let dark = square_minima(&channel, width, height);

    let mut counts = vec![0u32; SCALE as usize + 1];
    for &value in &dark {
        counts[value as usize] += 1;
    }
    let mut slots_at_cutoff = (area / 1000).max(1) as u32;
    let mut cutoff = 0;
    for (value, count) in counts.into_iter().enumerate().rev() {
        if count >= slots_at_cutoff {
            cutoff = value as u16;
            break;
        }
        slots_at_cutoff -= count;
    }

    let mut best = [0; 3];
    let mut best_brightness = 0;
    for (&rgb, value) in pixels.iter().zip(dark) {
        if value < cutoff || (value == cutoff && slots_at_cutoff == 0) {
            continue;
        }
        if value == cutoff {
            slots_at_cutoff -= 1;
        }
        let brightness = rgb.into_iter().map(u32::from).sum();
        if brightness > best_brightness {
            best = rgb;
            best_brightness = brightness;
        }
    }
    Ok(best)
}

pub(crate) fn recover(pixels: &mut [[u16; 3]], width: usize, height: usize, atmosphere: [u16; 3]) {
    let divisor = atmosphere.map(|channel| u32::from(channel.max(1)));
    let channel: Vec<_> = pixels
        .iter()
        .map(|&[r, g, b]| {
            normalize(r, divisor[0])
                .min(normalize(g, divisor[1]))
                .min(normalize(b, divisor[2]))
        })
        .collect();
    let dark = square_minima(&channel, width, height);
    for (rgb, value) in pixels.iter_mut().zip(dark) {
        let attenuation = (95 * u32::from(value) + 50) / 100;
        let transmission = (SCALE - attenuation).max(MIN_TRANSMISSION);
        for (sample, air) in rgb.iter_mut().zip(atmosphere) {
            let delta = i64::from(*sample) - i64::from(air);
            let divisor = i64::from(transmission);
            let magnitude = (delta.abs() * i64::from(SCALE) + divisor / 2) / divisor;
            *sample =
                (i64::from(air) + delta.signum() * magnitude).clamp(0, i64::from(SCALE)) as u16;
        }
    }
}

fn normalize(sample: u16, divisor: u32) -> u16 {
    // The maximum product plus the rounding term fits in u32.
    ((u32::from(sample) * SCALE + divisor / 2) / divisor).min(SCALE) as u16
}

fn square_minima(channel: &[u16], width: usize, height: usize) -> Vec<u16> {
    let mut horizontal = vec![0; channel.len()];
    let mut dark = vec![0; channel.len()];
    let mut window = VecDeque::with_capacity(2 * WINDOW_RADIUS + 1);
    for (input, output) in channel
        .chunks_exact(width)
        .zip(horizontal.chunks_exact_mut(width))
    {
        line_minima(
            width,
            &mut window,
            |x| input[x],
            |x, value| output[x] = value,
        );
    }
    for x in 0..width {
        line_minima(
            height,
            &mut window,
            |y| horizontal[y * width + x],
            |y, value| dark[y * width + x] = value,
        );
    }
    dark
}

fn line_minima(
    length: usize,
    window: &mut VecDeque<(usize, u16)>,
    read: impl Fn(usize) -> u16,
    mut write: impl FnMut(usize, u16),
) {
    window.clear();
    let mut next = 0;
    for center in 0..length {
        let start = center.saturating_sub(WINDOW_RADIUS);
        while window.front().is_some_and(|&(index, _)| index < start) {
            window.pop_front();
        }
        let end = (center + WINDOW_RADIUS + 1).min(length);
        for index in next..end {
            let value = read(index);
            while window.back().is_some_and(|&(_, minimum)| minimum >= value) {
                window.pop_back();
            }
            window.push_back((index, value));
        }
        next = end;
        // The window always includes the center of the line segment.
        write(center, window[0].1);
    }
}
