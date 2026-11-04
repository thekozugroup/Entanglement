//! A minimal QR Code encoder for the pairing screen (spec §6.3: "QR via
//! terminal (Unicode block renderer) is offered as a convenience but the
//! 6-digit code is canonical").
//!
//! Byte mode, error-correction level M, versions 1–10 (up to 213 bytes),
//! automatic mask selection by the standard penalty rules (ISO/IEC 18004).
//! No dependency: the workspace has no QR crate and this is ~300 lines. The
//! layout follows the well-known structure of Project Nayuki's reference
//! implementation (MIT); the tests check it against published vectors
//! (format strings, the "HELLO WORLD" 1-M Reed–Solomon codewords) and by
//! decoding what it drew.

/// Largest supported version.
const MAX_VERSION: usize = 10;

/// Error-correction codewords per block, level M, versions 1..=10.
const ECC_PER_BLOCK: [usize; MAX_VERSION + 1] = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
/// Number of blocks, level M, versions 1..=10.
const BLOCKS: [usize; MAX_VERSION + 1] = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
/// The 2-bit level indicator of M in the format information.
const LEVEL_M_BITS: u32 = 0;

/// An encoded symbol: `size × size` modules, `true` = dark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrCode {
    version: usize,
    size: usize,
    modules: Vec<bool>,
    function: Vec<bool>,
}

/// Total codewords (data + error correction) in a version.
fn raw_codewords(ver: usize) -> usize {
    let mut bits = (16 * ver + 128) * ver + 64;
    if ver >= 2 {
        let align = ver / 7 + 2;
        bits -= (25 * align - 10) * align - 55;
        if ver >= 7 {
            bits -= 36;
        }
    }
    bits / 8
}

/// Data codewords in a version at level M.
fn data_codewords(ver: usize) -> usize {
    raw_codewords(ver) - ECC_PER_BLOCK[ver] * BLOCKS[ver]
}

/// Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= u32::from((y >> i) & 1) * u32::from(x);
    }
    // `z` is reduced to 8 bits by the loop: every step above folds bit 8.
    (z & 0xFF) as u8
}

/// The Reed–Solomon generator polynomial of `degree` (leading 1 omitted).
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    result[degree - 1] = 1;
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..degree {
            result[j] = gf_mul(result[j], root);
            if j + 1 < degree {
                result[j] ^= result[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    result
}

/// The error-correction codewords of `data`.
fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for &b in data {
        let factor = b ^ result[0];
        result.rotate_left(1);
        let last = result.len() - 1;
        result[last] = 0;
        for (r, &d) in result.iter_mut().zip(divisor) {
            *r ^= gf_mul(d, factor);
        }
    }
    result
}

/// The 15-bit format information for level M and `mask`.
fn format_bits(mask: u32) -> u32 {
    let data = (LEVEL_M_BITS << 3) | mask;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

/// The 18-bit version information (versions 7+).
fn version_bits(ver: usize) -> u32 {
    let v = ver as u32;
    let mut rem = v;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    (v << 12) | rem
}

fn alignment_positions(ver: usize) -> Vec<usize> {
    if ver == 1 {
        return Vec::new();
    }
    let size = 4 * ver + 17;
    let count = ver / 7 + 2;
    let step = (ver * 8 + count * 3 + 5) / (count * 4 - 4) * 2;
    let mut out = vec![0; count];
    out[0] = 6;
    let mut pos = size - 7;
    for slot in out.iter_mut().skip(1).rev() {
        *slot = pos;
        pos -= step;
    }
    out
}

fn mask_applies(mask: u32, x: usize, y: usize) -> bool {
    let even = |n: usize| n.is_multiple_of(2);
    match mask {
        0 => even(x + y),
        1 => even(y),
        2 => x.is_multiple_of(3),
        3 => (x + y).is_multiple_of(3),
        4 => even(x / 3 + y / 2),
        5 => x * y % 2 + x * y % 3 == 0,
        6 => even(x * y % 2 + x * y % 3),
        _ => even((x + y) % 2 + x * y % 3),
    }
}

impl QrCode {
    /// Encode `data` in the smallest version (1–10) that holds it at level
    /// M. `None` when it does not fit.
    pub fn encode(data: &[u8]) -> Option<Self> {
        let ver = (1..=MAX_VERSION).find(|&v| {
            let count_bits = if v < 10 { 8 } else { 16 };
            4 + count_bits + 8 * data.len() <= 8 * data_codewords(v)
        })?;
        let count_bits = if ver < 10 { 8 } else { 16 };
        let capacity = data_codewords(ver);

        // Bit stream: byte mode, length, payload, terminator, padding.
        let mut bits: Vec<bool> = Vec::with_capacity(capacity * 8);
        let push = |value: usize, n: usize, bits: &mut Vec<bool>| {
            for i in (0..n).rev() {
                bits.push((value >> i) & 1 == 1);
            }
        };
        push(0b0100, 4, &mut bits);
        push(data.len(), count_bits, &mut bits);
        for &b in data {
            push(usize::from(b), 8, &mut bits);
        }
        let room = capacity * 8 - bits.len();
        push(0, room.min(4), &mut bits);
        let pad_to_byte = (8 - bits.len() % 8) % 8;
        push(0, pad_to_byte, &mut bits);
        let mut codewords: Vec<u8> = bits
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b)))
            .collect();
        for pad in [0xECu8, 0x11].iter().cycle() {
            if codewords.len() >= capacity {
                break;
            }
            codewords.push(*pad);
        }

        let all = Self::add_ecc_and_interleave(ver, &codewords);
        let mut qr = Self::blank(ver);
        qr.draw_function_patterns();
        qr.draw_codewords(&all);
        let mut best = (u32::MAX, 0u32);
        for mask in 0..8 {
            qr.apply_mask(mask);
            qr.draw_format(mask);
            let p = qr.penalty();
            if p < best.0 {
                best = (p, mask);
            }
            qr.apply_mask(mask); // XOR undoes it
        }
        qr.apply_mask(best.1);
        qr.draw_format(best.1);
        Some(qr)
    }

    fn blank(ver: usize) -> Self {
        let size = 4 * ver + 17;
        Self {
            version: ver,
            size,
            modules: vec![false; size * size],
            function: vec![false; size * size],
        }
    }

    /// Side length in modules.
    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.size
    }

    /// The symbol version (1–10).
    #[cfg(test)]
    pub fn version(&self) -> usize {
        self.version
    }

    /// Whether the module at column `x`, row `y` is dark.
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let i = y * self.size + x;
        self.modules[i] = dark;
        self.function[i] = true;
    }

    fn add_ecc_and_interleave(ver: usize, data: &[u8]) -> Vec<u8> {
        let blocks = BLOCKS[ver];
        let ecc_len = ECC_PER_BLOCK[ver];
        let raw = raw_codewords(ver);
        let short_blocks = blocks - raw % blocks;
        let short_len = raw / blocks;
        let divisor = rs_divisor(ecc_len);
        let mut parts: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(blocks);
        let mut k = 0;
        for i in 0..blocks {
            let dlen = short_len - ecc_len + usize::from(i >= short_blocks);
            let d = data[k..k + dlen].to_vec();
            k += dlen;
            let e = rs_remainder(&d, &divisor);
            parts.push((d, e));
        }
        let mut out = Vec::with_capacity(raw);
        let longest = parts.iter().map(|p| p.0.len()).max().unwrap_or(0);
        for i in 0..longest {
            for (d, _) in &parts {
                if let Some(b) = d.get(i) {
                    out.push(*b);
                }
            }
        }
        for i in 0..ecc_len {
            for (_, e) in &parts {
                out.push(e[i]);
            }
        }
        out
    }

    fn draw_function_patterns(&mut self) {
        let size = self.size;
        for i in 0..size {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }
        for (cx, cy) in [(3, 3), (size - 4, 3), (3, size - 4)] {
            for dy in -4i32..=4 {
                for dx in -4i32..=4 {
                    let (x, y) = (cx as i32 + dx, cy as i32 + dy);
                    if (0..size as i32).contains(&x) && (0..size as i32).contains(&y) {
                        let dist = dx.abs().max(dy.abs());
                        self.set_function(x as usize, y as usize, dist != 2 && dist != 4);
                    }
                }
            }
        }
        let pos = alignment_positions(self.version);
        let n = pos.len();
        for (i, &ax) in pos.iter().enumerate() {
            for (j, &ay) in pos.iter().enumerate() {
                // The three finder corners have no alignment pattern.
                let corner =
                    matches!((i, j), (0, 0)) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0);
                if corner {
                    continue;
                }
                for dy in -2i32..=2 {
                    for dx in -2i32..=2 {
                        let dist = dx.abs().max(dy.abs());
                        self.set_function(
                            (ax as i32 + dx) as usize,
                            (ay as i32 + dy) as usize,
                            dist != 1,
                        );
                    }
                }
            }
        }
        // Reserve the format areas (the real bits are drawn per mask).
        self.draw_format(0);
        if self.version >= 7 {
            let bits = version_bits(self.version);
            for i in 0..18 {
                let bit = (bits >> i) & 1 == 1;
                let a = size - 11 + i % 3;
                let b = i / 3;
                self.set_function(a, b, bit);
                self.set_function(b, a, bit);
            }
        }
    }

    fn draw_format(&mut self, mask: u32) {
        let bits = format_bits(mask);
        let bit = |i: u32| (bits >> i) & 1 == 1;
        let size = self.size;
        for i in 0..=5 {
            self.set_function(8, i, bit(i as u32));
        }
        self.set_function(8, 7, bit(6));
        self.set_function(8, 8, bit(7));
        self.set_function(7, 8, bit(8));
        for i in 9..15 {
            self.set_function(14 - i, 8, bit(i as u32));
        }
        for i in 0..8 {
            self.set_function(size - 1 - i, 8, bit(i as u32));
        }
        for i in 8..15 {
            self.set_function(8, size - 15 + i, bit(i as u32));
        }
        self.set_function(8, size - 8, true); // the dark module
    }

    fn draw_codewords(&mut self, data: &[u8]) {
        let size = self.size;
        let total = data.len() * 8;
        let mut i = 0;
        let mut right = size as i32 - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = right as usize - j;
                    let upward = (right + 1) & 2 == 0;
                    let y = if upward { size - 1 - vert } else { vert };
                    let idx = y * size + x;
                    if !self.function[idx] && i < total {
                        self.modules[idx] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1;
                        i += 1;
                    }
                }
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u32) {
        for y in 0..self.size {
            for x in 0..self.size {
                let idx = y * self.size + x;
                if !self.function[idx] && mask_applies(mask, x, y) {
                    self.modules[idx] = !self.modules[idx];
                }
            }
        }
    }

    fn penalty(&self) -> u32 {
        let size = self.size;
        let mut score = 0u32;
        for horizontal in [true, false] {
            for a in 0..size {
                let mut color = false;
                let mut run = 0usize;
                let mut history = [0usize; 7];
                for b in 0..size {
                    let m = if horizontal {
                        self.dark(b, a)
                    } else {
                        self.dark(a, b)
                    };
                    if m == color {
                        run += 1;
                        if run == 5 {
                            score += 3;
                        } else if run > 5 {
                            score += 1;
                        }
                    } else {
                        self.add_history(run, &mut history);
                        if !color {
                            score += self.count_finder_like(&history) * 40;
                        }
                        color = m;
                        run = 1;
                    }
                }
                score += self.terminate_and_count(color, run, &mut history) * 40;
            }
        }
        for y in 0..size - 1 {
            for x in 0..size - 1 {
                let c = self.dark(x, y);
                if c == self.dark(x + 1, y)
                    && c == self.dark(x, y + 1)
                    && c == self.dark(x + 1, y + 1)
                {
                    score += 3;
                }
            }
        }
        let dark = self.modules.iter().filter(|&&m| m).count() as i64;
        let total = (size * size) as i64;
        let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
        score + (k.max(0) as u32) * 10
    }

    fn add_history(&self, mut run: usize, history: &mut [usize; 7]) {
        if history[0] == 0 {
            run += self.size; // the light border before the first run
        }
        history.copy_within(0..6, 1);
        history[0] = run;
    }

    fn count_finder_like(&self, h: &[usize; 7]) -> u32 {
        let n = h[1];
        let core = n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n;
        u32::from(core && h[0] >= n * 4 && h[6] >= n)
            + u32::from(core && h[6] >= n * 4 && h[0] >= n)
    }

    fn terminate_and_count(&self, color: bool, mut run: usize, h: &mut [usize; 7]) -> u32 {
        if color {
            self.add_history(run, h);
            run = 0;
        }
        run += self.size;
        self.add_history(run, h);
        self.count_finder_like(h)
    }

    /// Render with Unicode half blocks, two module rows per text line, with
    /// a two-module quiet zone. Light modules are drawn as blocks (the
    /// terminal's foreground) and dark ones as spaces, the polarity that
    /// scans on the usual light-on-dark terminal.
    pub fn to_half_blocks(&self) -> Vec<String> {
        const QUIET: i32 = 2;
        let size = self.size as i32;
        let light = |x: i32, y: i32| {
            if x < 0 || y < 0 || x >= size || y >= size {
                true
            } else {
                !self.dark(x as usize, y as usize)
            }
        };
        let mut lines = Vec::new();
        let mut y = -QUIET;
        while y < size + QUIET {
            let mut line = String::new();
            for x in -QUIET..size + QUIET {
                line.push(match (light(x, y), light(x, y + 1)) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                });
            }
            lines.push(line);
            y += 2;
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The format information strings for level M from the standard's table.
    #[test]
    fn format_bits_match_the_published_table() {
        let table = [
            "101010000010010",
            "101000100100101",
            "101111001111100",
            "101101101001011",
            "100010111111001",
            "100000011001110",
            "100111110010111",
            "100101010100000",
        ];
        for (mask, want) in table.iter().enumerate() {
            assert_eq!(
                format!("{:015b}", format_bits(mask as u32)),
                *want,
                "mask {mask}"
            );
        }
        // Version 7's information block (ISO/IEC 18004 Annex D).
        assert_eq!(format!("{:018b}", version_bits(7)), "000111110010010100");
    }

    /// "HELLO WORLD" at 1-M: the textbook data codewords and their ten
    /// Reed–Solomon codewords.
    #[test]
    fn reed_solomon_matches_the_hello_world_vector() {
        let data = [
            32u8, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17,
        ];
        assert_eq!(
            rs_remainder(&data, &rs_divisor(10)),
            [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]
        );
    }

    #[test]
    fn capacities_and_alignment_positions_are_the_standard_ones() {
        let data: Vec<usize> = (1..=10).map(data_codewords).collect();
        assert_eq!(data, [16, 28, 44, 64, 86, 108, 124, 154, 182, 216]);
        assert_eq!(alignment_positions(2), [6, 18]);
        assert_eq!(alignment_positions(7), [6, 22, 38]);
        assert_eq!(alignment_positions(10), [6, 28, 50]);
        // Byte-mode capacity at M: 14 bytes in v1, 213 in v10.
        assert_eq!(QrCode::encode(&[b'a'; 14]).unwrap().version(), 1);
        assert_eq!(QrCode::encode(&[b'a'; 15]).unwrap().version(), 2);
        assert_eq!(QrCode::encode(&[b'a'; 213]).unwrap().version(), 10);
        assert!(QrCode::encode(&[b'a'; 214]).is_none());
    }

    /// Read the symbol back: format bits, unmask, codewords in placement
    /// order, de-interleave, check every block's Reed–Solomon syndromes and
    /// parse the byte-mode payload.
    fn decode(qr: &QrCode) -> Vec<u8> {
        let size = qr.size;
        // First copy of the format bits.
        let mut fb = 0u32;
        let read = |x, y| u32::from(qr.dark(x, y));
        for i in 0..=5 {
            fb |= read(8, i) << i;
        }
        fb |= read(8, 7) << 6;
        fb |= read(8, 8) << 7;
        fb |= read(7, 8) << 8;
        for i in 9..15 {
            fb |= read(14 - i, 8) << i;
        }
        let mask = (0..8)
            .find(|&m| format_bits(m) == fb)
            .expect("valid format bits");
        // Second copy agrees.
        let mut fb2 = 0u32;
        for i in 0..8 {
            fb2 |= read(size - 1 - i, 8) << i;
        }
        for i in 8..15 {
            fb2 |= read(8, size - 15 + i) << i;
        }
        assert_eq!(fb, fb2);

        let mut fresh = QrCode::blank(qr.version);
        fresh.draw_function_patterns();
        let mut bits = Vec::new();
        let mut right = size as i32 - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = right as usize - j;
                    let y = if (right + 1) & 2 == 0 {
                        size - 1 - vert
                    } else {
                        vert
                    };
                    if !fresh.function[y * size + x] {
                        bits.push(qr.dark(x, y) ^ mask_applies(mask, x, y));
                    }
                }
            }
            right -= 2;
        }
        let raw = raw_codewords(qr.version);
        let bytes: Vec<u8> = bits[..raw * 8]
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | u8::from(b)))
            .collect();
        // De-interleave.
        let (blocks, ecc) = (BLOCKS[qr.version], ECC_PER_BLOCK[qr.version]);
        let short_blocks = blocks - raw % blocks;
        let short_len = raw / blocks;
        let lens: Vec<usize> = (0..blocks)
            .map(|i| short_len - ecc + usize::from(i >= short_blocks))
            .collect();
        let mut block_bytes: Vec<Vec<u8>> = vec![Vec::new(); blocks];
        let mut k = 0;
        for i in 0..*lens.iter().max().unwrap() {
            for (b, len) in lens.iter().enumerate() {
                if i < *len {
                    block_bytes[b].push(bytes[k]);
                    k += 1;
                }
            }
        }
        for _ in 0..ecc {
            for block in &mut block_bytes {
                block.push(bytes[k]);
                k += 1;
            }
        }
        let mut data = Vec::new();
        for (b, block) in block_bytes.iter().enumerate() {
            // Syndromes: the codeword polynomial vanishes at α^0..α^(ecc-1).
            let mut alpha = 1u8;
            for _ in 0..ecc {
                let s = block.iter().fold(0u8, |acc, &c| gf_mul(acc, alpha) ^ c);
                assert_eq!(s, 0, "block {b} fails its Reed-Solomon check");
                alpha = gf_mul(alpha, 2);
            }
            data.extend_from_slice(&block[..lens[b]]);
        }
        let bit = |i: usize| (data[i / 8] >> (7 - i % 8)) & 1;
        let take = |from: usize, n: usize| {
            (from..from + n).fold(0usize, |a, i| (a << 1) | usize::from(bit(i)))
        };
        assert_eq!(take(0, 4), 0b0100, "byte mode");
        let cb = if qr.version < 10 { 8 } else { 16 };
        let len = take(4, cb);
        (0..len).map(|i| take(4 + cb + 8 * i, 8) as u8).collect()
    }

    #[test]
    fn encoded_symbols_decode_back_to_their_payload() {
        let payloads: Vec<Vec<u8>> = vec![
            b"x".to_vec(),
            b"entangle:pair?code=734291".to_vec(),
            format!("entangle:pair?code=734291&sha256={}", "ab".repeat(32)).into_bytes(),
            (0u8..=200).collect(),
        ];
        for p in payloads {
            let qr = QrCode::encode(&p).unwrap();
            assert_eq!(decode(&qr), p, "version {}", qr.version());
            // Finder pattern corners are dark, their separators light.
            assert!(qr.dark(0, 0) && qr.dark(qr.size() - 1, 0) && qr.dark(0, qr.size() - 1));
            assert!(!qr.dark(7, 7) && qr.dark(8, qr.size() - 8));
        }
    }

    #[test]
    fn half_block_rendering_has_a_quiet_zone_and_fixed_width() {
        let qr = QrCode::encode(b"entangle:pair?code=734291").unwrap();
        let lines = qr.to_half_blocks();
        let width = qr.size() + 4;
        assert_eq!(lines.len(), (qr.size() + 4).div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(lines[0].chars().all(|c| c == '█'), "quiet zone is light");
    }
}
