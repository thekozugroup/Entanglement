#[allow(dead_code)]
#[path = "/workspace/Entanglement/crates/entangle-cli/src/cmd/image_raster.rs"]
mod image_raster;
#[cfg(test)]
mod interoperability {
    use super::image_raster::{Raster, RasterOutput};
    fn pixels(data: &[u8]) -> Vec<u8> {
        let mut r = png::Decoder::new(std::io::Cursor::new(data))
            .read_info()
            .unwrap();
        let mut b = vec![0; r.output_buffer_size().unwrap()];
        r.next_frame(&mut b).unwrap();
        b
    }
    #[test]
    fn native_guest_matches_whole_full_frame_through_host_tiles() {
        let (w, h) = (1033, 1035);
        let mut state = 7u32;
        let v: Vec<[u16; 3]> = (0..w * h)
            .map(|i| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                if (i % w < 16) || (i / w > 1010) {
                    [40000, 30000, 20000]
                } else {
                    [
                        state as u16,
                        (state >> 16) as u16,
                        state.wrapping_mul(15937) as u16,
                    ]
                }
            })
            .collect();
        let r = Raster::from_linear_rgb16(w, h, v.iter().flatten().copied().collect()).unwrap();
        let a = r.atmosphere();
        assert_eq!(
            a,
            entangle_image_dehaze::estimate_atmosphere(&v, w as usize, h as usize).unwrap()
        );
        let whole = r.tiles(1536).unwrap()[0];
        let request = r.encode_tile(&whole, a).unwrap();
        let direct = entangle_image_dehaze::process(&request[10..]).unwrap();
        let oracle = pixels(&direct);
        let mut previous = None;
        for edge in [512, 1024] {
            let tiles = r.tiles(edge).unwrap();
            let mut assembled = RasterOutput::new(&r).unwrap();
            for tile in tiles.iter().rev() {
                let indata = r.encode_tile(tile, a).unwrap();
                let actual = entangle_image_dehaze::process(&indata).unwrap();
                assembled.place(tile, &actual).unwrap();
            }
            let mut png = Vec::new();
            assembled.write_png(&mut png).unwrap();
            assert_eq!(
                pixels(&png),
                oracle,
                "whole-file and tiled pixel streams differed"
            );
            if let Some(prev) = previous {
                assert_eq!(png, prev, "canonical bytes depend on tile grid");
            }
            previous = Some(png);
            eprintln!(
                "{}x{} tile edge={} tiles={} global RGB={a:?}, full 16-bit raster equality",
                w,
                h,
                edge,
                tiles.len()
            );
        }
    }
}
