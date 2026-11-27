//! Deterministic dark-channel-prior dehazing of linear RGB16 rasters.

#![warn(missing_docs)]

mod dcp;
mod raster;

pub use dcp::estimate_atmosphere;

use std::fmt;

/// Largest supported image width or height, in pixels.
pub const MAX_DIMENSION: usize = 4096;
/// Largest supported raster area, in pixels.
pub const MAX_PIXELS: usize = 2_500_000;
/// Largest accepted request or encoded PNG response, in bytes.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Radius of the square dark-channel window and required halo for each tile.
pub const WINDOW_RADIUS: usize = 7;
/// Magic before the three big-endian atmospheric RGB components in tiled requests.
pub const TILE_MAGIC: &[u8; 4] = b"EDH1";

/// A rejected request or failure to produce the result.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed or unsupported input.
    InvalidInput(String),
    /// The request or result exceeds the plugin's documented budgets.
    ResourceExhausted(String),
    /// Failed to encode the result.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message)
            | Self::ResourceExhausted(message)
            | Self::Internal(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

/// Dehaze a linear RGB16 PNG, with an optional `EDH1` atmosphere prefix.
/// The result is a linear RGB16 PNG of the same dimensions.
pub fn process(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_BYTES {
        return Err(Error::ResourceExhausted("input exceeds 16 MiB".into()));
    }
    let (atmosphere, png) = match input.strip_prefix(TILE_MAGIC) {
        Some(rest) => {
            let Some((channels, png)) = rest.split_first_chunk::<6>() else {
                return Err(Error::InvalidInput(
                    "incomplete EDH1 atmosphere prefix".into(),
                ));
            };
            (Some(raster::read_rgb16(channels)), png)
        }
        None => (None, input),
    };
    let raster::Raster {
        width,
        height,
        mut pixels,
    } = raster::decode(png)?;
    let atmosphere = match atmosphere {
        Some(rgb) => rgb,
        None => estimate_atmosphere(&pixels, width, height)?,
    };
    dcp::recover(&mut pixels, width, height, atmosphere);
    raster::encode(width, height, &pixels)
}

fn area(width: usize, height: usize) -> Result<usize, Error> {
    if width == 0 || height == 0 {
        return Err(Error::InvalidInput(
            "image dimensions must be positive".into(),
        ));
    }
    if width > MAX_DIMENSION || height > MAX_DIMENSION || width * height > MAX_PIXELS {
        return Err(Error::ResourceExhausted(
            "image exceeds the 4096-pixel side or 2,500,000-pixel area limit".into(),
        ));
    }
    Ok(width * height)
}

#[cfg(target_arch = "wasm32")]
fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    use entangle_sdk::PluginError;

    process(&input).map_err(|error| match error {
        Error::InvalidInput(message) => PluginError::InvalidInput(message),
        Error::ResourceExhausted(message) => PluginError::ResourceExhausted(message),
        Error::Internal(message) => PluginError::Internal(message),
    })
}

#[cfg(target_arch = "wasm32")]
entangle_sdk::entangle_plugin!(run);

#[cfg(test)]
mod tests;
