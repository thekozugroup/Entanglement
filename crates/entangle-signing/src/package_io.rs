//! Size and file-type limits shared by package installation and direct runtime loading.

use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

/// Maximum bytes in a signed package manifest.
pub const MANIFEST_LIMIT: usize = 1024 * 1024;
/// Maximum bytes in a signed WebAssembly component.
pub const COMPONENT_LIMIT: usize = 64 * 1024 * 1024;
/// Maximum bytes in its detached signature bundle.
pub const SIGNATURE_LIMIT: usize = 64 * 1024;

/// Read at most `limit` bytes, checking for growth or an undeclared extra byte.
pub fn read_bounded(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} bytes"),
        ));
    }
    Ok(bytes)
}

/// Read a bounded regular file. Unix opens refuse final-component symlinks and
/// use nonblocking mode so that a named pipe cannot block before the type check.
pub fn read_regular_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected a regular file at {}", path.display()),
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds {limit} bytes", path.display()),
        ));
    }
    read_bounded(file, limit)
}
