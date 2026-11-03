//! `native-echo` — an Entanglement tier-5 native plugin.
//!
//! The host runs this executable inside an OS sandbox and talks to it over
//! stdin/stdout with length-prefixed frames:
//!
//! ```text
//! request  (stdin):  u32 big-endian length | input bytes
//! response (stdout): u32 big-endian length | tag | body
//!                    tag 0 = ok (body = output), tag 1 = err (body = UTF-8 message)
//! ```
//!
//! The response length includes the tag byte. Loop until stdin closes.
//! Anything written to stderr ends up in the daemon's log.
//!
//! Behaviour: the output is the input, unchanged. As a demonstration of the
//! storage capability, each request is also counted in
//! `$ENTANGLE_DATA_DIR/requests` when that directory was granted.

use std::io::{self, Read, Write};

/// Refuse requests larger than this rather than allocating for them.
const MAX_REQUEST: usize = 64 * 1024 * 1024;

fn read_request(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_REQUEST {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_response(out: &mut impl Write, result: Result<&[u8], &str>) -> io::Result<()> {
    let (tag, body) = match result {
        Ok(bytes) => (0u8, bytes),
        Err(msg) => (1u8, msg.as_bytes()),
    };
    let len = u32::try_from(body.len() + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(&[tag])?;
    out.write_all(body)?;
    out.flush()
}

/// Count this request in the plugin's own storage scope, if it has one.
fn count_request() -> io::Result<u64> {
    let Some(dir) = std::env::var_os("ENTANGLE_DATA_DIR") else {
        return Ok(0);
    };
    let path = std::path::Path::new(&dir).join("requests");
    let n = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
        + 1;
    std::fs::write(&path, n.to_string())?;
    Ok(n)
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let (mut input, mut out) = (stdin.lock(), stdout.lock());
    loop {
        let request = match read_request(&mut input) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                eprintln!("native-echo: bad request: {e}");
                std::process::exit(2);
            }
        };
        match count_request() {
            Ok(n) if n > 0 => eprintln!("native-echo: request #{n}"),
            Ok(_) => {}
            Err(e) => eprintln!("native-echo: could not record request: {e}"),
        }
        if write_response(&mut out, Ok(&request)).is_err() {
            return;
        }
    }
}
