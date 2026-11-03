//! Test helper for `entangle-sandbox`'s integration tests — not shipped.
//!
//! Speaks the native-plugin frame protocol. The request is a command:
//!
//! | request              | behaviour                                              |
//! |----------------------|--------------------------------------------------------|
//! | `echo:<text>`        | ok(text)                                               |
//! | `read:<path>`        | ok(contents) or err("errno=N ...")                     |
//! | `write:<path>=<data>`| create/truncate + write; ok("written") or err(errno)   |
//! | `connect:<addr>`     | TCP connect; ok("connected") or err(errno)             |
//! | `udp:<addr>`         | UDP socket + send_to; ok("sent") or err(errno)         |
//! | `unix:<path>`        | Unix-socket connect; ok("connected") or err(errno)     |
//! | `sleep:<ms>`         | sleep, then ok("slept")                                |
//! | `big:<n>`            | announce an ok frame of n bytes, then stream zeros     |
//! | `fail:<msg>`         | err(msg)                                               |
//! | `exit:<code>`        | log "exiting with <code>" to stderr, exit, no response |
//! | `stderr:<text>`      | write text to stderr, then ok("logged")                |
//! | `env:<NAME>`         | ok(value) or err("unset")                              |
//! | `linger`             | ok("lingering"), then ignore EOF and sleep forever     |
//!
//! Errors carry the raw OS errno (`errno=13 ...`) so tests can assert on the
//! exact denial (EACCES, ENETUNREACH, ...).

use std::io::{self, Read, Write};
use std::time::Duration;

fn errno_msg(e: &io::Error) -> String {
    format!("errno={} {e}", e.raw_os_error().unwrap_or(-1))
}

fn handle(req: &str) -> Result<Vec<u8>, String> {
    let (cmd, arg) = req.split_once(':').unwrap_or((req, ""));
    match cmd {
        "echo" => Ok(arg.as_bytes().to_vec()),
        "read" => std::fs::read(arg).map_err(|e| errno_msg(&e)),
        "write" => {
            let (path, data) = arg.split_once('=').unwrap_or((arg, ""));
            std::fs::write(path, data)
                .map(|()| b"written".to_vec())
                .map_err(|e| errno_msg(&e))
        }
        "connect" => {
            let addr = arg.parse().map_err(|e| format!("bad addr: {e}"))?;
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
                .map(|_| b"connected".to_vec())
                .map_err(|e| errno_msg(&e))
        }
        "udp" => {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| errno_msg(&e))?;
            sock.send_to(b"ping", arg)
                .map(|_| b"sent".to_vec())
                .map_err(|e| errno_msg(&e))
        }
        "unix" => {
            #[cfg(unix)]
            {
                std::os::unix::net::UnixStream::connect(arg)
                    .map(|_| b"connected".to_vec())
                    .map_err(|e| errno_msg(&e))
            }
            #[cfg(not(unix))]
            {
                Err("unsupported".into())
            }
        }
        "sleep" => {
            let ms: u64 = arg.parse().map_err(|e| format!("bad ms: {e}"))?;
            std::thread::sleep(Duration::from_millis(ms));
            Ok(b"slept".to_vec())
        }
        "fail" => Err(arg.to_owned()),
        "stderr" => {
            eprintln!("{arg}");
            Ok(b"logged".to_vec())
        }
        "env" => std::env::var(arg)
            .map(String::into_bytes)
            .map_err(|_| "unset".to_owned()),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    loop {
        let mut hdr = [0u8; 4];
        if input.read_exact(&mut hdr).is_err() {
            return; // EOF: done
        }
        let mut req = vec![0u8; u32::from_be_bytes(hdr) as usize];
        if input.read_exact(&mut req).is_err() {
            std::process::exit(3);
        }
        let req = String::from_utf8_lossy(&req).into_owned();

        if let Some(code) = req.strip_prefix("exit:") {
            let code: i32 = code.parse().unwrap_or(1);
            eprintln!("exiting with {code}");
            std::process::exit(code);
        }
        if let Some(n) = req.strip_prefix("big:") {
            let n: u32 = n.parse().unwrap_or(u32::MAX - 1);
            let _ = out.write_all(&(n.saturating_add(1)).to_be_bytes());
            let _ = out.write_all(&[0u8]);
            let chunk = [0u8; 65536];
            let mut left = n as usize;
            while left > 0 {
                let k = left.min(chunk.len());
                if out.write_all(&chunk[..k]).is_err() {
                    std::process::exit(0);
                }
                left -= k;
            }
            let _ = out.flush();
            continue;
        }
        if req == "linger" {
            let _ = write_response(&mut out, Ok(b"lingering"));
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }

        let result = handle(&req);
        let r = match &result {
            Ok(b) => write_response(&mut out, Ok(b)),
            Err(m) => write_response(&mut out, Err(m)),
        };
        if r.is_err() {
            return;
        }
    }
}

fn write_response(out: &mut impl Write, r: Result<&[u8], &str>) -> io::Result<()> {
    let (tag, body) = match r {
        Ok(b) => (0u8, b),
        Err(m) => (1u8, m.as_bytes()),
    };
    out.write_all(&((body.len() + 1) as u32).to_be_bytes())?;
    out.write_all(&[tag])?;
    out.write_all(body)?;
    out.flush()
}
