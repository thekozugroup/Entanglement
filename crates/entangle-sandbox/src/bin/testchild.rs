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
//! | `unix-dgram:<path>`  | `socketpair(AF_UNIX, SOCK_DGRAM)` + `sendto(path)`     |
//! | `unshare`            | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)`; ok or err(errno) |
//! | `prlimit:<pid>`      | set `pid`'s RLIMIT_NOFILE soft limit to 123            |
//! | `renice:<pid>`       | `setpriority(PRIO_PROCESS, pid, 5)`                    |
//! | `keyring:<desc>`     | search the session keyring for user key `desc`, read it |
//! | `caps`               | ok("eff=.. prm=.. inh=.. bnd=N amb=N") (sets in hex, counts) |
//! | `raw`                | `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`              |
//! | `thread`             | spawn and join a thread; ok("joined")                  |
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
        "unix-dgram" => unix_dgram(arg),
        "unshare" => {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: integer-only syscall; this helper is single-threaded.
                if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0 {
                    Ok(b"unshared".to_vec())
                } else {
                    Err(errno_msg(&io::Error::last_os_error()))
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("unsupported".into())
            }
        }
        "prlimit" => {
            #[cfg(target_os = "linux")]
            {
                let pid: libc::pid_t = arg.parse().map_err(|e| format!("bad pid: {e}"))?;
                let mut old = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: NULL new limit; `old` is a valid out-pointer.
                if unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) }
                    != 0
                {
                    return Err(errno_msg(&io::Error::last_os_error()));
                }
                let new = libc::rlimit {
                    rlim_cur: 123.min(old.rlim_max),
                    rlim_max: old.rlim_max,
                };
                // SAFETY: valid in-pointer; NULL old limit.
                if unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, &new, std::ptr::null_mut()) }
                    != 0
                {
                    return Err(errno_msg(&io::Error::last_os_error()));
                }
                Ok(b"set".to_vec())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("unsupported".into())
            }
        }
        "renice" => {
            let pid: libc::id_t = arg.parse().map_err(|e| format!("bad pid: {e}"))?;
            // SAFETY: integer-only libc call.
            if unsafe { libc::setpriority(libc::PRIO_PROCESS, pid, 5) } != 0 {
                return Err(errno_msg(&io::Error::last_os_error()));
            }
            Ok(b"reniced".to_vec())
        }
        "keyring" => keyring_read(arg),
        "caps" => caps(),
        "raw" => {
            // SAFETY: integer-only libc call.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            if fd < 0 {
                return Err(errno_msg(&io::Error::last_os_error()));
            }
            // SAFETY: closing the descriptor just created.
            unsafe { libc::close(fd) };
            Ok(b"raw".to_vec())
        }
        "thread" => std::thread::Builder::new()
            .spawn(|| 42)
            .map_err(|e| errno_msg(&e))?
            .join()
            .map(|_| b"joined".to_vec())
            .map_err(|_| "thread panicked".to_owned()),
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

/// `socketpair(AF_UNIX, SOCK_DGRAM)`, then send "escaped" from one end to the
/// path-named datagram socket at `path`.
#[cfg(target_os = "linux")]
fn unix_dgram(path: &str) -> Result<Vec<u8>, String> {
    use std::os::unix::ffi::OsStrExt;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid out-array of two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(errno_msg(&io::Error::last_os_error()));
    }
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = std::ffi::OsStr::new(path).as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err("path too long".into());
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let msg = b"escaped";
    // SAFETY: valid descriptor, buffer and address of the stated length.
    let n = unsafe {
        libc::sendto(
            fds[0],
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(errno_msg(&io::Error::last_os_error()));
    }
    Ok(b"sent".to_vec())
}

#[cfg(not(target_os = "linux"))]
fn unix_dgram(_path: &str) -> Result<Vec<u8>, String> {
    Err("unsupported".into())
}

/// `keyctl(KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, "user", desc)` then
/// `KEYCTL_READ`: what a plugin would do to lift a secret from the
/// keyring it inherited.
#[cfg(target_os = "linux")]
fn keyring_read(desc: &str) -> Result<Vec<u8>, String> {
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    let desc = std::ffi::CString::new(desc).map_err(|e| e.to_string())?;
    // SAFETY: NUL-terminated strings that outlive the call.
    let id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SEARCH,
            KEY_SPEC_SESSION_KEYRING,
            c"user".as_ptr(),
            desc.as_ptr(),
            0 as libc::c_long,
        )
    };
    if id < 0 {
        return Err(errno_msg(&io::Error::last_os_error()));
    }
    let mut buf = vec![0u8; 256];
    // SAFETY: `buf` is a live buffer of the stated length.
    let n = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            id,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(errno_msg(&io::Error::last_os_error()));
    }
    buf.truncate((n as usize).min(256));
    Ok(buf)
}

#[cfg(not(target_os = "linux"))]
fn keyring_read(_desc: &str) -> Result<Vec<u8>, String> {
    Err("unsupported".into())
}

/// The capability sets of this process: effective/permitted/inheritable (hex
/// bitmasks from `capget`), and how many capabilities remain in the bounding
/// and ambient sets.
#[cfg(target_os = "linux")]
fn caps() -> Result<Vec<u8>, String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = Header {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: valid header and a two-element data array (version 3).
    if unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(errno_msg(&io::Error::last_os_error()));
    }
    let wide = |f: fn(&Data) -> u32| (u64::from(f(&data[1])) << 32) | u64::from(f(&data[0]));
    let count = |op: libc::c_int, sub: libc::c_ulong| {
        (0..64u64)
            .filter(|c| {
                // SAFETY: integer-only prctl.
                let r = unsafe {
                    if op == libc::PR_CAPBSET_READ {
                        libc::prctl(op, *c as libc::c_ulong, 0, 0, 0)
                    } else {
                        libc::prctl(op, sub, *c as libc::c_ulong, 0, 0)
                    }
                };
                r == 1
            })
            .count()
    };
    Ok(format!(
        "eff={:x} prm={:x} inh={:x} bnd={} amb={}",
        wide(|d| d.effective),
        wide(|d| d.permitted),
        wide(|d| d.inheritable),
        count(libc::PR_CAPBSET_READ, 0),
        count(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong
        ),
    )
    .into_bytes())
}

#[cfg(not(target_os = "linux"))]
fn caps() -> Result<Vec<u8>, String> {
    Err("unsupported".into())
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
