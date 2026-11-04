//! Test fixture that probes what a plugin's capability grants let it do.
//!
//! The input is a script: one command per line, words separated by single
//! spaces. The output has exactly one result line per command, either `ok`,
//! `ok:<detail>`, or `err:<kind>:<message>`, so a test can assert on each
//! step independently.
//!
//! | command                 | effect                                             |
//! |-------------------------|----------------------------------------------------|
//! | `write <path> <text>`   | `std::fs::write`                                   |
//! | `read <path>`           | `std::fs::read_to_string` → `ok:<text>`            |
//! | `mkdir <path>`          | `std::fs::create_dir`                              |
//! | `ls <path>`             | sorted entry names → `ok:a,b,c`                    |
//! | `symlink <target> <link>` | create a symbolic link (wasi-libc `symlink`)     |
//! | `connect <host:port>`   | TCP connect (resolving names), read the greeting   |
//! | `listen <ip:port>`      | TCP bind + listen                                  |
//! | `udp <ip:port>`         | bind an ephemeral UDP socket and send one datagram |
//! | `udprecv <ip:port>`     | as `udp`, then receive one datagram → `ok:<from>:<text>` |
//! | `resolve <host>`        | DNS lookup → `ok:<ip>,<ip>`                        |
//! | `fetch <kind> [<name>]` | `capability.fetch` → `ok:<handle>`                 |
//! | `release <handle>`      | `capability.release`                               |
//! | `info`                  | `host-info.get` → `ok:<plugin-id>@<tier>`          |
//!
//! Fetch errors are reported as `err:not-granted:<reason>`, `err:revoked:`
//! or `err:invalid-kind:`.

use entangle_sdk::capability::{fetch, release, FetchError, Kind};
use entangle_sdk::{entangle_plugin, PluginError};
use std::io::{Read, Write};

fn io_err(e: std::io::Error) -> String {
    format!("err:{:?}:{e}", e.kind())
}

fn kind(s: &str) -> Option<Kind> {
    Some(match s {
        "compute-cpu" => Kind::ComputeCpu,
        "compute-gpu" => Kind::ComputeGpu,
        "compute-npu" => Kind::ComputeNpu,
        "storage-local" => Kind::StorageLocal,
        "storage-share" => Kind::StorageShare,
        "net-lan" => Kind::NetLan,
        "net-wan" => Kind::NetWan,
        "mesh-peer" => Kind::MeshPeer,
        "agent-invoke" => Kind::AgentInvoke,
        "host-docker-socket" => Kind::HostDockerSocket,
        "custom" => Kind::Custom,
        _ => return None,
    })
}

extern "C" {
    // wasi-libc; std does not expose symlink creation on wasm32-wasip2.
    fn symlink(target: *const std::ffi::c_char, link: *const std::ffi::c_char) -> i32;
}

fn make_symlink(target: &str, link: &str) -> String {
    let (Ok(t), Ok(l)) = (
        std::ffi::CString::new(target),
        std::ffi::CString::new(link),
    ) else {
        return "err:InvalidInput:nul byte".into();
    };
    // SAFETY: both pointers are valid NUL-terminated strings that outlive the call.
    let rc = unsafe { symlink(t.as_ptr(), l.as_ptr()) };
    if rc == 0 {
        "ok".into()
    } else {
        io_err(std::io::Error::last_os_error())
    }
}

fn step(line: &str) -> String {
    let mut words = line.splitn(3, ' ');
    let cmd = words.next().unwrap_or("");
    let a = words.next().unwrap_or("");
    let b = words.next();
    match cmd {
        "write" => match std::fs::write(a, b.unwrap_or("")) {
            Ok(()) => "ok".into(),
            Err(e) => io_err(e),
        },
        "read" => match std::fs::read_to_string(a) {
            Ok(s) => format!("ok:{s}"),
            Err(e) => io_err(e),
        },
        "mkdir" => match std::fs::create_dir(a) {
            Ok(()) => "ok".into(),
            Err(e) => io_err(e),
        },
        "ls" => match std::fs::read_dir(a) {
            Ok(rd) => {
                let mut names: Vec<String> = rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                format!("ok:{}", names.join(","))
            }
            Err(e) => io_err(e),
        },
        "symlink" => make_symlink(a, b.unwrap_or("")),
        "connect" => match std::net::TcpStream::connect(a) {
            Ok(mut s) => {
                let _ = s.write_all(b"hi");
                let mut buf = [0u8; 64];
                match s.read(&mut buf) {
                    Ok(n) => format!("ok:{}", String::from_utf8_lossy(&buf[..n])),
                    Err(e) => io_err(e),
                }
            }
            Err(e) => io_err(e),
        },
        "listen" => match std::net::TcpListener::bind(a) {
            Ok(_) => "ok".into(),
            Err(e) => io_err(e),
        },
        "udp" => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => match s.send_to(b"ping", a) {
                Ok(_) => "ok".into(),
                Err(e) => io_err(e),
            },
            Err(e) => io_err(e),
        },
        "udprecv" => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => match s.send_to(b"ping", a) {
                Ok(_) => {
                    let mut buf = [0u8; 64];
                    match s.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            format!("ok:{from}:{}", String::from_utf8_lossy(&buf[..n]))
                        }
                        Err(e) => io_err(e),
                    }
                }
                Err(e) => io_err(e),
            },
            Err(e) => io_err(e),
        },
        "resolve" => {
            use std::net::ToSocketAddrs;
            match (a, 0u16).to_socket_addrs() {
                Ok(addrs) => {
                    let mut ips: Vec<String> = addrs.map(|s| s.ip().to_string()).collect();
                    ips.sort();
                    ips.dedup();
                    format!("ok:{}", ips.join(","))
                }
                Err(e) => io_err(e),
            }
        }
        "fetch" => {
            let Some(k) = kind(a) else {
                return format!("err:bad-kind-string:{a}");
            };
            match fetch(k, b) {
                Ok(h) => format!("ok:{h}"),
                Err(FetchError::NotGranted(why)) => format!("err:not-granted:{why}"),
                Err(FetchError::Revoked) => "err:revoked:".into(),
                Err(FetchError::InvalidKind) => "err:invalid-kind:".into(),
            }
        }
        "release" => match a.parse::<u32>() {
            Ok(h) => {
                release(h);
                "ok".into()
            }
            Err(e) => format!("err:bad-handle:{e}"),
        },
        "info" => {
            let i = entangle_sdk::host_info::get();
            format!("ok:{}@{}", i.plugin_id, i.effective_tier)
        }
        other => format!("err:unknown-command:{other}"),
    }
}

fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
    let script =
        String::from_utf8(input).map_err(|e| PluginError::InvalidInput(e.to_string()))?;
    let mut out = String::new();
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push_str(&step(line));
        out.push('\n');
    }
    Ok(out.into_bytes())
}

entangle_plugin!(run);
