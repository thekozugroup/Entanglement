//! Runtime-kind sniffing: is a plugin artifact what its manifest says it is?
//!
//! Spec §4.4.1 case C / ATC-MAN-3: a manifest that declares a WebAssembly
//! runtime while shipping a native executable (or the reverse) must be
//! rejected at instantiation with `RuntimeKindMismatch { declared, observed }`.
//! The check reads magic bytes only; it never executes or parses further.
//!
//! - Declared **wasm**: any native executable format (ELF, Mach-O, PE) is a
//!   mismatch. Anything else is left to the Wasm compiler, which reports
//!   malformed or core-module input with its own error.
//! - Declared **native**: the artifact must be an executable in *this host's*
//!   format (ELF on Linux, Mach-O on macOS); WebAssembly, scripts, unknown
//!   bytes, or another platform's binary are mismatches.

use std::fmt;

use crate::errors::HostError;

/// The runtime a manifest declares (`[plugin] runtime`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredRuntime {
    /// `runtime = "wasm"` — a WebAssembly component.
    Wasm,
    /// `runtime = "native"` — a native executable for this host.
    Native,
}

impl fmt::Display for DeclaredRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DeclaredRuntime::Wasm => "wasm",
            DeclaredRuntime::Native => "native",
        })
    }
}

/// What an artifact's leading bytes say it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// `\0asm` with the component-model layer.
    WasmComponent,
    /// `\0asm` core module (or an unknown wasm version).
    WasmModule,
    /// ELF executable or shared object (Linux, BSDs).
    Elf,
    /// Mach-O, thin or universal (macOS).
    MachO,
    /// PE/COFF, `MZ` header (Windows).
    Pe,
    /// None of the above.
    Unknown,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ArtifactKind::WasmComponent => "a wasm component",
            ArtifactKind::WasmModule => "a core wasm module",
            ArtifactKind::Elf => "an ELF executable",
            ArtifactKind::MachO => "a Mach-O executable",
            ArtifactKind::Pe => "a PE executable",
            ArtifactKind::Unknown => "unrecognised bytes",
        })
    }
}

/// The executable format native plugins must use on the host this crate was
/// compiled for.
pub const HOST_NATIVE_FORMAT: ArtifactKind = if cfg!(target_os = "macos") {
    ArtifactKind::MachO
} else if cfg!(windows) {
    ArtifactKind::Pe
} else {
    ArtifactKind::Elf
};

impl ArtifactKind {
    /// Classify `bytes` by magic number.
    pub fn sniff(bytes: &[u8]) -> Self {
        let head = |n: usize| bytes.get(..n);
        if head(4) == Some(b"\0asm") {
            // Version/layer word: component = 0x0d 0x00 0x01 0x00 (layer 1).
            return match bytes.get(6..8) {
                Some([1, 0]) => ArtifactKind::WasmComponent,
                _ => ArtifactKind::WasmModule,
            };
        }
        if head(4) == Some(b"\x7fELF") {
            return ArtifactKind::Elf;
        }
        if let Some(&[a, b, c, d]) = head(4) {
            let be = u32::from_be_bytes([a, b, c, d]);
            match be {
                0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE => {
                    return ArtifactKind::MachO
                }
                // Universal binaries share 0xCAFEBABE with Java class files;
                // a fat header's arch count is small, a class file's version
                // is >= 45.
                0xCAFE_BABE | 0xCAFE_BABF => {
                    if let Some(&[e, f, g, h]) = bytes.get(4..8) {
                        if u32::from_be_bytes([e, f, g, h]) < 45 {
                            return ArtifactKind::MachO;
                        }
                    }
                }
                _ => {}
            }
        }
        if head(2) == Some(b"MZ") {
            return ArtifactKind::Pe;
        }
        ArtifactKind::Unknown
    }

    /// `true` for any native executable format, whatever the platform.
    pub fn is_native_executable(self) -> bool {
        matches!(
            self,
            ArtifactKind::Elf | ArtifactKind::MachO | ArtifactKind::Pe
        )
    }
}

/// Check that `bytes` match the `declared` runtime; returns the sniffed kind.
///
/// # Errors
/// [`HostError::RuntimeKindMismatch`] (`ENTANGLE-E0507`) per the rules in the
/// module docs.
pub fn check_runtime_kind(
    declared: DeclaredRuntime,
    bytes: &[u8],
) -> Result<ArtifactKind, HostError> {
    let observed = ArtifactKind::sniff(bytes);
    let ok = match declared {
        DeclaredRuntime::Wasm => !observed.is_native_executable(),
        DeclaredRuntime::Native => observed == HOST_NATIVE_FORMAT,
    };
    if ok {
        Ok(observed)
    } else {
        Err(HostError::RuntimeKindMismatch { declared, observed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_every_known_magic() {
        assert_eq!(
            ArtifactKind::sniff(b"\0asm\x0d\x00\x01\x00"),
            ArtifactKind::WasmComponent
        );
        assert_eq!(
            ArtifactKind::sniff(b"\0asm\x01\x00\x00\x00"),
            ArtifactKind::WasmModule
        );
        assert_eq!(
            ArtifactKind::sniff(b"\x7fELF\x02\x01\x01"),
            ArtifactKind::Elf
        );
        assert_eq!(
            ArtifactKind::sniff(&[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1]),
            ArtifactKind::MachO
        );
        assert_eq!(
            ArtifactKind::sniff(&[0xFE, 0xED, 0xFA, 0xCE]),
            ArtifactKind::MachO
        );
        assert_eq!(
            ArtifactKind::sniff(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]),
            ArtifactKind::MachO
        );
        // A Java class file is not a universal binary.
        assert_eq!(
            ArtifactKind::sniff(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61]),
            ArtifactKind::Unknown
        );
        assert_eq!(ArtifactKind::sniff(b"MZ\x90\x00"), ArtifactKind::Pe);
        assert_eq!(ArtifactKind::sniff(b"#!/bin/sh\n"), ArtifactKind::Unknown);
        assert_eq!(ArtifactKind::sniff(b""), ArtifactKind::Unknown);
    }

    #[test]
    fn wasm_declaration_only_rejects_native_executables() {
        for native in [
            &b"\x7fELF...."[..],
            &[0xCF, 0xFA, 0xED, 0xFE][..],
            &b"MZ.."[..],
        ] {
            let err = check_runtime_kind(DeclaredRuntime::Wasm, native).unwrap_err();
            assert!(err.to_string().contains("ENTANGLE-E0507"), "{err}");
        }
        // Garbage is the compiler's problem, not a kind mismatch.
        assert!(check_runtime_kind(DeclaredRuntime::Wasm, &[0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn native_declaration_requires_this_hosts_format() {
        let mut host_magic: Vec<u8> = match HOST_NATIVE_FORMAT {
            ArtifactKind::MachO => vec![0xCF, 0xFA, 0xED, 0xFE],
            ArtifactKind::Pe => b"MZ".to_vec(),
            _ => b"\x7fELF".to_vec(),
        };
        host_magic.extend_from_slice(&[0; 8]);
        assert_eq!(
            check_runtime_kind(DeclaredRuntime::Native, &host_magic).unwrap(),
            HOST_NATIVE_FORMAT
        );
        let err = check_runtime_kind(DeclaredRuntime::Native, b"#!/bin/sh\nexit 0\n").unwrap_err();
        assert!(matches!(
            err,
            HostError::RuntimeKindMismatch {
                declared: DeclaredRuntime::Native,
                observed: ArtifactKind::Unknown
            }
        ));
    }
}
