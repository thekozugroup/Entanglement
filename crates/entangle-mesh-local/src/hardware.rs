//! Real hardware detection for the scheduler's [`HardwareAdvert`].
//!
//! Linux probes read sysfs and procfs files under a [`Probe`] root (`/` in
//! production, a temporary fake tree in tests). They spawn no processes and
//! touch no network. macOS memory is read with one `sysctl` call, and Apple
//! silicon is recognised from the compile-time architecture.
//!
//! Every probe is best-effort: a read error or an unparseable value leaves the
//! corresponding field at its "unknown" value (`0`, `None`) and never panics.
//!
//! The Linux parsers compile on every OS so they can be unit-tested anywhere;
//! on macOS they are unused outside tests, hence the module-level `allow`.

#![cfg_attr(target_os = "macos", allow(dead_code))]

use crate::peer::HardwareAdvert;
use entangle_types::resource::GpuBackend;
use std::fs;
use std::path::{Path, PathBuf};

/// PCI vendor id for NVIDIA.
const PCI_VENDOR_NVIDIA: u32 = 0x10de;
/// PCI vendor id for AMD.
const PCI_VENDOR_AMD: u32 = 0x1002;
/// PCI vendor id for Intel.
const PCI_VENDOR_INTEL: u32 = 0x8086;

/// Detect the local host's hardware and return a populated [`HardwareAdvert`].
///
/// Equivalent to `Probe::host().detect()`. Fields that cannot be determined
/// are left unknown: `memory_bytes` and `gpu_vram_bytes` are `0`, `gpu_backend`
/// and `npu_vendor` are `None`. `network_bandwidth_bps` is always `0` (not
/// measured). `cpu_cores` is `0.0` only if the platform cannot report its
/// parallelism.
pub fn detect() -> HardwareAdvert {
    Probe::host().detect()
}

/// Hardware prober rooted at a filesystem prefix.
///
/// Production code uses [`Probe::host`] (root `/`). Tests build a fake sysfs and
/// procfs tree in a temporary directory and pass its path to [`Probe::new`].
/// The root only affects Linux-style probes. macOS probes ignore it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    root: PathBuf,
}

/// A GPU selected from the probed candidates.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct GpuCandidate {
    backend: GpuBackend,
    vram_bytes: u64,
}

impl Probe {
    /// Create a prober that reads paths relative to `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Create a prober for the running host (root `/`).
    pub fn host() -> Self {
        Self::new("/")
    }

    /// Probe all hardware fields and build a [`HardwareAdvert`].
    pub fn detect(&self) -> HardwareAdvert {
        let (memory_bytes, gpu, npu_vendor) = self.platform_probe();
        let (gpu_backend, gpu_vram_bytes) = match gpu {
            Some(g) => (Some(g.backend), g.vram_bytes),
            None => (None, 0),
        };
        HardwareAdvert {
            cpu_cores: cpu_cores(),
            memory_bytes,
            gpu_backend,
            gpu_vram_bytes,
            network_bandwidth_bps: 0,
            npu_vendor,
        }
    }

    /// Path of `rel` (relative, no leading slash) under the root.
    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Linux, and other non-macOS targets: sysfs/procfs probes under the root.
    #[cfg(not(target_os = "macos"))]
    fn platform_probe(&self) -> (u64, Option<GpuCandidate>, Option<String>) {
        (
            self.meminfo_total_bytes().unwrap_or(0),
            self.drm_gpu(),
            self.accel_npu(),
        )
    }

    /// macOS: `sysctl` memory, Metal and Apple NPU on Apple silicon.
    #[cfg(target_os = "macos")]
    fn platform_probe(&self) -> (u64, Option<GpuCandidate>, Option<String>) {
        let memory = macos_memory_bytes().unwrap_or(0);
        let apple_silicon = std::env::consts::ARCH == "aarch64";
        // Apple silicon uses unified memory, so the GPU can address all of it.
        let gpu = apple_silicon.then_some(GpuCandidate {
            backend: GpuBackend::Metal,
            vram_bytes: memory,
        });
        let npu = apple_silicon.then(|| "apple".to_owned());
        (memory, gpu, npu)
    }

    /// Total memory from `<root>/proc/meminfo`, in bytes.
    fn meminfo_total_bytes(&self) -> Option<u64> {
        let text = fs::read_to_string(self.path("proc/meminfo")).ok()?;
        parse_meminfo_total(&text)
    }

    /// Pick the best GPU from `<root>/sys/class/drm/card*`.
    ///
    /// Discrete cards (NVIDIA, AMD) rank above Intel integrated graphics. Within
    /// a class, the larger VRAM wins. Connector entries such as `card0-DP-1`
    /// are skipped.
    fn drm_gpu(&self) -> Option<GpuCandidate> {
        let drm = self.path("sys/class/drm");
        let mut best: Option<(bool, GpuCandidate)> = None;
        for name in sorted_entries(&drm) {
            if !is_card_name(&name) {
                continue;
            }
            let dev = drm.join(&name).join("device");
            let Some(vendor) = read_hex_u32(&dev.join("vendor")) else {
                continue;
            };
            let Some(backend) = backend_for_vendor(vendor) else {
                continue;
            };
            let vram_bytes = match backend {
                GpuBackend::Cuda => self
                    .nvidia_vram_bytes(&dev)
                    .or_else(|| read_u64(&dev.join("mem_info_vram_total")))
                    .unwrap_or(0),
                _ => read_u64(&dev.join("mem_info_vram_total")).unwrap_or(0),
            };
            let discrete = matches!(backend, GpuBackend::Cuda | GpuBackend::Rocm);
            let candidate = GpuCandidate {
                backend,
                vram_bytes,
            };
            let better = match best {
                None => true,
                Some((best_discrete, best_cand)) => {
                    (discrete, vram_bytes) > (best_discrete, best_cand.vram_bytes)
                }
            };
            if better {
                best = Some((discrete, candidate));
            }
        }
        best.map(|(_, candidate)| candidate)
    }

    /// NVIDIA VRAM from `<root>/proc/driver/nvidia/gpus/<bus>/information`.
    ///
    /// The directory is matched to the card by the PCI bus id that the card's
    /// `device` symlink points to. If that cannot be resolved and exactly one
    /// NVIDIA GPU is present, that GPU is used. Otherwise `None`.
    fn nvidia_vram_bytes(&self, card_dev: &Path) -> Option<u64> {
        let gpus = self.path("proc/driver/nvidia/gpus");
        let by_bus = fs::read_link(card_dev)
            .ok()
            .and_then(|target| target.file_name().map(|s| s.to_string_lossy().into_owned()))
            .and_then(|bus| read_nvidia_information(&gpus.join(bus)));
        if by_bus.is_some() {
            return by_bus;
        }
        match sorted_entries(&gpus).as_slice() {
            [only] => read_nvidia_information(&gpus.join(only)),
            _ => None,
        }
    }

    /// NPU vendor from `<root>/sys/class/accel/accel*`, then `<root>/dev/apex_0`.
    ///
    /// The first recognised driver wins.
    fn accel_npu(&self) -> Option<String> {
        let accel = self.path("sys/class/accel");
        for name in sorted_entries(&accel) {
            if !name.starts_with("accel") {
                continue;
            }
            let dev = accel.join(&name).join("device");
            if let Some(vendor) = driver_name(&dev).as_deref().and_then(npu_vendor_for_driver) {
                return Some(vendor.to_owned());
            }
        }
        if self.path("dev/apex_0").exists() {
            return Some("google-coral".to_owned());
        }
        None
    }
}

/// Logical CPU count, or `0.0` if the platform cannot report it.
fn cpu_cores() -> f32 {
    std::thread::available_parallelism().map_or(0.0, |n| n.get() as f32)
}

/// Parse `MemTotal:` (kB) from `/proc/meminfo` text and return bytes.
fn parse_meminfo_total(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        kb.checked_mul(1024)
    })
}

/// Parse the `Video Memory:` line of an NVIDIA `information` file.
///
/// Accepts `<n>`, optionally followed by `B`, `KB`/`KiB`, `MB`/`MiB` or
/// `GB`/`GiB`. Units are binary (1024-based), matching NVIDIA's own
/// reporting. Returns `None` when the line is absent or unparseable.
fn parse_nvidia_video_memory(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if !key.trim().eq_ignore_ascii_case("Video Memory") {
            return None;
        }
        let mut parts = value.split_whitespace();
        let amount: u64 = parts.next()?.parse().ok()?;
        let multiplier: u64 = match parts.next().unwrap_or("B").to_ascii_lowercase().as_str() {
            "b" | "bytes" => 1,
            "kb" | "kib" => 1 << 10,
            "mb" | "mib" => 1 << 20,
            "gb" | "gib" => 1 << 30,
            _ => return None,
        };
        amount.checked_mul(multiplier)
    })
}

/// Read and parse one NVIDIA GPU's `information` file in `gpu_dir`.
fn read_nvidia_information(gpu_dir: &Path) -> Option<u64> {
    let text = fs::read_to_string(gpu_dir.join("information")).ok()?;
    parse_nvidia_video_memory(&text)
}

/// Map a PCI vendor id to the GPU backend the scheduler uses for it.
fn backend_for_vendor(vendor: u32) -> Option<GpuBackend> {
    match vendor {
        PCI_VENDOR_NVIDIA => Some(GpuBackend::Cuda),
        PCI_VENDOR_AMD => Some(GpuBackend::Rocm),
        PCI_VENDOR_INTEL => Some(GpuBackend::Vulkan),
        _ => None,
    }
}

/// Map a kernel accel driver name to an NPU vendor string.
fn npu_vendor_for_driver(driver: &str) -> Option<&'static str> {
    match driver {
        "intel_vpu" => Some("intel"),
        "amdxdna" => Some("amd"),
        "qaic" => Some("qualcomm"),
        _ => None,
    }
}

/// Driver name of a device: the `driver` symlink target, else `DRIVER=` in `uevent`.
fn driver_name(dev: &Path) -> Option<String> {
    if let Some(name) = fs::read_link(dev.join("driver"))
        .ok()
        .and_then(|target| target.file_name().map(|s| s.to_string_lossy().into_owned()))
    {
        return Some(name);
    }
    let uevent = fs::read_to_string(dev.join("uevent")).ok()?;
    uevent
        .lines()
        .find_map(|line| line.strip_prefix("DRIVER="))
        .map(|s| s.trim().to_owned())
}

/// True for `card<digits>` (not connector entries such as `card0-DP-1`).
fn is_card_name(name: &str) -> bool {
    name.strip_prefix("card")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Names of the entries in `dir`, sorted. Empty if the directory cannot be read.
fn sorted_entries(dir: &Path) -> Vec<String> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Read a file holding a hex PCI id such as `0x10de` (the `0x` is optional).
fn read_hex_u32(path: &Path) -> Option<u32> {
    let text = fs::read_to_string(path).ok()?;
    u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

/// Read a file holding a decimal integer.
fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Total physical memory on macOS, from `sysctl -n hw.memsize`.
#[cfg(target_os = "macos")]
fn macos_memory_bytes() -> Option<u64> {
    let out = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const GIB: u64 = 1 << 30;

    /// Write `contents` to `root/rel`, creating parent directories.
    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("test path has a parent")).expect("mkdir");
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn meminfo_normal() {
        let text = "MemTotal:       16318784 kB\nMemFree:         1000 kB\n";
        assert_eq!(parse_meminfo_total(text), Some(16_318_784 * 1024));
    }

    #[test]
    fn meminfo_missing_line() {
        let text = "MemFree:         1000 kB\nSwapTotal:       2048 kB\n";
        assert_eq!(parse_meminfo_total(text), None);
    }

    #[test]
    fn meminfo_garbage() {
        assert_eq!(parse_meminfo_total("MemTotal: lots kB\n"), None);
        assert_eq!(parse_meminfo_total("MemTotal:\n"), None);
        assert_eq!(parse_meminfo_total("\u{0}\u{1}not a meminfo file"), None);
        assert_eq!(parse_meminfo_total(""), None);
    }

    #[test]
    fn meminfo_via_probe_reads_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "proc/meminfo", "MemTotal:       2048 kB\n");
        let probe = Probe::new(dir.path());
        assert_eq!(probe.detect().memory_bytes, 2048 * 1024);
    }

    #[test]
    fn nvidia_card_with_video_memory() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x10de\n");
        write(
            dir.path(),
            "proc/driver/nvidia/gpus/0000:01:00.0/information",
            "Model:           GeForce RTX 3070\nVideo Memory: 8192 MiB\nIRQ: 130\n",
        );
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Cuda));
        assert_eq!(adv.gpu_vram_bytes, 8 * GIB);
    }

    #[test]
    fn nvidia_card_without_video_memory_has_unknown_vram() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x10de\n");
        write(
            dir.path(),
            "proc/driver/nvidia/gpus/0000:01:00.0/information",
            "Model:           GeForce RTX 3070\nIRQ: 130\n",
        );
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Cuda));
        assert_eq!(adv.gpu_vram_bytes, 0);
    }

    #[test]
    fn nvidia_video_memory_units() {
        assert_eq!(
            parse_nvidia_video_memory("Video Memory: 2 GiB"),
            Some(2 * GIB)
        );
        assert_eq!(
            parse_nvidia_video_memory("Video Memory: 512 MB"),
            Some(512 << 20)
        );
        assert_eq!(parse_nvidia_video_memory("Video Memory: 7"), Some(7));
        assert_eq!(parse_nvidia_video_memory("Video Memory: many MiB"), None);
        assert_eq!(parse_nvidia_video_memory("Video Memory: 4 furlongs"), None);
    }

    #[test]
    fn amd_card_with_vram() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x1002\n");
        write(
            dir.path(),
            "sys/class/drm/card0/device/mem_info_vram_total",
            "17179869184\n",
        );
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Rocm));
        assert_eq!(adv.gpu_vram_bytes, 16 * GIB);
    }

    #[test]
    fn intel_igpu_is_vulkan() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x8086\n");
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Vulkan));
        assert_eq!(adv.gpu_vram_bytes, 0);
    }

    #[test]
    fn discrete_preferred_over_intel_and_connectors_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x8086\n");
        write(dir.path(), "sys/class/drm/card1/device/vendor", "0x1002\n");
        write(
            dir.path(),
            "sys/class/drm/card1/device/mem_info_vram_total",
            "2147483648\n",
        );
        // A connector entry must not be mistaken for a card.
        write(
            dir.path(),
            "sys/class/drm/card0-DP-1/device/vendor",
            "0x10de\n",
        );
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Rocm));
        assert_eq!(adv.gpu_vram_bytes, 2 * GIB);
    }

    #[test]
    fn largest_vram_wins_within_discrete_class() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x1002\n");
        write(
            dir.path(),
            "sys/class/drm/card0/device/mem_info_vram_total",
            "2147483648\n",
        );
        write(dir.path(), "sys/class/drm/card1/device/vendor", "0x1002\n");
        write(
            dir.path(),
            "sys/class/drm/card1/device/mem_info_vram_total",
            "8589934592\n",
        );
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, Some(GpuBackend::Rocm));
        assert_eq!(adv.gpu_vram_bytes, 8 * GIB);
    }

    #[test]
    fn unknown_vendor_is_not_a_gpu() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "sys/class/drm/card0/device/vendor", "0x1234\n");
        write(dir.path(), "sys/class/drm/card1/device/vendor", "not hex\n");
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.gpu_backend, None);
        assert_eq!(adv.gpu_vram_bytes, 0);
    }

    #[test]
    fn npu_intel_vpu_via_uevent() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "sys/class/accel/accel0/device/uevent",
            "DRIVER=intel_vpu\nPCI_ID=8086:7D1D\n",
        );
        assert_eq!(
            Probe::new(dir.path()).detect().npu_vendor.as_deref(),
            Some("intel")
        );
    }

    #[test]
    fn npu_amdxdna_via_uevent_and_unknown_driver_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "sys/class/accel/accel0/device/uevent",
            "DRIVER=some_other\n",
        );
        write(
            dir.path(),
            "sys/class/accel/accel1/device/uevent",
            "DRIVER=amdxdna\n",
        );
        assert_eq!(
            Probe::new(dir.path()).detect().npu_vendor.as_deref(),
            Some("amd")
        );
    }

    #[test]
    fn npu_qualcomm_qaic_via_uevent() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "sys/class/accel/accel0/device/uevent",
            "DRIVER=qaic\n",
        );
        assert_eq!(
            Probe::new(dir.path()).detect().npu_vendor.as_deref(),
            Some("qualcomm")
        );
    }

    #[test]
    fn npu_coral_via_dev_apex() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "dev/apex_0", "");
        assert_eq!(
            Probe::new(dir.path()).detect().npu_vendor.as_deref(),
            Some("google-coral")
        );
    }

    #[cfg(unix)]
    #[test]
    fn npu_driver_symlink_is_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dev = dir.path().join("sys/class/accel/accel0/device");
        fs::create_dir_all(&dev).expect("mkdir");
        let drivers = dir.path().join("sys/bus/drivers/intel_vpu");
        fs::create_dir_all(&drivers).expect("mkdir");
        std::os::unix::fs::symlink(&drivers, dev.join("driver")).expect("symlink");
        assert_eq!(
            Probe::new(dir.path()).detect().npu_vendor.as_deref(),
            Some("intel")
        );
    }

    #[test]
    fn empty_root_is_all_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adv = Probe::new(dir.path()).detect();
        assert_eq!(adv.memory_bytes, 0);
        assert_eq!(adv.gpu_backend, None);
        assert_eq!(adv.gpu_vram_bytes, 0);
        assert_eq!(adv.npu_vendor, None);
        assert_eq!(adv.network_bandwidth_bps, 0);
    }

    #[test]
    fn missing_root_does_not_panic() {
        let adv = Probe::new("/this/path/does/not/exist/hwprobe").detect();
        assert_eq!(adv.memory_bytes, 0);
        assert_eq!(adv.gpu_backend, None);
        assert_eq!(adv.npu_vendor, None);
    }

    #[test]
    fn detect_on_host_is_fast_and_reports_cores() {
        let start = Instant::now();
        let adv = detect();
        let elapsed = start.elapsed();
        assert!(adv.cpu_cores >= 1.0, "cpu_cores was {}", adv.cpu_cores);
        assert!(
            elapsed < Duration::from_millis(200),
            "detect() took {elapsed:?}"
        );
    }
}
