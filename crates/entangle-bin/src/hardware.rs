//! CPU and memory capacity of the daemon's execution environment.

pub(super) fn cpu_and_memory() -> (f32, u64) {
    let logical_cores = num_cpus::get() as f32;
    let memory_bytes = host_memory_bytes().unwrap_or_default();

    #[cfg(target_os = "linux")]
    if let (Ok(membership), Ok(mounts)) = (
        std::fs::read_to_string("/proc/self/cgroup"),
        std::fs::read_to_string("/proc/self/mountinfo"),
    ) {
        return linux::limit_capacity(logical_cores, memory_bytes, &membership, &mounts);
    }

    (logical_cores, memory_bytes)
}

#[cfg(target_os = "linux")]
fn host_memory_bytes() -> Option<u64> {
    linux::mem_total_bytes(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

#[cfg(target_os = "macos")]
fn host_memory_bytes() -> Option<u64> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Component, Path, PathBuf};

    #[derive(Clone, Copy)]
    enum Version {
        V1,
        V2,
    }

    pub(super) fn mem_total_bytes(meminfo: &str) -> Option<u64> {
        let total = meminfo
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))?;
        let mut fields = total.split_whitespace();
        let kib = fields.next()?.parse::<u64>().ok()?;
        (fields.next()? == "kB").then_some(())?;
        kib.checked_mul(1024)
    }

    pub(super) fn limit_capacity(
        mut cores: f32,
        mut memory_bytes: u64,
        membership: &str,
        mounts: &str,
    ) -> (f32, u64) {
        for (version, path) in cgroup_directories("cpu", membership, mounts) {
            if let Some(quota_cores) = cpu_quota(version, &path) {
                cores = cores.min(quota_cores);
            }
        }

        for (version, path) in cgroup_directories("memory", membership, mounts) {
            let file = match version {
                Version::V1 => "memory.limit_in_bytes",
                Version::V2 => "memory.max",
            };
            // "max" is unlimited in v2. Taking the minimum also handles the
            // large numeric sentinel used for an unlimited v1 group.
            if let Some(limit) = read_number(&path, file) {
                memory_bytes = memory_bytes.min(limit);
            }
        }
        (cores, memory_bytes)
    }

    fn cpu_quota(version: Version, path: &Path) -> Option<f32> {
        let (quota, period) = match version {
            Version::V1 => (
                read_number(path, "cpu.cfs_quota_us")?,
                read_number(path, "cpu.cfs_period_us")?,
            ),
            Version::V2 => {
                let input = fs::read_to_string(path.join("cpu.max")).ok()?;
                let mut fields = input.split_whitespace();
                (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?)
            }
        };
        if quota == 0 || period == 0 {
            return None;
        }
        Some((quota as f64 / period as f64) as f32)
    }

    fn read_number(path: &Path, file: &str) -> Option<u64> {
        fs::read_to_string(path.join(file))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn cgroup_directories(
        controller: &str,
        membership: &str,
        mounts: &str,
    ) -> Vec<(Version, PathBuf)> {
        let mut directories = Vec::new();
        for line in membership.lines() {
            let Some((_, rest)) = line.split_once(':') else {
                continue;
            };
            let Some((controllers, group)) = rest.split_once(':') else {
                continue;
            };
            let version = if controllers.is_empty() {
                Version::V2
            } else if controllers.split(',').any(|name| name == controller) {
                Version::V1
            } else {
                continue;
            };
            let group = Path::new(group);
            if !group.is_absolute() || group.components().any(|part| part == Component::ParentDir) {
                continue;
            }

            for (root, mount) in mounts
                .lines()
                .filter_map(|line| cgroup_mount(line, version, controller))
            {
                let Ok(relative) = group.strip_prefix(root) else {
                    continue;
                };
                let path = mount.join(relative);
                // A process is constrained by every enclosing group visible
                // through this mount, even if its own group is unlimited.
                for directory in path.ancestors().take_while(|path| path.starts_with(&mount)) {
                    directories.push((version, directory.to_owned()));
                }
            }
        }
        directories
    }

    fn cgroup_mount(line: &str, version: Version, controller: &str) -> Option<(PathBuf, PathBuf)> {
        let (before, after) = line.split_once(" - ")?;
        let mut filesystem = after.split_whitespace();
        match (version, filesystem.next()?) {
            (Version::V2, "cgroup2") => {}
            (Version::V1, "cgroup")
                if filesystem.nth(1)?.split(',').any(|name| name == controller) => {}
            _ => return None,
        }

        let mut fields = before.split_whitespace().skip(3);
        let root = mountinfo_path(fields.next()?);
        let mount = mountinfo_path(fields.next()?);
        Some((root, mount))
    }

    fn mountinfo_path(encoded: &str) -> PathBuf {
        encoded
            .replace(r"\040", " ")
            .replace(r"\011", "\t")
            .replace(r"\012", "\n")
            .replace(r"\134", "\\")
            .into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn meminfo_converts_kib_to_bytes_and_rejects_invalid_values() {
            let meminfo = "MemTotal:       16375452 kB\nMemFree:         2450492 kB\n";
            assert_eq!(mem_total_bytes(meminfo), Some(16_768_462_848));
            assert_eq!(mem_total_bytes("MemFree: 15 kB\n"), None);
            assert_eq!(mem_total_bytes("MemTotal: 15 B\n"), None);
            assert_eq!(mem_total_bytes("MemTotal: 18446744073709551615 kB\n"), None);
        }

        #[test]
        fn v2_limits_include_parent_cgroups() {
            let dir = tempfile::tempdir().unwrap();
            let mount = dir.path().join("cgroup v2");
            let parent = mount.join("workers.slice");
            let leaf = parent.join("entangled.service");
            fs::create_dir_all(&leaf).unwrap();
            fs::write(mount.join("memory.max"), "8589934592\n").unwrap();
            fs::write(parent.join("memory.max"), "2147483648\n").unwrap();
            fs::write(leaf.join("memory.max"), "max\n").unwrap();
            fs::write(parent.join("cpu.max"), "150000 100000\n").unwrap();
            fs::write(leaf.join("cpu.max"), "max 100000\n").unwrap();

            let membership = "0::/delegated/workers.slice/entangled.service\n";
            let escaped_mount = mount.to_str().unwrap().replace(' ', r"\040");
            let mounts = format!("26 24 0:24 /delegated {escaped_mount} rw - cgroup2 cgroup rw\n");
            assert_eq!(
                limit_capacity(8.0, 16 << 30, membership, &mounts),
                (1.5, 2 << 30)
            );
            assert_eq!(
                limit_capacity(1.0, 1 << 30, membership, &mounts),
                (1.0, 1 << 30)
            );
        }

        #[test]
        fn v1_resolves_separate_cpu_and_memory_mounts() {
            let dir = tempfile::tempdir().unwrap();
            let cpu = dir.path().join("cpu,cpuacct");
            let memory = dir.path().join("memory");
            fs::create_dir_all(&cpu).unwrap();
            fs::create_dir_all(memory.join("services")).unwrap();
            fs::write(cpu.join("cpu.cfs_quota_us"), "25000\n").unwrap();
            fs::write(cpu.join("cpu.cfs_period_us"), "100000\n").unwrap();
            fs::write(
                memory.join("memory.limit_in_bytes"),
                "9223372036854771712\n",
            )
            .unwrap();
            fs::write(
                memory.join("services/memory.limit_in_bytes"),
                "1073741824\n",
            )
            .unwrap();

            let membership = "8:cpu,cpuacct:/services\n7:memory:/services\n";
            let mounts = format!(
                "27 24 0:25 /services {} rw - cgroup cgroup rw,cpu,cpuacct\n\
                 28 24 0:26 / {} rw - cgroup cgroup rw,memory\n",
                cpu.display(),
                memory.display()
            );
            assert_eq!(
                limit_capacity(8.0, 16 << 30, membership, &mounts),
                (0.25, 1 << 30)
            );

            fs::write(cpu.join("cpu.cfs_quota_us"), "-1\n").unwrap();
            fs::remove_file(memory.join("services/memory.limit_in_bytes")).unwrap();
            assert_eq!(
                limit_capacity(8.0, 16 << 30, membership, &mounts),
                (8.0, 16 << 30)
            );
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[test]
    fn daemon_reads_cpu_and_memory_from_the_current_system() {
        let (cores, memory_bytes) = super::cpu_and_memory();
        assert!(cores > 0.0 && cores <= num_cpus::get() as f32);
        assert!(memory_bytes > 0 && memory_bytes <= super::host_memory_bytes().unwrap());
    }
}
