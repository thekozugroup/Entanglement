//! Tier 4–5 native (subprocess) plugins: staging, sandbox profile, invocation
//! (spec §3.4, §3.5, §8.2).
//!
//! # Load
//! After the kernel has verified the signature over the artifact bytes and
//! the manifest, [`NativePlugin::prepare`]:
//! 1. derives a [`SandboxProfile`] from the capabilities the broker granted
//!    (see [`profile_for`]);
//! 2. plans the sandbox for this host — refusing the load when no primitive
//!    is available and the operator has not opted out
//!    (`[security] allow_unsandboxed_native`), *before* anything is written;
//! 3. stages the **verified in-memory bytes** into a fresh private directory
//!    (mode 0700, binary 0500). The plugin is executed from there, never from
//!    the package directory, so swapping the file after verification has no
//!    effect, and a package unpacked without the executable bit still runs.
//!
//! # Invoke
//! Every invocation spawns a fresh sandboxed process (one request, one
//! response; see `entangle_sandbox::frame`), so no state leaks between
//! calls and a timeout kill is always clean.
//!
//! # Capability → sandbox mapping
//! | capability | effect on the child |
//! |---|---|
//! | `storage.local { scope = "plugin" }` | rw `<data>/plugins/<publisher>/<name>`; `ENTANGLE_DATA_DIR`, `HOME`, cwd |
//! | `storage.local { scope = "shared" }` | rw `<data>/shared`; `ENTANGLE_SHARED_DIR` |
//! | `storage.share.<n> { mode = "ro" }` | ro `<data>/shares/<n>`; `ENTANGLE_SHARE_<N>` |
//! | `storage.share.<n> { mode = "rw" }` | rw `<data>/shares/<n>` |
//! | `storage.share.<n> { mode = "rw-scoped" }` | rw `<data>/shares/<n>/<publisher>/<name>` |
//! | `net.lan`, `net.wan` | IP networking allowed (no finer host allowlist yet) |
//! | `host.docker-socket` | rw `/var/run/docker.sock` + `AF_UNIX` sockets |
//! | `compute.gpu` | read, write and ioctl on the GPU device nodes present (`/dev/dri`, `/dev/nvidia*`, `/dev/kfd`) |
//! | `compute.cpu`, `compute.npu`, `mesh.peer`, `agent.invoke`, `custom.*` | none at the OS level |
//!
//! Always: the staged binary (read+exec), the package directory (read-only,
//! for bundled assets), `ENTANGLE_PLUGIN_ID`, `ENTANGLE_PROTOCOL=frame-v1`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use entangle_broker::GrantedCapability;
use entangle_sandbox::{
    InvokeLimits, Plan, Policy, ResourceLimits, SandboxError, SandboxProfile, Supervisor,
    SupervisorError,
};
use entangle_types::capability::{CapabilityKind, ShareMode, StorageScope};
use entangle_types::plugin_id::PluginId;

/// Daemon-wide settings for native plugins (part of `KernelConfig`).
#[derive(Clone, Debug)]
pub struct NativeConfig {
    /// `[security] allow_unsandboxed_native`. Default `false`: a native plugin
    /// is refused (`ENTANGLE-E0700`) on a host with no sandbox primitive.
    pub allow_unsandboxed: bool,
    /// Root of plugin storage scopes. `None` refuses any storage capability
    /// for native plugins (`ENTANGLE-E0741`).
    pub data_dir: Option<PathBuf>,
    /// Where verified binaries are staged. `None` uses the system temp dir.
    pub staging_dir: Option<PathBuf>,
    /// Address-space limit per plugin process (`RLIMIT_AS`).
    pub memory_limit_bytes: Option<u64>,
    /// Largest request accepted.
    pub max_input_bytes: usize,
    /// Largest response accepted; larger ones kill the plugin.
    pub max_output_bytes: usize,
}

impl Default for NativeConfig {
    fn default() -> Self {
        let inv = InvokeLimits::default();
        Self {
            allow_unsandboxed: false,
            data_dir: None,
            staging_dir: None,
            memory_limit_bytes: ResourceLimits::default().address_space_bytes,
            max_input_bytes: inv.max_input_bytes,
            max_output_bytes: inv.max_output_bytes,
        }
    }
}

/// Errors specific to running native plugins.
#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    /// ENTANGLE-E0740: the verified binary could not be staged for execution.
    #[error("ENTANGLE-E0740: cannot stage native plugin binary: {0}")]
    Staging(std::io::Error),

    /// ENTANGLE-E0741: a storage capability was granted but the daemon has no
    /// data directory configured to place it in.
    #[error(
        "ENTANGLE-E0741: plugin {plugin} was granted '{capability}' but no data directory \
         is configured for native plugin storage"
    )]
    NoDataDir {
        /// The plugin.
        plugin: String,
        /// The storage capability.
        capability: String,
    },

    /// ENTANGLE-E0742: a storage-scope directory could not be created.
    #[error("ENTANGLE-E0742: cannot prepare storage scope {path}: {source}")]
    StorageScope {
        /// The scope directory.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },

    /// Planning or engaging the OS sandbox failed (`ENTANGLE-E07xx`).
    #[error(transparent)]
    Sandbox(#[from] SandboxError),

    /// The invocation failed (`ENTANGLE-E072x`).
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
}

/// A private directory holding one staged binary; removed on drop.
#[derive(Debug)]
struct StagingDir {
    dir: PathBuf,
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::debug!(dir = %self.dir.display(), error = %e, "staging dir cleanup failed");
        }
    }
}

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to a fresh `0700` directory under `root` as an `0500` file.
///
/// The directory name is unpredictable and created exclusively (`mkdir`
/// fails if it exists), so a shared `root` such as `/tmp` cannot be used to
/// pre-plant or swap the binary.
fn stage(root: &Path, name: &str, bytes: &[u8]) -> std::io::Result<(StagingDir, PathBuf)> {
    std::fs::create_dir_all(root)?;
    let mut last_err = None;
    for _ in 0..8 {
        let nonce = blake3::hash(
            format!(
                "{}-{}-{:?}",
                std::process::id(),
                STAGE_COUNTER.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
            )
            .as_bytes(),
        );
        let dir = root.join(format!(
            "entangle-native-{name}-{}",
            &nonce.to_hex().as_str()[..16]
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => {
                let guard = StagingDir { dir: dir.clone() };
                let bin = dir.join("plugin");
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o500);
                }
                {
                    use std::io::Write as _;
                    let mut f = opts.open(&bin)?;
                    f.write_all(bytes)?;
                    f.sync_all()?;
                }
                return Ok((guard, bin));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("could not create a staging directory")))
}

/// Layout inputs for [`profile_for`].
#[derive(Clone, Debug)]
pub struct ProfileInputs<'a> {
    /// The plugin.
    pub plugin_id: &'a PluginId,
    /// The staged executable.
    pub binary: &'a Path,
    /// The (read-only) package directory, for bundled assets.
    pub package_dir: Option<&'a Path>,
    /// Root of storage scopes.
    pub data_dir: Option<&'a Path>,
    /// Address-space limit.
    pub memory_limit_bytes: Option<u64>,
}

/// Uppercase, `[A-Z0-9_]` form of a share name for an environment variable.
fn env_suffix(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Derive the sandbox profile from the capabilities the broker **granted**
/// (see the module table). Storage directories are returned for creation;
/// nothing is created here.
pub fn profile_for(
    inputs: &ProfileInputs<'_>,
    grants: &[GrantedCapability],
) -> Result<(SandboxProfile, Vec<PathBuf>), NativeError> {
    let id = inputs.plugin_id;
    let mut p = SandboxProfile::new(inputs.binary)
        .env("ENTANGLE_PLUGIN_ID", id.to_string())
        .env("ENTANGLE_PROTOCOL", "frame-v1")
        .limits(ResourceLimits {
            address_space_bytes: inputs.memory_limit_bytes,
            cpu_time_secs: None, // set per invocation from the deadline
            open_files: ResourceLimits::default().open_files,
        });
    if let Some(dir) = inputs.package_dir {
        p = p.read_only(dir);
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut home: Option<PathBuf> = None;

    let data = |cap: &CapabilityKind| -> Result<&Path, NativeError> {
        inputs.data_dir.ok_or_else(|| NativeError::NoDataDir {
            plugin: id.to_string(),
            capability: format!("{cap:?}"),
        })
    };

    for g in grants {
        match &g.kind {
            CapabilityKind::StorageLocal { scope } => {
                let root = data(&g.kind)?;
                let (dir, var) = match scope {
                    StorageScope::Plugin => (
                        root.join("plugins").join(&id.publisher).join(&id.name),
                        "ENTANGLE_DATA_DIR",
                    ),
                    StorageScope::Shared => (root.join("shared"), "ENTANGLE_SHARED_DIR"),
                };
                if *scope == StorageScope::Plugin {
                    home = Some(dir.clone());
                }
                p = p.read_write(&dir).env(var, &dir);
                dirs.push(dir);
            }
            CapabilityKind::StorageShare { name, mode } => {
                let root = data(&g.kind)?;
                let share = root.join("shares").join(name);
                let var = format!("ENTANGLE_SHARE_{}", env_suffix(name));
                match mode {
                    ShareMode::Ro => p = p.read_only(&share),
                    ShareMode::Rw => p = p.read_write(&share),
                    ShareMode::RwScoped => {
                        let scoped = share.join(&id.publisher).join(&id.name);
                        p = p.read_write(&scoped).env(&var, &scoped);
                        dirs.push(scoped);
                        continue;
                    }
                }
                p = p.env(&var, &share);
                dirs.push(share);
            }
            CapabilityKind::NetLan | CapabilityKind::NetWan => p = p.allow_network(true),
            CapabilityKind::HostDockerSocket => {
                p = p
                    .read_write(resolve_trusted(Path::new("/var/run/docker.sock")))
                    .allow_unix_sockets(true);
            }
            CapabilityKind::ComputeGpu => {
                // Device grants carry ioctl rights; GPU drivers work through
                // ioctls, so a plain read_write grant would be useless.
                for dev in gpu_device_nodes() {
                    p = p.device(dev);
                }
            }
            CapabilityKind::ComputeCpu
            | CapabilityKind::ComputeNpu
            | CapabilityKind::MeshPeer
            | CapabilityKind::AgentInvoke
            | CapabilityKind::Custom(_) => {}
        }
    }
    match &home {
        Some(h) => p = p.env("HOME", h).cwd(h),
        None => p = p.env("HOME", "/nonexistent"),
    }
    Ok((p, dirs))
}

/// GPU device nodes present on this host.
fn gpu_device_nodes() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for fixed in ["/dev/dri", "/dev/kfd"] {
        if Path::new(fixed).exists() {
            v.push(PathBuf::from(fixed));
        }
    }
    if let Ok(rd) = std::fs::read_dir("/dev") {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("nvidia") {
                v.push(e.path());
            }
        }
    }
    v
}

/// A loaded native plugin: verified binary staged, sandbox planned.
#[derive(Debug)]
pub struct NativePlugin {
    plugin_id: PluginId,
    profile: SandboxProfile,
    plan: Plan,
    max_input_bytes: usize,
    max_output_bytes: usize,
    _staging: StagingDir,
}

impl NativePlugin {
    /// Plan the sandbox, then stage `bytes` (already signature-verified).
    ///
    /// Refuses — before writing anything — when the host cannot sandbox the
    /// plugin and the operator has not opted out.
    pub fn prepare(
        plugin_id: &PluginId,
        bytes: &[u8],
        package_dir: Option<&Path>,
        grants: &[GrantedCapability],
        config: &NativeConfig,
    ) -> Result<Self, NativeError> {
        // Scopes are granted without following links, so resolve the trusted
        // roots they hang off first (see `resolve_trusted`).
        let package_dir = package_dir.map(resolve_trusted);
        let package_dir = package_dir.as_deref();
        let data_dir = config.data_dir.as_deref().map(resolve_trusted);

        // Plan against a placeholder binary path first: the decision depends
        // only on the capabilities and the host, and refusing must not leave
        // a staged copy behind.
        let placeholder = Path::new("/entangle-native-placeholder");
        let (probe_profile, _) = profile_for(
            &ProfileInputs {
                plugin_id,
                binary: placeholder,
                package_dir,
                data_dir: data_dir.as_deref(),
                memory_limit_bytes: config.memory_limit_bytes,
            },
            grants,
        )?;
        let plan = entangle_sandbox::plan(
            &probe_profile,
            entangle_sandbox::probe(),
            Policy {
                allow_unsandboxed: config.allow_unsandboxed,
            },
        )?;

        let root = config
            .staging_dir
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        let (staging, binary) =
            stage(&root, &plugin_id.name, bytes).map_err(NativeError::Staging)?;

        let (profile, dirs) = profile_for(
            &ProfileInputs {
                plugin_id,
                binary: &binary,
                package_dir,
                data_dir: data_dir.as_deref(),
                memory_limit_bytes: config.memory_limit_bytes,
            },
            grants,
        )?;
        for d in dirs {
            create_private_dir(&d).map_err(|source| NativeError::StorageScope {
                path: d.clone(),
                source,
            })?;
        }

        if plan.is_degraded() {
            tracing::warn!(plugin = %plugin_id, sandbox = %plan.describe(), "native plugin runs with REDUCED isolation");
        } else {
            tracing::info!(plugin = %plugin_id, sandbox = %plan.describe(), "native plugin sandbox planned");
        }

        Ok(Self {
            plugin_id: plugin_id.clone(),
            profile,
            plan,
            max_input_bytes: config.max_input_bytes,
            max_output_bytes: config.max_output_bytes,
            _staging: staging,
        })
    }

    /// The sandbox plan engaged for every invocation.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// The sandbox profile (without the per-invocation CPU limit).
    pub fn profile(&self) -> &SandboxProfile {
        &self.profile
    }

    /// Run one invocation in a fresh sandboxed process.
    pub async fn invoke(&self, input: &[u8], timeout_ms: u64) -> Result<Vec<u8>, NativeError> {
        #[cfg(not(unix))]
        {
            let _ = (input, timeout_ms);
            Err(NativeError::Sandbox(SandboxError::UnsupportedPlatform {
                reason: "native plugins require a Unix host".into(),
            }))
        }
        #[cfg(unix)]
        {
            let mut profile = self.profile.clone();
            // CPU seconds track the wall-clock deadline (plus one second of
            // slack); the deadline itself is enforced by the supervisor.
            profile.limits.cpu_time_secs = Some(timeout_ms.div_ceil(1000).saturating_add(1));
            let cmd = entangle_sandbox::sandboxed_command(&profile, &self.plan)?;
            let limits = InvokeLimits {
                timeout: Duration::from_millis(timeout_ms.max(1)),
                max_input_bytes: self.max_input_bytes,
                max_output_bytes: self.max_output_bytes,
                exit_grace: InvokeLimits::default().exit_grace,
            };
            Ok(Supervisor::new(self.plugin_id.to_string(), limits)
                .invoke(cmd, input)
                .await?)
        }
    }
}

/// Resolve a *trusted* root — one no plugin can write to or above, such as
/// the daemon's data directory, a package directory or `/var/run` — to its
/// canonical form. The longest existing ancestor is canonicalised and the
/// rest appended, so a data directory that does not exist yet still loses
/// the OS symlinks above it (`/home` → `var/home`).
///
/// Scopes derived from these roots are then granted without following any
/// link (`entangle-sandbox` refuses one), so a link a plugin plants *below*
/// a root can never redirect another plugin's grant.
fn resolve_trusted(p: &Path) -> PathBuf {
    let mut existing = p;
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(mut c) = std::fs::canonicalize(existing) {
            c.extend(rest.iter().rev());
            return c;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// `mkdir -p` with mode 0700 on every directory it creates (Unix), without
/// following symbolic links: a plugin with write access to a share can plant
/// links beneath it, and following one would create directories wherever it
/// points. Callers pass paths under a [`resolve_trusted`] root.
fn create_private_dir(d: &Path) -> std::io::Result<()> {
    use std::path::Component;
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    let mut cur = PathBuf::new();
    for comp in d.components() {
        cur.push(comp);
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a storage path may not contain '..'",
                ))
            }
            Component::Normal(_) => {}
        }
        // Create if missing (an existing entry, e.g. from a concurrent load,
        // is then inspected like any other).
        match b.create(&cur) {
            Ok(()) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = std::fs::symlink_metadata(&cur)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is a symbolic link", cur.display()),
            ));
        }
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a directory", cur.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PluginId {
        "aabbccddeeff00112233445566778899/echo@0.1.0"
            .parse()
            .unwrap()
    }

    fn grant(kind: CapabilityKind) -> GrantedCapability {
        GrantedCapability {
            grant_id: 1,
            plugin: pid(),
            kind,
        }
    }

    fn inputs<'a>(id: &'a PluginId, data: Option<&'a Path>) -> ProfileInputs<'a> {
        ProfileInputs {
            plugin_id: id,
            binary: Path::new("/stage/plugin"),
            package_dir: Some(Path::new("/pkg")),
            data_dir: data,
            memory_limit_bytes: Some(1 << 30),
        }
    }

    #[test]
    fn no_capabilities_means_no_storage_and_no_network() {
        let id = pid();
        let (p, dirs) = profile_for(&inputs(&id, Some(Path::new("/data"))), &[]).unwrap();
        assert!(!p.allow_network && !p.allow_unix_sockets);
        assert!(p.read_write.is_empty());
        assert_eq!(p.read_only, vec![PathBuf::from("/pkg")]);
        assert!(dirs.is_empty());
        assert!(p
            .env
            .iter()
            .any(|(k, v)| k == "ENTANGLE_PLUGIN_ID" && v == id.to_string().as_str()));
        assert!(p
            .env
            .iter()
            .any(|(k, v)| k == "HOME" && v == "/nonexistent"));
    }

    #[test]
    fn storage_scopes_map_to_per_plugin_directories() {
        let id = pid();
        let grants = [
            grant(CapabilityKind::StorageLocal {
                scope: StorageScope::Plugin,
            }),
            grant(CapabilityKind::StorageLocal {
                scope: StorageScope::Shared,
            }),
            grant(CapabilityKind::StorageShare {
                name: "photos".into(),
                mode: ShareMode::Ro,
            }),
            grant(CapabilityKind::StorageShare {
                name: "inbox".into(),
                mode: ShareMode::RwScoped,
            }),
        ];
        let (p, dirs) = profile_for(&inputs(&id, Some(Path::new("/data"))), &grants).unwrap();
        let own = PathBuf::from("/data/plugins/aabbccddeeff00112233445566778899/echo");
        assert!(p.read_write.contains(&own));
        assert!(p.read_write.contains(&PathBuf::from("/data/shared")));
        assert!(p.read_only.contains(&PathBuf::from("/data/shares/photos")));
        assert!(p.read_write.contains(&PathBuf::from(
            "/data/shares/inbox/aabbccddeeff00112233445566778899/echo"
        )));
        assert!(!p.read_write.contains(&PathBuf::from("/data/shares/photos")));
        assert_eq!(p.cwd.as_deref(), Some(own.as_path()));
        assert!(dirs.contains(&own));
        assert!(p.env.iter().any(|(k, _)| k == "ENTANGLE_SHARE_PHOTOS"));
    }

    #[test]
    fn network_and_docker_socket_capabilities() {
        let id = pid();
        let (p, _) = profile_for(&inputs(&id, None), &[grant(CapabilityKind::NetWan)]).unwrap();
        assert!(p.allow_network);
        let (p, _) = profile_for(
            &inputs(&id, None),
            &[grant(CapabilityKind::HostDockerSocket)],
        )
        .unwrap();
        assert!(p.allow_unix_sockets);
        // `/var/run` is a link to `/run` on most hosts; the grant names the
        // resolved socket (scopes are granted without following links).
        assert!(p
            .read_write
            .contains(&resolve_trusted(Path::new("/var/run/docker.sock"))));
        assert!(!p.allow_network);
    }

    #[test]
    fn storage_without_a_data_dir_is_refused() {
        let id = pid();
        let err = profile_for(
            &inputs(&id, None),
            &[grant(CapabilityKind::StorageLocal {
                scope: StorageScope::Plugin,
            })],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0741"), "{err}");
    }

    /// A plugin with `rw` on a share can plant links beneath it; creating
    /// another plugin's scope directory must not follow them (it would
    /// create directories wherever the link points).
    #[cfg(unix)]
    #[test]
    fn scope_directories_are_created_without_following_links() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let share = tmp.path().join("share");
        std::fs::create_dir(&share).unwrap();
        std::os::unix::fs::symlink(&outside, share.join("publisher")).unwrap();
        let err = create_private_dir(&share.join("publisher/victim")).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!outside.join("victim").exists());
        // Without links it is `mkdir -p` with private leaves.
        let ok = share.join("real/a/b");
        create_private_dir(&ok).unwrap();
        create_private_dir(&ok).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&ok).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// Scopes are granted without following links (entangle-sandbox), so the
    /// trusted roots they hang off — the data directory, the package
    /// directory — are resolved first: an OS symlink above them (Fedora
    /// Silverblue's `/home` → `var/home`, `/var/run` → `/run`) must not make
    /// every grant fail.
    #[cfg(unix)]
    #[test]
    fn trusted_roots_are_resolved_before_scopes_are_derived() {
        let tmp = tempfile::tempdir().unwrap();
        let real_home = tmp.path().join("var-home");
        std::fs::create_dir_all(real_home.join("pkg")).unwrap();
        let link_home = tmp.path().join("home");
        std::os::unix::fs::symlink(&real_home, &link_home).unwrap();
        let canonical = std::fs::canonicalize(&real_home).unwrap();

        // The data directory need not exist yet.
        assert_eq!(
            resolve_trusted(&link_home.join("data/x")),
            canonical.join("data/x")
        );
        assert_eq!(
            resolve_trusted(&link_home.join("pkg")),
            canonical.join("pkg")
        );

        let id = pid();
        let config = NativeConfig {
            data_dir: Some(link_home.join("data")),
            staging_dir: Some(tmp.path().join("stage")),
            allow_unsandboxed: true,
            ..NativeConfig::default()
        };
        let grants = [grant(CapabilityKind::StorageLocal {
            scope: StorageScope::Plugin,
        })];
        let plugin = match NativePlugin::prepare(
            &id,
            b"\x7fELF",
            Some(&link_home.join("pkg")),
            &grants,
            &config,
        ) {
            Ok(p) => p,
            Err(NativeError::Sandbox(e)) => {
                eprintln!("skipping: no sandbox plan on this host: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let prof = plugin.profile();
        assert_eq!(prof.read_only, vec![canonical.join("pkg")]);
        assert_eq!(
            prof.read_write,
            vec![canonical
                .join("data/plugins")
                .join(&id.publisher)
                .join(&id.name)]
        );
    }

    #[test]
    fn staging_is_private_and_removed_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let (guard, bin) = stage(root.path(), "echo", b"\x7fELFbytes").unwrap();
        assert_eq!(std::fs::read(&bin).unwrap(), b"\x7fELFbytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(bin.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            let bin_mode = std::fs::metadata(&bin).unwrap().permissions().mode();
            assert_eq!(bin_mode & 0o777, 0o500);
        }
        let dir = bin.parent().unwrap().to_path_buf();
        drop(guard);
        assert!(!dir.exists());
        // Two stagings never share a directory.
        let (_a, a) = stage(root.path(), "echo", b"a").unwrap();
        let (_b, b) = stage(root.path(), "echo", b"b").unwrap();
        assert_ne!(a.parent(), b.parent());
    }
}
