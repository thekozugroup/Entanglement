use super::*;

const RUNNING: &str = include_str!("../tests/fixtures/status.json");

#[test]
fn running_status_retains_only_node_addresses_and_distinguishes_offline_peers() {
    let status = parse_status(RUNNING.as_bytes()).unwrap();
    assert!(status.is_running());
    assert_eq!(status.dns_suffix, "mesh.example.ts.net");
    assert_eq!(status.local_ips.len(), 2);
    assert_eq!(status.peers.len(), 2);
    let offline = &status.peers[0];
    assert_eq!(offline.node_id, "nOffline");
    assert!(!offline.online);
    assert!(offline.ips.is_empty());
    let worker = &status.peers[1];
    assert_eq!(worker.node_id, "nWorker");
    assert_eq!(worker.hostname, "worker");
    assert_eq!(worker.magic_dns, "worker.mesh.example.ts.net");
    assert_eq!(
        worker.ips,
        ["100.64.0.2", "fd7a:115c:a1e0::2"].map(|ip| ip.parse::<IpAddr>().unwrap())
    );
    assert!(worker.online);
    assert!(!serde_json::to_string(&status)
        .unwrap()
        .contains("LoginName"));
}

#[test]
fn stopped_status_accepts_null_and_absent_go_collections() {
    let status = parse_status(br#"{"BackendState":"NeedsLogin","Self":null,"Peer":null}"#).unwrap();
    assert!(!status.is_running());
    assert!(status.local_ips.is_empty());
    assert!(status.peers.is_empty());
}

#[test]
fn self_and_unidentified_nodes_are_excluded() {
    let status = parse_status(br#"{"BackendState":"Running","Self":{"ID":"n1","TailscaleIPs":["100.64.0.1"]},"Peer":{"a":{"ID":"n1"},"b":{}}}"#).unwrap();
    assert_eq!(status.local_ips, ["100.64.0.1".parse::<IpAddr>().unwrap()]);
    assert!(!status.is_running());
    assert!(status.peers.is_empty());
}

#[test]
fn rejects_malformed_status_and_unparseable_addresses() {
    for bytes in [
        "{}",
        "not json",
        r#"{"BackendState":"Running","TailscaleIPs":["100.64.0.0/10"]}"#,
    ] {
        assert!(matches!(
            parse_status(bytes.as_bytes()),
            Err(MeshTailscaleError::InvalidStatus(_))
        ));
    }
}

#[test]
fn defaults_use_path_and_entanglement_acls() {
    let config = MeshTailscaleConfig::default();
    assert_eq!(config.resolve_cli(), "tailscale");
    assert_eq!(config.acl_mode, AclMode::EntangleOnTop);
}

#[tokio::test]
async fn missing_cli_reports_not_installed() {
    let dir = tempfile::tempdir().unwrap();
    let mesh = MeshTailscale::new(MeshTailscaleConfig {
        tailscale_cli: dir.path().join("missing").to_str().unwrap().into(),
        ..Default::default()
    });
    assert!(matches!(
        mesh.status().await,
        Err(MeshTailscaleError::NotInstalled)
    ));
}

#[cfg(unix)]
mod command {
    use super::*;
    use std::{os::unix::fs::symlink, path::Path};

    fn fixture(name: &str) -> (tempfile::TempDir, MeshTailscale) {
        let dir = tempfile::tempdir().unwrap();
        // Use a checked-in executable so parallel subprocesses cannot inherit a
        // write descriptor to a just-created script and cause ETXTBSY at exec.
        let path = dir.path().join(name);
        let executable = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/status-cli.sh");
        symlink(executable, &path).unwrap();
        let mesh = MeshTailscale::new(MeshTailscaleConfig {
            tailscale_cli: path.to_str().unwrap().into(),
            ..Default::default()
        });
        (dir, mesh)
    }

    #[tokio::test]
    async fn calls_only_read_only_status_and_reports_inactive_backend() {
        let (_dir, mesh) = fixture("inactive fixture");
        assert_eq!(mesh.status().await.unwrap().backend_state, "NeedsLogin");
        assert!(matches!(
            mesh.start().await,
            Err(MeshTailscaleError::Inactive(state)) if state == "NeedsLogin"
        ));
    }

    #[tokio::test]
    async fn command_failures_do_not_accept_partial_status() {
        let (_dir, mesh) = fixture("failing fixture");
        assert!(matches!(
            mesh.status().await,
            Err(MeshTailscaleError::CommandFailed(status)) if status.code() == Some(42)
        ));
    }

    #[tokio::test]
    async fn oversized_cli_output_is_rejected() {
        let (_dir, mesh) = fixture("oversized fixture");
        assert!(matches!(
            mesh.status().await,
            Err(MeshTailscaleError::OutputTooLarge)
        ));
    }

    #[tokio::test]
    async fn hung_cli_times_out() {
        let (_dir, mesh) = fixture("hung fixture");
        assert!(matches!(
            mesh.status().await,
            Err(MeshTailscaleError::Timeout)
        ));
    }
}
