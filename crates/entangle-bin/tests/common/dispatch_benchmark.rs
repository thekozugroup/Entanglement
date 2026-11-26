//! Opt-in measurements using the same two-daemon fixture as the integration test.

use super::{first_remote, request, start_cluster, Client, Duration, Instant, Path};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::task::JoinSet;

struct Samples {
    latency: Vec<Duration>,
    wall: Duration,
}

impl Samples {
    fn report(mut self, route: &str, concurrency: usize) {
        self.latency.sort_unstable();
        let count = self.latency.len();
        let percentile_ms = |p: usize| {
            let rank = (count * p).div_ceil(100);
            self.latency[rank - 1].as_secs_f64() * 1_000.0
        };
        println!(
            "{route} concurrency={concurrency} requests={count} p50_ms={:.3} p95_ms={:.3} requests_per_s={:.1}",
            percentile_ms(50), percentile_ms(95), count as f64 / self.wall.as_secs_f64(),
        );
    }
}

async fn sample(
    socket: &Path,
    plugin: &str,
    peer: &str,
    count: usize,
    concurrency: usize,
) -> Samples {
    static REQUEST_NUMBER: AtomicU32 = AtomicU32::new(0);
    assert_eq!(count % concurrency, 0);
    let mut clients = JoinSet::new();
    let started = Instant::now();
    for _ in 0..concurrency {
        let client = Client::new(socket);
        let plugin = plugin.to_owned();
        let peer = peer.to_owned();
        clients.spawn(async move {
            let mut times = Vec::with_capacity(count / concurrency);
            for _ in 0..count / concurrency {
                let mut task = request(&plugin);
                let sequence = REQUEST_NUMBER.fetch_add(1, Ordering::Relaxed);
                let input = format!("job{sequence:08x}");
                let expected = format!("Hello, {input}!");
                task.input = input.into_bytes();
                let start = Instant::now();
                let result = client.compute_dispatch(task).await.unwrap();
                times.push(start.elapsed());
                assert_eq!(result.chosen_peer, peer);
                assert_eq!(result.output, expected.as_bytes());
            }
            times
        });
    }
    let mut latency = Vec::with_capacity(count);
    while let Some(times) = clients.join_next().await {
        latency.extend(times.unwrap());
    }
    Samples {
        latency,
        wall: started.elapsed(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "opt-in dispatch performance measurement; see docs/performance.md"]
async fn measure_dispatch() {
    let daemon = std::env::var_os("ENTANGLE_BENCH_DAEMON")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_entangled").into());
    println!("daemon={}", Path::new(&daemon).display());
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    tokio::time::timeout(Duration::from_secs(180), async {
        let cluster = start_cluster(dir.path(), Path::new(&daemon)).await;
        let peer = cluster.worker.peer_id().to_hex();

        let start = Instant::now();
        let local = cluster
            .executor
            .client
            .compute_dispatch(request(&cluster.plugin_id))
            .await
            .unwrap();
        let first_local = start.elapsed();
        assert_eq!(local.chosen_peer, peer);
        assert_eq!(local.output, b"Hello, mesh worker!");
        let (remote, first_remote) = first_remote(&cluster).await;
        assert_eq!(remote.chosen_peer, peer);
        assert_eq!(remote.output, local.output);
        println!(
            "first package_load_ms={:.3} local_ms={:.3} remote_ms={:.3}",
            cluster.package_load.as_secs_f64() * 1_000.0,
            first_local.as_secs_f64() * 1_000.0,
            first_remote.as_secs_f64() * 1_000.0,
        );
        for (route, home) in [
            ("local", &cluster.worker.home),
            ("remote", &cluster.coordinator.home),
        ] {
            let socket = home.join(".entangle/sock");
            for concurrency in [1, 4] {
                sample(&socket, &cluster.plugin_id, &peer, 16, concurrency).await;
                sample(&socket, &cluster.plugin_id, &peer, 1_024, concurrency)
                    .await
                    .report(route, concurrency);
            }
        }
    })
    .await
    .expect("dispatch benchmark timed out");
}
