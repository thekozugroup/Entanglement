//! Recursive RAW photo processing through authenticated one-shot scheduler calls.

mod files;

use self::files::StagedFile;
use super::{
    image_raster::{
        Raster, RasterOutput, Tile, DEFAULT_TILE_EDGE, MAX_DIMENSION, MAX_PIXELS, MAX_TILE_EDGE,
    },
    image_raw::{self, MAX_INPUT_BYTES},
};
use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Subcommand};
use entangle_rpc::{
    methods::{ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity},
    Client, RpcError,
};
use entangle_types::{peer_id::PeerId, plugin_id::PluginId, task::OneShotTask};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Seek, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const RECEIPT_VERSION: u32 = 1;
const OUTPUT_LIMIT: u64 = MAX_PIXELS as u64 * 6 + MAX_DIMENSION as u64 + 2 * 1024 * 1024;
const TILE_BATCH_BYTES: usize = 32 * 1024 * 1024;

type TileResult = Result<(Tile, ComputeDispatchResult)>;

#[derive(Args)]
pub struct ImageArgs {
    #[command(subcommand)]
    cmd: ImageCmd,
}

#[derive(Subcommand)]
enum ImageCmd {
    /// Dehaze RAW photos using the signed image-dehaze plugin on trusted workers.
    #[command(
        long_about = "Dehaze RAW photos using the signed image-dehaze plugin. A running daemon and an explicit executor allowlist are required."
    )]
    Dehaze(DehazeArgs),
}

#[derive(Args)]
struct DehazeArgs {
    /// Scan this directory recursively for supported RAW files.
    #[arg(long, value_name = "INPUT_DIR")]
    recursive: PathBuf,
    /// Save images under this separate directory, mirroring input subdirectories.
    #[arg(long, value_name = "OUTPUT_DIR")]
    output_dir: PathBuf,
    /// Exact loaded image-dehaze plugin ID.
    #[arg(long)]
    plugin: PluginId,
    /// Trusted executor peer ID. Repeat to allow several workers.
    #[arg(long = "allow", required = true, value_name = "PEER")]
    allow: Vec<String>,
    /// Maximum in-flight tiles. Each batch decodes and assembles one photo at a time.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=8))]
    jobs: u32,
    /// Maximum width or height of each output tile before halo padding.
    #[arg(long, default_value_t = DEFAULT_TILE_EDGE, value_parser = clap::value_parser!(u32).range(128..=i64::from(MAX_TILE_EDGE)))]
    tile_edge: u32,
    /// Deadline for the worker to render an individual tile.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS, value_parser = clap::value_parser!(u64).range(1..=300_000))]
    timeout_ms: u64,
    /// Reuse completed outputs whose hashes match and whose workers are still allowed.
    #[arg(long)]
    resume: bool,
    /// Emit one JSON object per photo and a final summary.
    #[arg(long)]
    json: bool,
}

#[derive(Deserialize, Serialize)]
struct Receipt {
    version: u32,
    plugin: String,
    tile_edge: u32,
    input: String,
    output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_path_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_path_hex: Option<String>,
    input_blake3: String,
    output_blake3: String,
    width: u32,
    height: u32,
    workers: BTreeMap<String, usize>,
    tile_workers: Vec<String>,
}

#[derive(Serialize)]
struct Summary {
    status: &'static str,
    processed: usize,
    resumed: usize,
    failed: usize,
    skipped: usize,
}

struct Batch {
    client: Arc<Client>,
    plugin: String,
    allow: Vec<String>,
    jobs: usize,
    tile_edge: u32,
    timeout_ms: u64,
    resume: bool,
    input_root: File,
    output_root: File,
    state: File,
}

pub async fn run(args: ImageArgs) -> Result<()> {
    match args.cmd {
        ImageCmd::Dehaze(args) => run_dehaze(args).await,
    }
}

async fn run_dehaze(args: DehazeArgs) -> Result<()> {
    ensure!(
        args.plugin.name == "image-dehaze",
        "--plugin must name a signed image-dehaze package"
    );
    let mut allow = args
        .allow
        .iter()
        .map(|id| {
            PeerId::from_hex(id)
                .map(|id| id.to_hex())
                .with_context(|| format!("invalid --allow peer ID {id:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    allow.sort_unstable();
    allow.dedup();

    let client = Arc::new(Client::new(Client::default_socket()));
    tokio::time::timeout(Duration::from_secs(5), client.mesh_status())
        .await
        .context("waiting for the local Entanglement daemon")?
        .map_err(|error| match error {
            RpcError::DaemonNotRunning(_) => crate::daemon_not_running_error(),
            other => other.into(),
        })?;

    let (input_root, output_root) = files::roots(&args.recursive, &args.output_dir)?;
    let (state, _lock) = files::private_state(&output_root)?;
    let batch = Batch {
        client,
        plugin: args.plugin.to_string(),
        allow,
        jobs: args.jobs as usize,
        tile_edge: args.tile_edge,
        timeout_ms: args.timeout_ms,
        resume: args.resume,
        input_root,
        output_root,
        state,
    };

    let mut paths = Vec::new();
    let mut summary = Summary {
        status: "summary",
        processed: 0,
        resumed: 0,
        failed: 0,
        skipped: 0,
    };
    files::discover(
        &batch.input_root,
        Path::new(""),
        &mut paths,
        &mut summary.skipped,
    )?;
    paths.sort_unstable();
    let mut stdout = std::io::stdout();
    for relative in &paths {
        let started = Instant::now();
        match batch.process_photo(relative).await {
            Ok((receipt, resumed)) => {
                let status = if resumed {
                    summary.resumed += 1;
                    "resumed"
                } else {
                    summary.processed += 1;
                    "processed"
                };
                if args.json {
                    // Flatten the durable per-image receipt into the live progress row.
                    #[derive(Serialize)]
                    struct Progress<'a> {
                        status: &'a str,
                        elapsed_ms: f64,
                        #[serde(flatten)]
                        receipt: &'a Receipt,
                    }
                    print_json(
                        &mut stdout,
                        &Progress {
                            status,
                            elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
                            receipt: &receipt,
                        },
                    )?;
                } else {
                    writeln!(stdout, "{status} {}", receipt.output)?;
                }
            }
            Err(error) => {
                summary.failed += 1;
                if args.json {
                    print_json(
                        &mut stdout,
                        &serde_json::json!({
                            "status": "failed", "input": relative.to_string_lossy(),
                            "input_path_hex": path_hex(relative), "error": format!("{error:#}")
                        }),
                    )?;
                } else {
                    eprintln!("{}: {error:#}", relative.display());
                }
            }
        }
    }
    if args.json {
        print_json(&mut stdout, &summary)?;
    } else {
        writeln!(
            stdout,
            "{} processed, {} resumed, {} failed, {} sidecars skipped",
            summary.processed, summary.resumed, summary.failed, summary.skipped
        )?;
    }
    ensure!(!paths.is_empty(), "no supported RAW photos found");
    ensure!(summary.failed == 0, "{} photo(s) failed", summary.failed);
    Ok(())
}

fn print_json(mut out: impl Write, data: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut out, data)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn path_hex(path: &Path) -> Option<String> {
    path.to_str()
        .is_none()
        .then(|| hex::encode(path.as_os_str().as_encoded_bytes()))
}

fn count_workers(tile_workers: &[String]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for peer in tile_workers {
        *counts.entry(peer.clone()).or_insert(0) += 1;
    }
    counts
}

impl Batch {
    async fn process_photo(&self, relative: &Path) -> Result<(Receipt, bool)> {
        let parent = relative.parent().context("missing input parent")?;
        let leaf = relative.file_name().context("missing input filename")?;
        let source_dir = files::directory(&self.input_root, parent, false)?;
        let mut source = files::regular_file(&source_dir, leaf)?;
        let dest_dir = files::directory(&self.output_root, parent, true)?;
        let mut dest_name = OsString::from(leaf);
        dest_name.push(".dehazed.png");
        let dest_rel = parent.join(&dest_name);
        let receipt_name = format!(
            "{}.json",
            blake3::hash(relative.as_os_str().as_encoded_bytes())
        );
        let receipt_name = OsStr::new(&receipt_name);
        let has_receipt = files::leaf_exists(&self.state, receipt_name)?;
        let has_output = files::leaf_exists(&dest_dir, &dest_name)?;
        let mut previous_input = None;

        if has_output || has_receipt {
            ensure!(
                self.resume,
                "output or receipt already exists at {}; use --resume to verify it",
                dest_rel.display()
            );
            ensure!(
                has_receipt,
                "existing output has no batch receipt: {}",
                dest_rel.display()
            );
            let receipt_file = files::regular_file(&self.state, receipt_name)?;
            let receipt: Receipt = serde_json::from_slice(
                &entangle_signing::package_io::read_bounded(receipt_file, 1024 * 1024)?,
            )
            .context("reading batch receipt")?;
            let digest = files::digest(&mut source, MAX_INPUT_BYTES)?;
            source.rewind()?;
            ensure!(
                receipt.version == RECEIPT_VERSION
                    && receipt.plugin == self.plugin
                    && receipt.tile_edge == self.tile_edge
                    && receipt.input == relative.to_string_lossy()
                    && receipt.input_path_hex == path_hex(relative)
                    && receipt.output == dest_rel.to_string_lossy()
                    && receipt.output_path_hex == path_hex(&dest_rel)
                    && receipt.input_blake3 == digest.to_hex().as_str(),
                "batch receipt does not match the current input or settings at {}",
                dest_rel.display()
            );
            self.validate_saved_tiles(&receipt)?;
            if has_output {
                ensure!(
                    receipt
                        .workers
                        .keys()
                        .all(|peer| self.allow.binary_search(peer).is_ok()),
                    "batch receipt names a worker outside the current allowlist"
                );
                let mut output = files::regular_file(&dest_dir, &dest_name)?;
                ensure!(
                    receipt.output_blake3
                        == files::digest(&mut output, OUTPUT_LIMIT)?.to_hex().as_str(),
                    "existing output has changed: {}",
                    dest_rel.display()
                );
                return Ok((receipt, true));
            }
            previous_input = Some(digest);
        }

        let source_path = relative.to_owned();
        let (raster, input_hash) = tokio::task::spawn_blocking(move || {
            let decoded = image_raw::decode_raw_file(&mut source, &source_path)?;
            Ok::<_, anyhow::Error>((Raster::open_ppm(decoded.path())?, decoded.input_hash()))
        })
        .await
        .context("joining the RAW decoder")??;
        ensure!(
            previous_input.is_none_or(|digest| digest == input_hash),
            "input changed after resuming an incomplete image"
        );
        let (width, height) = (raster.width(), raster.height());
        let (image, tile_workers) = self.render(raster).await?;

        let mut output = StagedFile::create(&dest_dir)?;
        image
            .write_png(&mut output.file)
            .context("encoding the complete image")?;
        output.file.rewind()?;
        let output_hash = files::digest(&mut output.file, OUTPUT_LIMIT)?;
        let receipt = Receipt {
            version: RECEIPT_VERSION,
            plugin: self.plugin.clone(),
            tile_edge: self.tile_edge,
            input: relative.to_string_lossy().into_owned(),
            output: dest_rel.to_string_lossy().into_owned(),
            input_path_hex: path_hex(relative),
            output_path_hex: path_hex(&dest_rel),
            input_blake3: input_hash.to_hex().to_string(),
            output_blake3: output_hash.to_hex().to_string(),
            width,
            height,
            workers: count_workers(&tile_workers),
            tile_workers,
        };

        // The receipt lands first. If the process stops before the no-clobber
        // publication, --resume can distinguish unfinished work from an output
        // without a receipt and rerun only the unfinished photo.
        let mut saved = StagedFile::create(&self.state)?;
        serde_json::to_writer(&mut saved.file, &receipt)?;
        saved
            .publish(receipt_name, has_receipt)
            .context("publishing the batch receipt")?;
        output
            .publish(&dest_name, false)
            .with_context(|| format!("publishing {} without overwriting", dest_rel.display()))?;
        Ok((receipt, false))
    }

    fn validate_saved_tiles(&self, receipt: &Receipt) -> Result<()> {
        ensure!(
            (1..=MAX_DIMENSION).contains(&receipt.width)
                && (1..=MAX_DIMENSION).contains(&receipt.height)
                && receipt.width as usize * receipt.height as usize <= MAX_PIXELS,
            "invalid raster dimensions in the batch receipt"
        );
        let tile_count =
            receipt.width.div_ceil(self.tile_edge) * receipt.height.div_ceil(self.tile_edge);
        ensure!(
            receipt.tile_workers.len() == tile_count as usize
                && receipt.workers == count_workers(&receipt.tile_workers),
            "invalid tile attribution in the batch receipt"
        );
        Ok(())
    }

    async fn render(&self, raster: Raster) -> Result<(RasterOutput, Vec<String>)> {
        let atmosphere = raster.atmosphere();
        let plan = raster.tiles(self.tile_edge)?;
        let mut output = RasterOutput::new(&raster)?;
        let mut workers = vec![String::new(); plan.len()];
        let mut active = JoinSet::new();
        // UDS JSON can allocate substantially more than the raw payload size.
        // Budget the uncompressed RGB16 tile, including halo and codec overhead.
        let padded_edge = self.tile_edge as usize + 16;
        let tile_bytes = 6 * padded_edge * padded_edge + 256 * 1024;
        let concurrent = self.jobs.min((TILE_BATCH_BYTES / tile_bytes).max(1));
        for tile in plan {
            let input = raster.encode_tile(&tile, atmosphere)?;
            ensure!(
                input.len() as u64 <= OneShotTask::DEFAULT_MAX_INPUT_BYTES,
                "tile exceeds the scheduler input limit"
            );
            let client = self.client.clone();
            let timeout_ms = self.timeout_ms;
            let params = ComputeDispatchParams {
                plugin_id: self.plugin.clone(),
                input,
                timeout_ms,
                // Use the scheduler's ordinary resource and in-flight placement.
                cpu_cores: 0.0,
                memory_bytes: 256 * 1024 * 1024,
                gpu_required: false,
                gpu_vram_min_bytes: 0,
                integrity: ComputeIntegrity::TrustedExecutor {
                    allowlist: self.allow.clone(),
                },
            };
            active.spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_millis(timeout_ms + 15_000),
                    client.compute_dispatch(&params),
                )
                .await
                .with_context(|| format!("tile {} scheduler deadline expired", tile.ordinal))?
                .with_context(|| {
                    format!(
                        "dispatching tile {} at ({}, {})",
                        tile.ordinal, tile.x, tile.y
                    )
                })?;
                Ok((tile, result))
            });

            if active.len() >= concurrent {
                self.receive_tile(&mut active, &mut output, &mut workers)
                    .await?;
            }
        }
        while !active.is_empty() {
            self.receive_tile(&mut active, &mut output, &mut workers)
                .await?;
        }
        Ok((output, workers))
    }

    async fn receive_tile(
        &self,
        active: &mut JoinSet<TileResult>,
        output: &mut RasterOutput,
        workers: &mut [String],
    ) -> Result<()> {
        let Some(result) = active.join_next().await else {
            bail!("no tile result to collect");
        };
        let (tile, result) = result.context("joining a tile dispatch")??;
        let peer = PeerId::from_hex(&result.chosen_peer)
            .context("scheduler returned an invalid worker ID")?
            .to_hex();
        ensure!(
            self.allow.binary_search(&peer).is_ok(),
            "tile {} was returned by a worker outside the allowlist ({peer})",
            tile.ordinal
        );
        ensure!(
            result.output.len() as u64 <= OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
            "tile {} exceeds the scheduler output limit",
            tile.ordinal
        );
        output
            .place(&tile, &result.output)
            .with_context(|| format!("validating tile {} from {peer}", tile.ordinal))?;
        workers[tile.ordinal] = peer;
        Ok(())
    }
}
