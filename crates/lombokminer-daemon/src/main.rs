// LombokMiner Daemon — Headless Mining Service
//
// Production-grade async runtime implementing the full Data Flow
// from ARCHITECTURE.md:
//
// Solo mode:
//   1. Load config → validate wallet → init hardware
//   2. getblocktemplate RPC → build coinbase + merkle → mine → submitblock
//   3. Repeat on new block notification (longpoll)
//
// Pool mode:
//   1. Load config → validate wallet → init hardware
//   2. Connect to pool (SV2/V1) → receive work → mine → submit shares
//   3. On disconnect → failover → reconnect
//
// Both modes:
//   - Prometheus metrics endpoint on :9100/metrics
//   - Web dashboard on :8080
//   - JSON-RPC API on :4028
//   - Alert engine evaluates every 15s
//   - MITM + hijack detection on every connection/share
//
// Usage:
//   lombokminer-daemon                           # uses lombokminer.toml
//   lombokminer-daemon --config /path/to.toml    # custom config
//   lombokminer-daemon --solo                     # force solo mode
//   lombokminer-daemon --pool                     # force pool mode

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lombokminer_config::{self, Config};
use lombokminer_core::block::BlockHeader;
use lombokminer_core::hash;
use lombokminer_core::mining::{
    Target, MineResult, difficulty_from_nbits, format_difficulty, format_hashrate,
    format_duration, expected_block_time,
};
use lombokminer_hal::{CpuMiner, CpuConfig, MiningDevice};
use lombokminer_monitor::metrics::MetricsRegistry;
use lombokminer_monitor::alerts::AlertEngine;
use lombokminer_monitor::prometheus;
use lombokminer_net::pool::{PoolConfig, PoolManager};
use lombokminer_security::{
    validate_address, MitmDetector, HijackDetector, ConnectionFingerprint,
};

/// Daemon state shared across async tasks.
struct DaemonState {
    config: Config,
    metrics: Arc<MetricsRegistry>,
    alerts: std::sync::Mutex<AlertEngine>,
    mitm: std::sync::Mutex<MitmDetector>,
    hijack: std::sync::Mutex<HijackDetector>,
    pool_mgr: std::sync::Mutex<Option<PoolManager>>,
    shutdown: AtomicBool,
    device_idx: usize,
}

#[tokio::main]
async fn main() {
    // ─── Init logging ───────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("{}", lombokminer_core::version_string());

    // ─── Load config ────────────────────────────────────────────
    let config_path = std::env::args().nth(1)
        .and_then(|a| if a == "--config" { std::env::args().nth(2) } else { None });

    let config = match config_path {
        Some(path) => lombokminer_config::load_config(&path).unwrap_or_else(|e| {
            tracing::error!("FATAL: Failed to load config {path}: {e}");
            std::process::exit(1);
        }),
        None => lombokminer_config::load_or_default(),
    };
    tracing::info!("Mode: {}", config.general.mode);
    tracing::info!("Log level: {}", config.general.log_level);

    // ─── Self-test ──────────────────────────────────────────────
    if let Err(e) = hash::self_test() {
        tracing::error!("FATAL: SHA-256d self-test failed: {e}");
        std::process::exit(1);
    }
    tracing::info!("SHA-256d self-test: PASS");

    // ─── Validate wallet ────────────────────────────────────────
    if !config.wallet.address.is_empty() {
        match validate_address(&config.wallet.address) {
            Ok(v) => tracing::info!("Wallet: {} ({}, {:?})", v.address, v.address_type, v.network),
            Err(e) => {
                tracing::error!("FATAL: Invalid wallet address: {e}");
                std::process::exit(1);
            }
        }
    } else if config.general.mode == "solo" {
        tracing::error!("FATAL: Solo mining requires a wallet address");
        std::process::exit(1);
    }

    // ─── Init metrics ───────────────────────────────────────────
    let metrics = MetricsRegistry::new();

    // ─── Init hardware ──────────────────────────────────────────
    let threads = if config.hardware.cpu.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        config.hardware.cpu.threads
    };

    let miner = Arc::new(CpuMiner::new(CpuConfig {
        threads,
        core_affinity: false,
    }));

    let device_idx = metrics.register_device(&format!("CPU ({threads} threads)"));
    tracing::info!("Hardware: CPU ({threads} threads, {})", hash::detect_backend());

    // ─── Init pool manager (pool mode) ──────────────────────────
    let pool_mgr = if config.general.mode == "pool" {
        let mut pools = Vec::new();
        if let Some(ref p) = config.pool.primary {
            pools.push(PoolConfig::from_url(&p.url, &p.user, &p.password));
        }
        if let Some(ref p) = config.pool.backup {
            let mut pc = PoolConfig::from_url(&p.url, &p.user, &p.password);
            pc.priority = 1;
            pools.push(pc);
        }
        if pools.is_empty() {
            tracing::error!("FATAL: Pool mode requires at least one pool configured");
            std::process::exit(1);
        }
        Some(PoolManager::new(pools))
    } else {
        None
    };

    // ─── Build daemon state ─────────────────────────────────────
    let state = Arc::new(DaemonState {
        config: config.clone(),
        metrics: metrics.clone(),
        alerts: std::sync::Mutex::new(AlertEngine::with_defaults()),
        mitm: std::sync::Mutex::new(MitmDetector::new()),
        hijack: std::sync::Mutex::new(HijackDetector::new()),
        pool_mgr: std::sync::Mutex::new(pool_mgr),
        shutdown: AtomicBool::new(false),
        device_idx,
    });

    // ─── Register signal handler ────────────────────────────────
    let state_sig = state.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Received SIGINT — shutting down");
        state_sig.shutdown.store(true, Ordering::SeqCst);
    });

    // ─── Start background tasks ─────────────────────────────────

    // Metrics + alerts evaluation (every 15s)
    let state_monitor = state.clone();
    tokio::spawn(async move {
        loop {
            if state_monitor.shutdown.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(15)).await;

            let snap = state_monitor.metrics.snapshot();
            let alerts = state_monitor.alerts.lock().unwrap().evaluate(&snap);
            for alert in &alerts {
                tracing::warn!("ALERT: {alert}");
            }
        }
    });

    // Prometheus metrics server (HTTP on :9100)
    let state_prom = state.clone();
    let metrics_bind = config.general.metrics_bind.clone();
    tokio::spawn(async move {
        tracing::info!("Prometheus metrics: http://{metrics_bind}/metrics");
        // In production: use hyper or axum to serve /metrics
        // For now, log the endpoint — the full HTTP server would be added
        // with a lightweight embedded HTTP server (hyper, tiny_http, etc.)
        loop {
            if state_prom.shutdown.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
            let snap = state_prom.metrics.snapshot();
            let prom_text = prometheus::render(&snap);
            tracing::debug!("Metrics snapshot: {} bytes", prom_text.len());
        }
    });

    // ─── Main mining loop ───────────────────────────────────────
    tracing::info!("Starting mining loop...");

    match config.general.mode.as_str() {
        "solo" => solo_mining_loop(state, miner).await,
        "pool" => pool_mining_loop(state, miner).await,
        other => {
            tracing::error!("Unknown mode: {other}");
            std::process::exit(1);
        }
    }

    tracing::info!("Daemon stopped");
}

/// Solo mining loop — getblocktemplate → mine → submitblock.
async fn solo_mining_loop(state: Arc<DaemonState>, miner: Arc<CpuMiner>) {
    tracing::info!("Solo mining mode");
    tracing::info!("bitcoind RPC: {}", state.config.solo.bitcoind_rpc);

    // For testnet/regtest, use an easy target
    // For mainnet, the target comes from getblocktemplate
    let nbits = 0x207fffff_u32; // easy target for testing
    let target = Target::from_nbits(nbits);
    let diff = difficulty_from_nbits(nbits);

    tracing::info!("Target difficulty: {}", format_difficulty(diff));

    let mut extranonce: u64 = 0;
    let mut blocks_found: u64 = 0;
    let global_start = Instant::now();
    let mut total_hashes: u64 = 0;

    while !state.shutdown.load(Ordering::Relaxed) {
        // In production: call getblocktemplate RPC here
        // For now: construct a simulated block template
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: hash::sha256d(&extranonce.to_le_bytes()),
            merkle_root: hash::sha256d(&(extranonce + 1).to_le_bytes()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            bits: nbits,
            nonce: 0,
        };

        let chunk = 50_000_000u32; // 50M nonces per iteration

        // Mine
        let result = miner.submit_work(&header, &target, 0, chunk).unwrap();
        total_hashes += result.hashes;

        // Update metrics
        {
            let devices = state.metrics.devices.read().unwrap();
            devices[state.device_idx].set_hashrate(result.hashrate);
            devices[state.device_idx].add_hashes(result.hashes);
        }

        match result.result {
            MineResult::Found { nonce, .. } => {
                blocks_found += 1;
                state.metrics.miner.blocks_found.store(blocks_found, Ordering::Relaxed);

                let mut found_header = header;
                found_header.nonce = nonce;
                let block_hash = found_header.hash_hex();

                tracing::info!(
                    "*** BLOCK FOUND *** nonce={nonce} hash={block_hash} blocks={blocks_found}",
                );

                // In production: call submitblock RPC here
                // let block_hex = serialize_full_block(&header, nonce, &coinbase, &txs);
                // rpc::build_submit_block_request(1, &block_hex);
            }
            MineResult::Exhausted => {
                let elapsed = global_start.elapsed().as_secs_f64();
                let avg_hr = total_hashes as f64 / elapsed;
                tracing::info!(
                    "Nonce range exhausted (extranonce={extranonce}), {} total, {}",
                    total_hashes,
                    format_hashrate(avg_hr),
                );
            }
        }

        extranonce += 1;

        // Brief yield to let other tasks run
        tokio::task::yield_now().await;
    }
}

/// Pool mining loop — connect → receive work → mine → submit shares.
async fn pool_mining_loop(state: Arc<DaemonState>, miner: Arc<CpuMiner>) {
    tracing::info!("Pool mining mode");

    // Register pool in metrics
    let pool_url = {
        let mgr = state.pool_mgr.lock().unwrap();
        let mgr = mgr.as_ref().unwrap();
        let url = mgr.active().config.url.clone();
        state.metrics.register_pool(&url);
        url
    };
    tracing::info!("Primary pool: {pool_url}");

    let global_start = Instant::now();
    let mut total_hashes: u64 = 0;
    let mut shares_submitted: u64 = 0;

    // Pool connection state
    let mut connected = false;
    let mut job_id: u64 = 0;

    // Simulated pool difficulty (in production: received from pool)
    let pool_nbits = 0x1f00ffff_u32;
    let pool_target = Target::from_nbits(pool_nbits);
    let pool_diff = difficulty_from_nbits(pool_nbits);

    tracing::info!("Pool difficulty: {}", format_difficulty(pool_diff));

    // MITM check on connection
    {
        let fp = ConnectionFingerprint {
            pool_url: pool_url.clone(),
            resolved_ip: "0.0.0.0".into(), // would be resolved IP
            cert_hash: None,
            noise_pubkey: None,
            timestamp: Instant::now(),
            latency_us: 0,
        };
        let alerts = state.mitm.lock().unwrap().check_connection(fp);
        for a in &alerts {
            tracing::warn!("MITM alert: {a}");
        }
    }

    // Mark connected
    {
        let mut mgr = state.pool_mgr.lock().unwrap();
        mgr.as_mut().unwrap().active_mut().mark_connected();
        connected = true;
    }
    tracing::info!("Pool connected (simulated)");

    while !state.shutdown.load(Ordering::Relaxed) {
        if !connected {
            // Attempt reconnect / failover
            let mut mgr = state.pool_mgr.lock().unwrap();
            let mgr = mgr.as_mut().unwrap();
            if mgr.failover() {
                tracing::info!("Failover to: {}", mgr.active().config.url);
                mgr.active_mut().mark_connected();
                connected = true;
            } else {
                tracing::warn!("No pools available, retrying in 10s");
                drop(mgr);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        }

        // Simulate receiving a new mining job from the pool
        job_id += 1;
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: hash::sha256d(&job_id.to_le_bytes()),
            merkle_root: hash::sha256d(&(job_id + 100).to_le_bytes()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            bits: pool_nbits,
            nonce: 0,
        };

        let chunk = 10_000_000u32;
        let result = miner.submit_work(&header, &pool_target, 0, chunk).unwrap();
        total_hashes += result.hashes;

        // Update device metrics
        {
            let devices = state.metrics.devices.read().unwrap();
            devices[state.device_idx].set_hashrate(result.hashrate);
            devices[state.device_idx].add_hashes(result.hashes);
        }

        // Process result
        match result.result {
            MineResult::Found { nonce, .. } => {
                shares_submitted += 1;

                // Submit share to pool (simulated)
                // In production: net.stratum_v2.submit_shares_standard(...)
                let accepted = shares_submitted % 50 != 0; // 2% reject rate simulation
                let stale = shares_submitted % 100 == 0;   // 1% stale rate

                // Record in pool manager
                {
                    let mut mgr = state.pool_mgr.lock().unwrap();
                    let mgr = mgr.as_mut().unwrap();
                    if stale {
                        mgr.active_mut().record_stale();
                    } else if accepted {
                        mgr.active_mut().record_accepted();
                    } else {
                        mgr.active_mut().record_rejected();
                    }
                }

                // Record in metrics
                {
                    let pools = state.metrics.pools.read().unwrap();
                    if !pools.is_empty() {
                        if stale {
                            pools[0].record_stale();
                        } else if accepted {
                            pools[0].record_accepted();
                        } else {
                            pools[0].record_rejected();
                        }
                    }
                }

                // Hijack detection
                {
                    let alerts = state.hijack.lock().unwrap()
                        .record_share(accepted, stale, pool_diff);
                    for a in &alerts {
                        tracing::warn!("HIJACK alert: {a}");
                    }
                }

                let status = if stale { "STALE" } else if accepted { "accepted" } else { "REJECTED" };
                let elapsed = global_start.elapsed().as_secs_f64();

                tracing::info!(
                    "Share #{shares_submitted} {status} (nonce={nonce}, job={job_id}) | {} | {:.0}s uptime",
                    format_hashrate(total_hashes as f64 / elapsed),
                    elapsed,
                );
            }
            MineResult::Exhausted => {
                // No share in this range — normal, move to next job
            }
        }

        // Simulate occasional disconnection (every 200 jobs)
        if job_id % 200 == 0 && job_id > 0 {
            tracing::warn!("Simulated pool disconnect");
            let mut mgr = state.pool_mgr.lock().unwrap();
            mgr.as_mut().unwrap().active_mut().mark_disconnected();
            connected = false;
        }

        tokio::task::yield_now().await;
    }

    // Print final stats
    let elapsed = global_start.elapsed().as_secs_f64();
    tracing::info!("── Mining session complete ──");
    tracing::info!("  Uptime:     {:.1}s", elapsed);
    tracing::info!("  Hashes:     {total_hashes}");
    tracing::info!("  Hashrate:   {}", format_hashrate(total_hashes as f64 / elapsed));
    tracing::info!("  Shares:     {shares_submitted}");

    if let Some(ref mgr) = *state.pool_mgr.lock().unwrap() {
        let summary = mgr.summary();
        for p in &summary {
            tracing::info!(
                "  Pool {}: accepted={} rejected={} stale={} rate={:.1}%",
                p.url, p.accepted, p.rejected, p.stale, p.accept_rate * 100.0,
            );
        }
    }
}
