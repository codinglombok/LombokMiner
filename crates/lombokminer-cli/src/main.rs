// LombokMiner CLI — v1.0.0
//
// Full-featured command-line interface integrating all crates.
//
// Commands:
//   lombokminer selftest     — verify SHA-256d + crypto + wallet validation
//   lombokminer bench        — benchmark hashing (single + multi-thread)
//   lombokminer info         — system info, capabilities, devices
//   lombokminer mine         — start mining (CPU, configurable threads)
//   lombokminer init         — generate default config file
//   lombokminer validate     — validate a Bitcoin address
//   lombokminer config       — show loaded configuration

use clap::{Parser, Subcommand};
use lombokminer_core::block::BlockHeader;
use lombokminer_core::hash;
use lombokminer_core::mining::{
    MineResult, Target, format_hashrate, format_difficulty,
    difficulty_from_nbits, expected_block_time, format_duration,
};
use lombokminer_hal::{CpuMiner, CpuConfig, MiningDevice};

#[derive(Parser)]
#[command(
    name = "lombokminer",
    about = "LombokMiner — High-performance Bitcoin mining software",
    version = lombokminer_core::VERSION,
)]
struct Cli {
    /// Config file path
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run self-test (SHA-256d, crypto, wallet validation)
    Selftest,
    /// Benchmark hashing performance
    Bench {
        #[arg(short, long, default_value_t = 10)]
        millions: u32,
        #[arg(short, long, default_value_t = 0)]
        threads: usize,
    },
    /// Show system information and detected capabilities
    Info,
    /// Start mining
    Mine {
        #[arg(short, long, default_value = "207fffff")]
        bits: String,
        #[arg(short, long, default_value_t = 0)]
        threads: usize,
    },
    /// Generate default configuration file
    Init,
    /// Validate a Bitcoin address
    Validate {
        /// Bitcoin address to validate
        address: String,
    },
    /// Show loaded configuration
    Config,
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match cli.command {
        Commands::Selftest => cmd_selftest(),
        Commands::Bench { millions, threads } => cmd_bench(millions, threads),
        Commands::Info => cmd_info(),
        Commands::Mine { bits, threads } => cmd_mine(&bits, threads),
        Commands::Init => cmd_init(),
        Commands::Validate { address } => cmd_validate(&address),
        Commands::Config => cmd_config(cli.config),
    }
}

fn cmd_selftest() {
    println!("{}", lombokminer_core::version_string());
    println!("Self-Test Suite");
    println!("===============\n");

    let mut pass = 0u32;
    let mut fail = 0u32;

    // 1. SHA-256d
    print!("  [1] SHA-256d empty              ");
    let h = hash::sha256d(b"");
    if hex::encode(h) == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" {
        println!("PASS"); pass += 1;
    } else { println!("FAIL"); fail += 1; }

    // 2. Genesis block
    print!("  [2] Genesis block hash          ");
    match hash::self_test() {
        Ok(()) => { println!("PASS"); pass += 1; }
        Err(e) => { println!("FAIL — {e}"); fail += 1; }
    }

    // 3. Midstate
    print!("  [3] Midstate optimization       ");
    let mut hdr = [0u8; 80];
    for (i, b) in hdr.iter_mut().enumerate() { *b = (i * 7 + 13) as u8; }
    let full = hash::sha256d(&hdr);
    let first: [u8; 64] = hdr[..64].try_into().unwrap();
    let last: [u8; 16] = hdr[64..].try_into().unwrap();
    let optimized = hash::sha256_from_midstate(&hash::sha256_midstate(&first), &last);
    if full == optimized { println!("PASS"); pass += 1; }
    else { println!("FAIL"); fail += 1; }

    // 4. Merkle tree
    print!("  [4] Merkle tree (5 tx)          ");
    let txs: Vec<[u8; 32]> = (0..5).map(|i| hash::sha256d(format!("tx{i}").as_bytes())).collect();
    let root = lombokminer_core::block::merkle_root(&txs);
    let branch = lombokminer_core::block::MerkleBranch::from_tx_hashes(&txs);
    if root == branch.compute_root(&txs[0]) { println!("PASS"); pass += 1; }
    else { println!("FAIL"); fail += 1; }

    // 5. Difficulty
    print!("  [5] Difficulty (genesis=1.0)    ");
    if (difficulty_from_nbits(0x1d00ffff) - 1.0).abs() < 0.001 { println!("PASS"); pass += 1; }
    else { println!("FAIL"); fail += 1; }

    // 6. ChaCha20-Poly1305 AEAD
    print!("  [6] ChaCha20-Poly1305 AEAD     ");
    let key = [0x42u8; 32]; let nonce = [0x01u8; 12];
    let (ct, tag) = lombokminer_security::aead_encrypt(&key, &nonce, b"aad", b"secret");
    match lombokminer_security::aead_decrypt(&key, &nonce, b"aad", &ct, &tag) {
        Ok(pt) if pt == b"secret" => { println!("PASS"); pass += 1; }
        _ => { println!("FAIL"); fail += 1; }
    }

    // 7. AEAD tamper detection
    print!("  [7] AEAD tamper detection       ");
    let mut ct2 = ct.clone(); ct2[0] ^= 0xFF;
    if lombokminer_security::aead_decrypt(&key, &nonce, b"aad", &ct2, &tag).is_err() {
        println!("PASS"); pass += 1;
    } else { println!("FAIL"); fail += 1; }

    // 8. Wallet validation (Bech32 P2WPKH)
    print!("  [8] Bech32 address validation   ");
    match lombokminer_security::validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") {
        Ok(v) if v.address_type == lombokminer_security::AddressType::P2wpkh => {
            println!("PASS"); pass += 1;
        }
        _ => { println!("FAIL"); fail += 1; }
    }

    // 9. Config vault
    print!("  [9] Config vault seal/unseal    ");
    let vault = lombokminer_security::ConfigVault::seal("pass123", "wallet=bc1q...");
    match vault.unseal("pass123") {
        Ok(s) if s == "wallet=bc1q..." => { println!("PASS"); pass += 1; }
        _ => { println!("FAIL"); fail += 1; }
    }

    // 10. Config vault wrong passphrase
    print!("  [10] Vault wrong passphrase     ");
    if vault.unseal("wrong").is_err() { println!("PASS"); pass += 1; }
    else { println!("FAIL"); fail += 1; }

    // 11. CPU multi-thread mining
    print!("  [11] CPU multi-thread mining    ");
    let miner = CpuMiner::new(CpuConfig { threads: 2, core_affinity: false });
    let target = Target::from_nbits(0x207fffff);
    let header = BlockHeader { version: 0x20000000, prev_block: [0xAB; 32], merkle_root: [0xCD; 32],
        timestamp: 1700000000, bits: 0x207fffff, nonce: 0 };
    match miner.submit_work(&header, &target, 0, 100_000) {
        Ok(r) => match r.result {
            MineResult::Found { hash, .. } if target.check_hash(&hash) => { println!("PASS"); pass += 1; }
            _ => { println!("FAIL"); fail += 1; }
        }
        Err(_) => { println!("FAIL"); fail += 1; }
    }

    // 12. Config TOML parsing
    print!("  [12] Config TOML parsing        ");
    match lombokminer_config::parse_config("[general]\nmode = \"solo\"\n") {
        Ok(c) if c.general.mode == "solo" => { println!("PASS"); pass += 1; }
        _ => { println!("FAIL"); fail += 1; }
    }

    println!("\n  Result: {pass}/{} passed", pass + fail);
    if fail > 0 { std::process::exit(1); }
    println!("  All tests passed.");
}

fn cmd_bench(millions: u32, threads: usize) {
    let total = millions as u64 * 1_000_000;
    let threads = if threads == 0 { num_cpus() } else { threads };

    println!("LombokMiner Benchmark");
    println!("=====================\n");
    println!("  Backend:  {}", hash::detect_backend());
    println!("  Threads:  {threads}");
    println!("  Hashes:   {total} ({millions}M)\n");

    let target = Target::from_nbits(0x01003456);
    let header = BlockHeader { version: 0x20000000, prev_block: [0xAB; 32], merkle_root: [0xCD; 32],
        timestamp: 1700000000, bits: 0x01003456, nonce: 0 };

    let miner = CpuMiner::new(CpuConfig { threads, core_affinity: false });

    print!("  Mining {millions}M nonces ({threads} threads) ... ");
    let start = std::time::Instant::now();
    let _ = miner.submit_work(&header, &target, 0, total as u32);
    let elapsed = start.elapsed();
    println!("done");

    let hashrate = total as f64 / elapsed.as_secs_f64();
    println!("\n  Hashrate: {}", format_hashrate(hashrate));
    println!("  Time:     {:.2}s", elapsed.as_secs_f64());
    println!("  Per hash: {:.1}ns", elapsed.as_nanos() as f64 / total as f64);
}

fn cmd_info() {
    println!("{}", lombokminer_core::version_string());
    println!("==========================\n");
    println!("  Hash backend:   {}", hash::detect_backend());
    println!("  CPU cores:      {}", num_cpus());
    println!("  Architecture:   {}", std::env::consts::ARCH);
    println!("  OS:             {}", std::env::consts::OS);

    #[cfg(target_arch = "x86_64")]
    {
        println!("\n  x86_64 features:");
        for (feat, name) in [("sha", "SHA-NI"), ("avx2", "AVX2"), ("sse4.1", "SSE4.1"), ("aes", "AES-NI")] {
            let ok = match feat {
                "sha" => is_x86_feature_detected!("sha"),
                "avx2" => is_x86_feature_detected!("avx2"),
                "sse4.1" => is_x86_feature_detected!("sse4.1"),
                "aes" => is_x86_feature_detected!("aes"),
                _ => false,
            };
            println!("    {name:8} {}", if ok { "yes" } else { "no" });
        }
    }

    // Devices
    println!("\n  Devices:");
    for d in lombokminer_hal::enumerate_devices() {
        println!("    [{}] {}", d.device_type, d.name);
    }

    // Quick bench
    let miner = CpuMiner::new(CpuConfig::default());
    let target = Target::from_nbits(0x01003456);
    let header = BlockHeader::default();
    let start = std::time::Instant::now();
    let _ = miner.submit_work(&header, &target, 0, 1_000_000);
    let hashrate = 1_000_000.0 / start.elapsed().as_secs_f64();
    println!("\n  Quick benchmark: {}", format_hashrate(hashrate));

    let mainnet_bits = 0x17034219u32;
    println!("\n  Solo mining estimate (mainnet):");
    println!("    Difficulty: {}", format_difficulty(difficulty_from_nbits(mainnet_bits)));
    println!("    ETA: {}", format_duration(expected_block_time(mainnet_bits, hashrate)));
}

fn cmd_mine(bits_hex: &str, threads: usize) {
    let bits = u32::from_str_radix(bits_hex, 16).expect("Invalid bits hex value");
    let target = Target::from_nbits(bits);
    let threads = if threads == 0 { num_cpus() } else { threads };

    println!("LombokMiner — Mining");
    println!("====================\n");
    println!("  Target:    0x{bits_hex}");
    println!("  Difficulty: {}", format_difficulty(difficulty_from_nbits(bits)));
    println!("  Threads:   {threads}");
    println!("  Backend:   {}\n", hash::detect_backend());

    let miner = CpuMiner::new(CpuConfig { threads, core_affinity: false });
    let header = BlockHeader {
        version: 0x20000000, prev_block: [0xAA; 32], merkle_root: [0xBB; 32],
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
        bits, nonce: 0,
    };

    let chunk = 10_000_000u32;
    let mut total: u64 = 0;
    let start = std::time::Instant::now();

    for cs in (0u32..u32::MAX).step_by(chunk as usize) {
        let ce = cs.saturating_add(chunk);
        let result = miner.submit_work(&header, &target, cs, ce).expect("mining failed");
        total += result.hashes;
        let elapsed = start.elapsed().as_secs_f64();
        let hr = total as f64 / elapsed;

        match result.result {
            MineResult::Found { nonce, hash } => {
                let mut hd = hash; hd.reverse();
                println!("\n  *** BLOCK FOUND ***");
                println!("  Nonce:    {nonce}");
                println!("  Hash:     {}", hex::encode(hd));
                println!("  Hashes:   {total}");
                println!("  Time:     {:.2}s", elapsed);
                println!("  Hashrate: {}", format_hashrate(hr));
                return;
            }
            MineResult::Exhausted => {
                print!("\r  Scanning {cs}..{ce} | {} | {total} hashes", format_hashrate(hr));
            }
        }
    }
    println!("\n  Nonce space exhausted.");
}

fn cmd_init() {
    let path = "lombokminer.toml";
    if std::path::Path::new(path).exists() {
        println!("  {path} already exists. Remove it first to regenerate.");
        return;
    }
    std::fs::write(path, lombokminer_config::generate_default_toml()).expect("write config");
    println!("  Created {path}");
    println!("  Edit wallet address and pool settings, then run: lombokminer mine");
}

fn cmd_validate(address: &str) {
    match lombokminer_security::validate_address(address) {
        Ok(v) => {
            println!("  Address: {}", v.address);
            println!("  Type:    {}", v.address_type);
            println!("  Network: {:?}", v.network);
            println!("  Valid");
        }
        Err(e) => {
            println!("  Address: {address}");
            println!("  Error:   {e}");
            println!("  Invalid");
            std::process::exit(1);
        }
    }
}

fn cmd_config(path: Option<String>) {
    let cfg = match path {
        Some(p) => lombokminer_config::load_config(&p).unwrap_or_else(|e| {
            eprintln!("  Error loading {p}: {e}");
            std::process::exit(1);
        }),
        None => lombokminer_config::load_or_default(),
    };
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
