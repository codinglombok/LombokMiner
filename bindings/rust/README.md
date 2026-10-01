# lombokminer

Bitcoin mining library for Rust. SHA-256d hashing, Stratum V2, wallet validation, CPU mining.

## Usage

```toml
# Cargo.toml
[dependencies]
lombokminer = { git = "https://github.com/codinglombok/lombokminer", path = "bindings/rust" }
```

```rust
use lombokminer::prelude::*;

fn main() {
    // SHA-256d
    let hash = sha256d(b"hello");
    println!("SHA-256d: {}", hex::encode(hash));

    // Difficulty
    let diff = difficulty_from_nbits(0x1d00ffff);
    println!("Difficulty: {}", format_difficulty(diff));

    // Validate address
    let result = validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    println!("Address type: {}", result.address_type);

    // CPU mining
    let miner = CpuMiner::new(CpuConfig { threads: 4, core_affinity: false });
    let target = Target::from_nbits(0x207fffff);
    let header = BlockHeader::default();
    let result = miner.submit_work(&header, &target, 0, 1_000_000).unwrap();
    match result.result {
        MineResult::Found { nonce, .. } => println!("Found nonce: {nonce}"),
        MineResult::Exhausted => println!("Not found"),
    }
}
```

## Modules

| Module | Contents |
|---|---|
| `lombokminer::core` | SHA-256d, BlockHeader, merkle tree, coinbase, difficulty, mining |
| `lombokminer::net` | Stratum V2/V1, getblocktemplate RPC, pool manager |
| `lombokminer::hal` | MiningDevice trait, CpuMiner, GPU/ASIC abstractions |
| `lombokminer::security` | ChaCha20-Poly1305, wallet validation, MITM/hijack detection |
| `lombokminer::monitor` | Metrics registry, Prometheus export, alert engine |
| `lombokminer::config` | TOML config parsing and validation |
| `lombokminer::prelude` | Most commonly used items — `use lombokminer::prelude::*` |

## License

Apache-2.0
