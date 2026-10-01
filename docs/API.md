# LombokMiner API Reference

## C FFI (lombokminer.h)

The shared library exposes a C-compatible API usable from any language.

### Build

```bash
cargo build --release -p lombokminer-ffi
# Output: target/release/liblombokminer.so (Linux)
#         target/release/liblombokminer.dylib (macOS)
#         target/release/lombokminer.dll (Windows)
```

### Link

```bash
gcc -o miner main.c -L./target/release -llombokminer -lpthread -ldl -lm
```

### Functions

| Function | Signature | Description |
|---|---|---|
| `lombokminer_version` | `() → *char` | Library version string |
| `lombokminer_sha256d` | `(*u8, len, *u8) → i32` | SHA-256d hash |
| `lombokminer_sha256_midstate` | `(*u8[64], *u32[8]) → i32` | Midstate of first 64 bytes |
| `lombokminer_sha256d_from_midstate` | `(*u32[8], *u8[16], *u8[32]) → i32` | Hash from midstate |
| `lombokminer_block_hash` | `(*u8[80], *u8[32]) → i32` | Block header hash |
| `lombokminer_difficulty` | `(u32) → f64` | Difficulty from nBits |
| `lombokminer_check_target` | `(*u8[32], u32) → i32` | Hash meets target? |
| `lombokminer_mine_cpu` | `(*u8[80], u32, u32, u32, u32, *u8[32]) → i64` | CPU mining |
| `lombokminer_validate_address` | `(*char) → i32` | Validate Bitcoin address |
| `lombokminer_selftest` | `() → i32` | SHA-256d verification |

All functions return 0 on success, negative on error. Thread-safe.

## Python

```python
from lombokminer import LombokMiner

miner = LombokMiner()  # auto-detect library

# Hashing
hash_bytes = miner.sha256d(b"hello")
block_hash = miner.block_hash_hex(header_80_bytes)

# Difficulty
diff = miner.difficulty(0x17034219)  # → 86.39T

# Mining
nonce, hash = miner.mine_cpu(header_bytes, nbits=0x207fffff, threads=4)

# Wallet validation
valid, network = miner.validate_address("bc1q...")
```

Requires: Python 3.8+, liblombokminer in PATH or passed as argument.

## PHP

```php
$miner = new LombokMiner('/path/to/liblombokminer.so');

// Hashing
$hash = $miner->sha256dHex('hello');
$blockHash = $miner->blockHashHex($header80);

// Difficulty
$diff = $miner->difficulty(0x17034219);

// Mining
$result = $miner->mineCpu($header80, 0x207fffff, 0, 0xFFFFFFFF, 4);
// $result = ['nonce' => 12345, 'hash' => "\x00\x00..."]

// Wallet validation
$info = $miner->validateAddress('bc1q...');
// $info = ['valid' => true, 'network' => 'mainnet']
```

Requires: PHP 7.4+ with FFI extension, liblombokminer built.

## C/C++

```c
#include "lombokminer.h"

int main() {
    // Self-test
    if (lombokminer_selftest() != 0) return 1;

    // SHA-256d
    uint8_t hash[32];
    lombokminer_sha256d((uint8_t*)"hello", 5, hash);

    // Validate address
    int net = lombokminer_validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    // net == 0 → mainnet, valid

    // Mine
    uint8_t out_hash[32];
    int64_t nonce = lombokminer_mine_cpu(header, 0x207fffff, 0, 1000000, 4, out_hash);
    // nonce >= 0 → found

    return 0;
}
```

## Go

```bash
# Build the shared library first
cargo build --release -p lombokminer-ffi

# Then in your Go project
cd bindings/go
go test ./lombokminer/...         # Run tests
go run ./example                   # Run example
```

```go
package main

import (
    "fmt"
    "log"
    "github.com/codinglombok/lombokminer/bindings/go/lombokminer"
)

func main() {
    m, err := lombokminer.New()
    if err != nil {
        log.Fatal(err)
    }

    // SHA-256d
    hash, _ := m.SHA256dHex([]byte("hello"))
    fmt.Println(hash)

    // Genesis block hash
    var header [80]byte // ... fill with genesis header bytes
    blockHash, _ := m.BlockHashHex(header)
    fmt.Println(blockHash)

    // Difficulty
    fmt.Printf("Difficulty: %.2f\n", m.Difficulty(0x1d00ffff))

    // Validate address
    net, err := m.ValidateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    if err == nil {
        fmt.Printf("Valid (%s)\n", net)
    }

    // CPU mining
    result, err := m.MineCPU(header, 0x207fffff, 0, 100_000, 4)
    if err == nil {
        fmt.Printf("Nonce: %d, Hash: %s\n", result.Nonce, result.HashHex())
    }
}
```

Requires: Go 1.21+, liblombokminer built, CGo enabled (default).

## Rust (as library dependency)

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

    // Difficulty
    let diff = difficulty_from_nbits(0x1d00ffff);
    println!("{}", format_difficulty(diff));

    // Validate address
    let v = validate_address("bc1q...").unwrap();
    println!("{}: {}", v.address_type, v.network);

    // CPU mining
    let miner = CpuMiner::new(CpuConfig { threads: 4, core_affinity: false });
    let target = Target::from_nbits(0x207fffff);
    let header = BlockHeader::default();
    let r = miner.submit_work(&header, &target, 0, 1_000_000).unwrap();
    if let MineResult::Found { nonce, .. } = r.result {
        println!("Found nonce: {nonce}");
    }
}
```

Zero external dependencies. Uses the workspace crates directly via path imports.
