# LombokMiner

High-performance Bitcoin mining software. Memory-safe. Stratum V2-first. Zero external C dependencies.

## Quick Start

```bash
cargo build --release

lombokminer selftest           # verify SHA-256d + crypto + wallet + mining
lombokminer bench -m 50 -t 4   # benchmark 50M hashes, 4 threads
lombokminer info               # system capabilities + solo mining ETA
lombokminer init               # generate lombokminer.toml
lombokminer mine -b 1f00ffff   # test mining (easy difficulty)
lombokminer validate bc1q...   # validate Bitcoin address
lombokminer config             # show loaded config
```

## Why LombokMiner?

|  | CGMiner | BFGMiner | LombokMiner |
|---|---|---|---|
| Language | C (unsafe) | C (unsafe) | **Rust (memory-safe)** |
| Protocol | Stratum V1 | Stratum V1 | **Stratum V2 + V1** |
| Encryption | None | None | **ChaCha20-Poly1305** |
| Dependencies | libcurl, jansson | libcurl, jansson | **Zero external C deps** |
| Dashboard | None | None | **CLI + Web** |
| MITM detection | None | None | **IP + key + latency monitoring** |
| Audit | Manual only | Manual only | **cargo audit + 6 fuzz targets** |

## Architecture

```
lombokminer-core        SHA-256d, block construction, difficulty       1,682 LOC
lombokminer-net         Stratum V2/V1, GBT RPC, pool failover        2,345 LOC
lombokminer-hal         CPU multi-thread, GPU (OpenCL), ASIC USB      1,068 LOC
lombokminer-security    ChaCha20-Poly1305, wallet, MITM/hijack        1,462 LOC
lombokminer-monitor     Prometheus metrics, alert engine               1,046 LOC
lombokminer-config      TOML config, validation                          255 LOC
lombokminer-cli         7 commands                                       362 LOC
lombokminer-ffi         C FFI for Python/PHP/Go bindings                 340 LOC
dashboard/              Real-time web UI (WebSocket)                     585 LOC
─────────────────────────────────────────────────────────────────────────────
Total                                                                  9,145 LOC
Tests                                                                    150
Binary                                                                  2.7 MB
```

## Language Bindings

Build the shared library, then use from any language:

```bash
cargo build --release -p lombokminer-ffi
```

**Python** (ctypes, zero compilation):
```python
from lombokminer import LombokMiner
m = LombokMiner()
m.sha256d(b"hello")
m.validate_address("bc1q...")
nonce, hash = m.mine_cpu(header, nbits=0x207fffff, threads=4)
```

**PHP** (FFI extension):
```php
$m = new LombokMiner('/path/to/liblombokminer.so');
$m->sha256dHex('hello');
$m->validateAddress('bc1q...');
```

**C/C++** (link against liblombokminer):
```c
#include "lombokminer.h"
lombokminer_sha256d(data, len, out);
lombokminer_mine_cpu(header, nbits, 0, 0xFFFFFFFF, 4, out_hash);
```

## Documentation

- [Security](docs/SECURITY.md) — threat model, encryption, audit checklist
- [API Reference](docs/API.md) — C FFI, Python, PHP, C/C++ usage

## License

Apache-2.0 — [codinglombok](https://github.com/codinglombok)
