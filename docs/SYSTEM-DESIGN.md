# LombokMiner — System Design Document

**Status:** Complete
**Date:** 2026-09-01
**Version:** 1.0.0
**License:** Apache-2.0
**Organization:** codinglombok

---

## 1. Executive Summary

LombokMiner is a Bitcoin mining application designed from scratch with the following principles: **zero-dependency core**, **Stratum V2-first**, **memory-safe**, and **auditable**. This project addresses the fundamental weaknesses of existing mining software (CGMiner, BFGMiner, etc.) which are written in C without memory safety, still rely on plaintext Stratum V1, and are difficult to audit.

**Key differentiators versus competitors:**

| Aspect | CGMiner/BFGMiner | NiceHash/EasyMiner | LombokMiner |
|---|---|---|---|
| Language | C (unsafe) | C#/.NET (heavy runtime) | Rust (memory-safe, zero-cost) |
| Protocol | Stratum V1 (plaintext) | Stratum V1 | Stratum V2 (encrypted) + V1 compat |
| Dependencies | libcurl, jansson, etc. | .NET Runtime ~200MB | Zero external C deps |
| Encryption | None | TLS bolt-on | ChaCha20-Poly1305 native |
| Block template | Pool-controlled | Pool-controlled | Job Declaration (miner-sovereign) |
| Dashboard | None (CLI only) | GUI (Windows only) | CLI + Web Dashboard (cross-platform) |
| Audit | Difficult (C pointer arithmetic) | Closed-source | `cargo audit` + fuzzing + MIRI |

---

## 2. Requirements

### 2.1 Functional Requirements

**FR-1: Mining Modes**
- Solo mining via `getblocktemplate` RPC to `bitcoind`
- Pool mining via Stratum V2 (primary) and Stratum V1 (backward-compat)
- Job Declaration — miner builds its own block template from local mempool

**FR-2: Hardware Abstraction**
- CPU mining (SHA-256d) — for development/testnet
- GPU mining via compute shaders (OpenCL 3.0 / Vulkan Compute)
- ASIC control via USB/serial (cgminer-compatible protocol)

**FR-3: Network**
- Bitcoin P2P protocol for node discovery (DNS seeds, addr messages)
- Stratum V2 sub-protocols: Mining Protocol, Job Declaration, Template Distribution
- Stratum V1 fallback (JSON-RPC over TCP)
- `getblocktemplate` RPC client (BIP 22/23/9/145)

**FR-4: User Interface**
- CLI: real-time hashrate, temperature, shares, profit estimation
- Web Dashboard: live metrics, pool management, hardware control, log viewer
- Headless mode: daemon + JSON API for automation/monitoring

**FR-5: Monitoring & Telemetry**
- Per-device hashrate, temperature, fan speed, power draw
- Share accept/reject/stale ratio
- Network latency to pool
- Prometheus-compatible metrics endpoint
- Alert system (hashrate drop, temperature threshold, stale shares)

**FR-6: Security**
- Encrypted communication (Stratum V2: Noise Framework / ChaCha20-Poly1305)
- MITM detection and prevention
- Configuration encryption at rest
- Wallet address validation (Bech32/Bech32m)
- Hashrate hijacking detection

### 2.2 Non-Functional Requirements

| Requirement | Target |
|---|---|
| Startup time | < 500ms to first hash |
| Memory footprint | < 50MB (CLI mode), < 100MB (dashboard) |
| Binary size | < 15MB stripped |
| Latency (share submission) | < 5ms overhead above network RTT |
| Platform | Linux x86_64/aarch64, Windows x86_64, macOS x86_64/aarch64 |
| Zero external C library deps | Core binary statically links everything |
| Audit surface | `cargo audit` clean, `cargo clippy` zero warnings, fuzzing harness |

---

## 3. Architecture Decision: Language

### 3.1 ADR-001: Primary Language — Rust

**Options evaluated:**

| Language | Hashing Speed | Memory Safety | Concurrency | Binary Size | Cross-platform | Dependency Footprint |
|---|---|---|---|---|---|---|
| **Rust** | ~C speed | Compile-time guaranteed | async (tokio) + channels | 10-15MB | Excellent | Zero runtime |
| C++ | Fastest possible | Manual (error-prone) | Threads + locks | 5-10MB | Good | libc only |
| Go | ~70% of C | GC (pauses) | Goroutines | 15-20MB | Excellent | Go runtime |
| TypeScript | ~5% of C | GC | Event loop (single-thread) | N/A (needs Node) | Needs runtime | node_modules |
| Python | ~1% of C | GC | GIL bottleneck | N/A (needs interpreter) | Needs runtime | pip packages |
| Assembly | Fastest | None | Manual | Tiny | Per-architecture | None |

**Decision: Rust as the primary language.**

Rationale:
- **Performance**: SHA-256d hashing in Rust with SIMD intrinsics approaches C/assembly speed. `core::arch` provides platform-specific SIMD without unsafe external deps.
- **Memory safety**: The ownership system prevents use-after-free, buffer overflows, and data races — all vulnerability classes present in CGMiner/BFGMiner.
- **Zero-cost abstractions**: Traits, generics, and async/await with no runtime overhead.
- **No garbage collector**: No GC pauses that could cause stale shares.
- **Auditable**: `cargo audit` for CVE scanning, `cargo clippy` for lint, `cargo fuzz` + MIRI for memory correctness. This is an advantage C/C++ does not have.
- **Cross-compilation**: The `cross` toolchain supports all target platforms.
- **No external C deps**: `ring` for crypto, `rustls` for TLS — pure Rust, no OpenSSL.

**Consequences:**
- Steeper learning curve than Go/Python/TS
- Longer compile times than C/Go
- Mining-specific crate ecosystem is still small (we build our own)

### 3.2 Porting Strategy

| Port | Language | Purpose | Timeline |
|---|---|---|---|
| Core Engine | Rust | Primary — all platforms | v0.1.0 |
| Web Dashboard | TypeScript (Svelte) | Browser-based monitoring UI | v0.3.0 |
| Python Bindings | Python (PyO3) | Scripting, plugin API, automation | v0.6.0 |
| PHP SDK | PHP | Integration with web apps (monitoring panel) | v0.6.0 |
| C FFI | C header | Embedding into ASIC firmware / legacy systems | v0.6.0 |

The Rust core is exposed via C FFI (`cbindgen`), so all other languages can call the hashing engine, Stratum client, and block template builder without reimplementation.

---

## 4. System Architecture

### 4.1 High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        LombokMiner                              │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │   CLI/TUI    │  │ Web Dashboard│  │    JSON-RPC API        ││
│  │  (ratatui)   │  │  (Svelte)    │  │  (headless/daemon)     ││
│  └──────┬───────┘  └──────┬───────┘  └────────┬───────────────┘│
│         │                 │                    │                │
│  ┌──────┴─────────────────┴────────────────────┴──────────────┐│
│  │                    Control Plane                            ││
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  ││
│  │  │ Config  │ │  Alerts  │ │ Metrics  │ │  Pool Manager │  ││
│  │  │ Manager │ │  Engine  │ │ Collector│ │  (failover)   │  ││
│  │  └─────────┘ └──────────┘ └──────────┘ └───────────────┘  ││
│  └────────────────────────┬───────────────────────────────────┘│
│                           │                                     │
│  ┌────────────────────────┴───────────────────────────────────┐│
│  │                    Mining Engine                             ││
│  │  ┌──────────────┐ ┌────────────────┐ ┌──────────────────┐  ││
│  │  │ Block Builder│ │ Nonce Iterator │ │ Share Validator  │  ││
│  │  │ (merkle tree,│ │ (SIMD SHA-256d)│ │ (diff check,    │  ││
│  │  │  coinbase tx)│ │                │ │  submit)        │  ││
│  │  └──────────────┘ └────────────────┘ └──────────────────┘  ││
│  └────────────────────────┬───────────────────────────────────┘│
│                           │                                     │
│  ┌────────────────────────┴───────────────────────────────────┐│
│  │                 Hardware Abstraction Layer                   ││
│  │  ┌─────────┐  ┌──────────────┐  ┌───────────────────────┐ ││
│  │  │   CPU   │  │  GPU (OpenCL │  │  ASIC (USB/Serial     │ ││
│  │  │  Worker │  │  / Vulkan)   │  │  cgminer-compat)      │ ││
│  │  └─────────┘  └──────────────┘  └───────────────────────┘ ││
│  └────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐│
│  │                    Network Layer                             ││
│  │  ┌──────────────┐ ┌─────────────┐ ┌──────────────────────┐││
│  │  │ Stratum V2   │ │ Stratum V1  │ │ getblocktemplate     │││
│  │  │ (Noise/AEAD) │ │ (JSON-RPC)  │ │ RPC Client           │││
│  │  └──────────────┘ └─────────────┘ └──────────────────────┘││
│  └────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐│
│  │                    Security Layer                            ││
│  │  ┌──────────────┐ ┌─────────────┐ ┌──────────────────────┐││
│  │  │ Noise_NNpsk0 │ │ MITM        │ │ Hashrate Hijack      │││
│  │  │ Handshake    │ │ Detection   │ │ Detection            │││
│  │  └──────────────┘ └─────────────┘ └──────────────────────┘││
│  │  ┌──────────────┐ ┌─────────────────────────────────────┐ ││
│  │  │ Config       │ │ Wallet Address Validation           │ ││
│  │  │ Encryption   │ │ (Bech32/Bech32m/P2SH/P2PKH)        │ ││
│  │  └──────────────┘ └─────────────────────────────────────┘ ││
│  └────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Flow — Solo Mining

```
bitcoind                    LombokMiner                    Hardware
   │                            │                              │
   │◄── getblocktemplate ───────│                              │
   │    (HTTP longpoll)         │                              │
   │───── block template ──────►│                              │
   │    (txs, prev_hash,        │── construct coinbase tx ──►  │
   │     target, bits)          │── build merkle tree ──────►  │
   │                            │── create 80-byte header ──►  │
   │                            │                              │
   │                            │◄── nonce iteration ──────── │
   │                            │    (SHA-256d per nonce)      │
   │                            │                              │
   │                            │◄── hash < target? ────────  │
   │                            │    YES: return header+nonce  │
   │                            │    NO: bump extranonce,      │
   │                            │        rebuild merkle root   │
   │                            │                              │
   │◄── submitblock ───────────│                              │
   │    (complete block)        │                              │
   │───── accepted ────────────►│                              │
```

### 4.3 Data Flow — Pool Mining (Stratum V2)

```
Pool                        LombokMiner                    ASIC/GPU
   │                            │                              │
   │◄═══ Noise_NNpsk0 ════════►│  (encrypted handshake)       │
   │     handshake              │                              │
   │                            │                              │
   │── SetupConnection ────────►│                              │
   │◄── SetupConnection.Succ ──│                              │
   │                            │                              │
   │── OpenMiningChannel ──────►│                              │
   │◄── OpenMiningChannel.Succ │                              │
   │                            │                              │
   │── NewMiningJob ───────────►│── distribute work ─────────►│
   │   (binary, ~70% less       │   (header + target)          │
   │    bandwidth vs V1)        │                              │
   │                            │◄── share found ────────────│
   │◄── SubmitSharesStandard ──│                              │
   │── SubmitShares.Success ───►│                              │
   │                            │                              │
   │  [Job Declaration mode]    │                              │
   │◄── DeclareMiningJob ──────│  (miner-built template)      │
   │── DeclareMiningJob.Succ ──►│                              │
```

---

## 5. Development Roadmap (Completed)

| Version | Scope | Status |
|---|---|---|
| **v0.1.0** | Core: SHA-256d engine + CPU mining + getblocktemplate solo mining + CLI | Done: 34 tests |
| **v0.2.0** | Network: Stratum V2 client + pool mining + Stratum V1 compat | Done: 68 tests |
| **v0.3.0** | Dashboard: Web UI + Prometheus metrics + alerts | Done: 84 tests |
| **v0.4.0** | Hardware: GPU (OpenCL/Vulkan) + ASIC USB support | Done: 104 tests |
| **v0.5.0** | Security: Job Declaration + MITM detection + hashrate hijack detect | Done: 132 tests |
| **v0.6.0** | Bindings: Python (ctypes) + PHP FFI + C header | Done: 150 tests |
| **v1.0.0** | Production: Full audit, fuzz clean, documentation, binary releases | Done: 150 tests |

---

## 6. References

1. Bitcoin Developer Guide — Mining: https://developer.bitcoin.org/devguide/mining.html
2. Bitcoin Core: https://github.com/bitcoin/bitcoin
3. BFGMiner: https://github.com/luke-jr/bfgminer
4. OpenCL (Khronos): https://www.khronos.org/opencl/
5. NVIDIA OpenCL: https://developer.nvidia.com/opencl
6. Eloipool (pool software): https://github.com/luke-jr/eloipool
7. libblkmaker: https://github.com/bitcoin/libblkmaker
8. python-blkmaker: https://github.com/luke-jr/python-blkmaker
9. Bitcoin P2P Network: https://developer.bitcoin.org/devguide/p2p_network.html
10. Bitcoin seed nodes: https://github.com/bitcoin/bitcoin/tree/master/contrib/seeds
11. MITM attacks: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
12. BitcoinJ: https://bitcoinj.org/
13. DNS (RFC 1035): https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
14. DNS Seeds: https://developer.bitcoin.org/glossary.html#term-DNS-seed
15. getblocktemplate RPC: https://developer.bitcoin.org/reference/rpc/getblocktemplate.html
16. Stratum V2 Spec: https://github.com/stratum-mining/sv2-spec
17. SRI (Stratum V2 Reference Implementation): https://github.com/stratum-mining/stratum
18. BIP 22 (getblocktemplate): https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
19. BIP 23 (GBT pooled mining): https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki
20. Noise Protocol Framework: http://www.noiseprotocol.org/

---

*Document generated for codinglombok organization. Apache-2.0 licensed.*
