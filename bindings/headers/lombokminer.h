/*
 * LombokMiner C API — v1.0.0
 *
 * Generated from lombokminer-ffi. Do not edit manually.
 * https://github.com/codinglombok/lombokminer
 *
 * Usage (link against liblombokminer.so / .dylib / .dll / .a):
 *   gcc -o miner main.c -L./target/release -llombokminer -lpthread -ldl -lm
 */

#ifndef LOMBOKMINER_H
#define LOMBOKMINER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Version ──────────────────────────────────────────────────── */

/* Returns a static null-terminated version string. Do NOT free. */
const char* lombokminer_version(void);

/* ─── SHA-256d Hashing ─────────────────────────────────────────── */

/* SHA-256d(data, data_len) → out[32]. Returns 0 on success, -1 on null. */
int32_t lombokminer_sha256d(
    const uint8_t* data,
    size_t         data_len,
    uint8_t*       out       /* [32] caller-allocated */
);

/* SHA-256 midstate of first 64 bytes → out[8] (as uint32_t). */
int32_t lombokminer_sha256_midstate(
    const uint8_t*  first_64, /* [64] */
    uint32_t*       out       /* [8] caller-allocated */
);

/* SHA-256d from precomputed midstate + last 16 bytes → out[32]. */
int32_t lombokminer_sha256d_from_midstate(
    const uint32_t* midstate, /* [8] */
    const uint8_t*  last_16,  /* [16] */
    uint8_t*        out       /* [32] caller-allocated */
);

/* ─── Block Header ─────────────────────────────────────────────── */

/* Hash an 80-byte block header → out[32] (internal byte order). */
int32_t lombokminer_block_hash(
    const uint8_t* header_80, /* [80] */
    uint8_t*       out        /* [32] caller-allocated */
);

/* ─── Difficulty ───────────────────────────────────────────────── */

/* Compute difficulty from compact target (nBits). */
double lombokminer_difficulty(uint32_t nbits);

/* Check if hash[32] meets target. Returns 1=yes, 0=no, -1=null. */
int32_t lombokminer_check_target(
    const uint8_t* hash, /* [32] internal byte order */
    uint32_t       nbits
);

/* ─── Mining ───────────────────────────────────────────────────── */

/*
 * Mine a nonce range on CPU.
 *
 * Returns: winning nonce (≥0), -1 if not found, -2 on error.
 * On success, out_hash[32] is filled with the winning hash.
 */
int64_t lombokminer_mine_cpu(
    const uint8_t* header_80,   /* [80] block header template */
    uint32_t       nbits,       /* compact target */
    uint32_t       nonce_start,
    uint32_t       nonce_end,   /* exclusive */
    uint32_t       threads,     /* 0 = auto-detect */
    uint8_t*       out_hash     /* [32] caller-allocated */
);

/* ─── Wallet Validation ────────────────────────────────────────── */

/* Validate a Bitcoin address (null-terminated UTF-8).
 * Returns: 0=mainnet, 1=testnet, 2=regtest, -1=invalid, -2=null. */
int32_t lombokminer_validate_address(const char* address);

/* ─── Self-test ────────────────────────────────────────────────── */

/* Run SHA-256d self-test. Returns 0 on success, -1 on failure. */
int32_t lombokminer_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* LOMBOKMINER_H */
