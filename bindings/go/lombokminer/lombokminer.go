// Package lombokminer provides Go bindings for the LombokMiner Bitcoin mining library.
//
// It wraps the C FFI (liblombokminer) via CGo, exposing an idiomatic Go API
// for SHA-256d hashing, block header operations, difficulty calculation,
// CPU mining, and wallet address validation.
//
// # Build Requirements
//
// Build the shared library first:
//
//	cd lombokminer && cargo build --release -p lombokminer-ffi
//
// Then set CGo linker flags (or use the defaults below which look in ../target/release):
//
//	export CGO_LDFLAGS="-L/path/to/lombokminer/target/release -llombokminer -lpthread -ldl -lm"
//	go build ./...
//
// # Quick Start
//
//	m, err := lombokminer.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	hash := m.SHA256d([]byte("hello"))
//	fmt.Printf("%x\n", hash)
package lombokminer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -llombokminer -lpthread -ldl -lm
#include <stdint.h>
#include <stdlib.h>

// From lombokminer.h
const char* lombokminer_version(void);
int32_t lombokminer_sha256d(const uint8_t* data, size_t data_len, uint8_t* out);
int32_t lombokminer_sha256_midstate(const uint8_t* first_64, uint32_t* out);
int32_t lombokminer_sha256d_from_midstate(const uint32_t* midstate, const uint8_t* last_16, uint8_t* out);
int32_t lombokminer_block_hash(const uint8_t* header_80, uint8_t* out);
double lombokminer_difficulty(uint32_t nbits);
int32_t lombokminer_check_target(const uint8_t* hash, uint32_t nbits);
int64_t lombokminer_mine_cpu(const uint8_t* header_80, uint32_t nbits,
    uint32_t nonce_start, uint32_t nonce_end, uint32_t threads, uint8_t* out_hash);
int32_t lombokminer_validate_address(const char* address);
int32_t lombokminer_selftest(void);
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

// Errors returned by the library.
var (
	ErrSelfTestFailed = errors.New("lombokminer: SHA-256d self-test failed")
	ErrNullPointer    = errors.New("lombokminer: null pointer")
	ErrInvalidAddress = errors.New("lombokminer: invalid Bitcoin address")
	ErrMiningFailed   = errors.New("lombokminer: mining error")
	ErrNotFound       = errors.New("lombokminer: nonce not found in range")
	ErrInvalidHeader  = errors.New("lombokminer: header must be exactly 80 bytes")
	ErrInvalidHash    = errors.New("lombokminer: hash must be exactly 32 bytes")
)

// Network represents a Bitcoin network.
type Network int

const (
	Mainnet Network = 0
	Testnet Network = 1
	Regtest Network = 2
)

// String returns the network name.
func (n Network) String() string {
	switch n {
	case Mainnet:
		return "mainnet"
	case Testnet:
		return "testnet"
	case Regtest:
		return "regtest"
	default:
		return "unknown"
	}
}

// MineResult holds the result of a CPU mining operation.
type MineResult struct {
	// Nonce is the winning nonce value.
	Nonce uint32
	// Hash is the 32-byte block hash (internal byte order).
	Hash [32]byte
}

// HashHex returns the block hash in display order (big-endian hex).
func (r *MineResult) HashHex() string {
	var display [32]byte
	for i := 0; i < 32; i++ {
		display[i] = r.Hash[31-i]
	}
	return hex.EncodeToString(display[:])
}

// Miner is the main interface to the LombokMiner library.
// Create one with New(). It is safe for concurrent use.
type Miner struct{}

// New creates a new Miner instance and runs the self-test.
// Returns an error if the self-test fails (library may be corrupt).
func New() (*Miner, error) {
	ret := C.lombokminer_selftest()
	if ret != 0 {
		return nil, ErrSelfTestFailed
	}
	return &Miner{}, nil
}

// Version returns the library version string.
func (m *Miner) Version() string {
	return C.GoString(C.lombokminer_version())
}

// SHA256d computes SHA-256d (double SHA-256) of the input data.
// Returns a 32-byte hash.
func (m *Miner) SHA256d(data []byte) ([32]byte, error) {
	var out [32]byte
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	} else {
		// Empty input — pass a valid pointer to avoid null
		dummy := [1]byte{}
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&dummy[0]))
	}

	ret := C.lombokminer_sha256d(dataPtr, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		return out, ErrNullPointer
	}
	return out, nil
}

// SHA256dHex computes SHA-256d and returns the hex-encoded hash string.
func (m *Miner) SHA256dHex(data []byte) (string, error) {
	hash, err := m.SHA256d(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash[:]), nil
}

// Midstate computes the SHA-256 midstate of the first 64 bytes of a block header.
// This is used to optimize mining: the midstate is computed once and reused
// for each nonce attempt.
func (m *Miner) Midstate(first64 [64]byte) ([8]uint32, error) {
	var out [8]uint32
	ret := C.lombokminer_sha256_midstate(
		(*C.uint8_t)(unsafe.Pointer(&first64[0])),
		(*C.uint32_t)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, ErrNullPointer
	}
	return out, nil
}

// SHA256dFromMidstate completes a SHA-256d hash from a precomputed midstate
// and the last 16 bytes of the 80-byte header.
func (m *Miner) SHA256dFromMidstate(midstate [8]uint32, last16 [16]byte) ([32]byte, error) {
	var out [32]byte
	ret := C.lombokminer_sha256d_from_midstate(
		(*C.uint32_t)(unsafe.Pointer(&midstate[0])),
		(*C.uint8_t)(unsafe.Pointer(&last16[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, ErrNullPointer
	}
	return out, nil
}

// BlockHash hashes an 80-byte serialized block header and returns the
// 32-byte hash in internal byte order.
func (m *Miner) BlockHash(header [80]byte) ([32]byte, error) {
	var out [32]byte
	ret := C.lombokminer_block_hash(
		(*C.uint8_t)(unsafe.Pointer(&header[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, ErrNullPointer
	}
	return out, nil
}

// BlockHashHex hashes a block header and returns the hash in display order
// (big-endian hex string), as shown in block explorers.
func (m *Miner) BlockHashHex(header [80]byte) (string, error) {
	hash, err := m.BlockHash(header)
	if err != nil {
		return "", err
	}
	var display [32]byte
	for i := 0; i < 32; i++ {
		display[i] = hash[31-i]
	}
	return hex.EncodeToString(display[:]), nil
}

// Difficulty computes the mining difficulty from the compact target (nBits).
// Difficulty 1.0 corresponds to nBits = 0x1d00ffff (Bitcoin genesis block).
func (m *Miner) Difficulty(nbits uint32) float64 {
	return float64(C.lombokminer_difficulty(C.uint32_t(nbits)))
}

// CheckTarget checks whether a 32-byte hash (internal byte order) meets
// the target specified by nBits. Returns true if hash <= target.
func (m *Miner) CheckTarget(hash [32]byte, nbits uint32) (bool, error) {
	ret := C.lombokminer_check_target(
		(*C.uint8_t)(unsafe.Pointer(&hash[0])),
		C.uint32_t(nbits),
	)
	if ret < 0 {
		return false, ErrNullPointer
	}
	return ret == 1, nil
}

// MineCPU mines a nonce range on the CPU using multiple threads.
//
// Parameters:
//   - header: 80-byte block header template (nonce field is overwritten)
//   - nbits: compact target encoding
//   - nonceStart: first nonce to try (inclusive)
//   - nonceEnd: last nonce to try (exclusive)
//   - threads: number of CPU threads (0 = auto-detect all cores)
//
// Returns a MineResult if a valid nonce is found, or ErrNotFound if the
// entire range is exhausted without finding a valid hash.
func (m *Miner) MineCPU(header [80]byte, nbits uint32, nonceStart, nonceEnd uint32, threads uint32) (*MineResult, error) {
	var outHash [32]byte

	nonce := C.lombokminer_mine_cpu(
		(*C.uint8_t)(unsafe.Pointer(&header[0])),
		C.uint32_t(nbits),
		C.uint32_t(nonceStart),
		C.uint32_t(nonceEnd),
		C.uint32_t(threads),
		(*C.uint8_t)(unsafe.Pointer(&outHash[0])),
	)

	switch nonce {
	case -2:
		return nil, ErrMiningFailed
	case -1:
		return nil, ErrNotFound
	default:
		return &MineResult{
			Nonce: uint32(nonce),
			Hash:  outHash,
		}, nil
	}
}

// ValidateAddress validates a Bitcoin address string.
// Returns the network (Mainnet, Testnet, Regtest) on success,
// or ErrInvalidAddress if the address is invalid.
func (m *Miner) ValidateAddress(address string) (Network, error) {
	cAddr := C.CString(address)
	defer C.free(unsafe.Pointer(cAddr))

	ret := C.lombokminer_validate_address(cAddr)
	switch ret {
	case 0:
		return Mainnet, nil
	case 1:
		return Testnet, nil
	case 2:
		return Regtest, nil
	default:
		return -1, fmt.Errorf("%w: %s", ErrInvalidAddress, address)
	}
}

// SelfTest runs the SHA-256d self-test (genesis block hash verification).
// Returns nil on success, an error on failure.
func (m *Miner) SelfTest() error {
	if C.lombokminer_selftest() != 0 {
		return ErrSelfTestFailed
	}
	return nil
}
