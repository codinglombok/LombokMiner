// Example: using LombokMiner Go bindings.
//
// Build:
//
//	cd lombokminer && cargo build --release -p lombokminer-ffi
//	cd bindings/go && go run ./example
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/codinglombok/lombokminer/bindings/go/lombokminer"
)

func main() {
	m, err := lombokminer.New()
	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	fmt.Printf("LombokMiner Go Bindings v%s\n\n", m.Version())

	// --- SHA-256d ---
	hash, _ := m.SHA256dHex([]byte("hello"))
	fmt.Printf("SHA-256d(\"hello\") = %s\n", hash)

	// --- Genesis block ---
	headerHex := "01000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
		"29ab5f49ffff001d1dac2b7c"

	headerBytes, _ := hex.DecodeString(headerHex)
	var header [80]byte
	copy(header[:], headerBytes)

	blockHash, _ := m.BlockHashHex(header)
	fmt.Printf("Genesis block:       %s\n", blockHash)

	// --- Difficulty ---
	diff := m.Difficulty(0x1d00ffff)
	fmt.Printf("Genesis difficulty:  %.2f\n", diff)

	// --- Address validation ---
	addr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	net, err := m.ValidateAddress(addr)
	if err != nil {
		fmt.Printf("Address %s: INVALID (%v)\n", addr, err)
	} else {
		fmt.Printf("Address %s: valid (%s)\n", addr, net)
	}

	// --- CPU mining ---
	fmt.Println("\nMining 100K nonces (easy target)...")
	var mineHeader [80]byte
	for i := range mineHeader {
		mineHeader[i] = byte(i * 3)
	}

	result, err := m.MineCPU(mineHeader, 0x207fffff, 0, 100_000, 0)
	if err != nil {
		fmt.Printf("Mining: %v\n", err)
	} else {
		fmt.Printf("Found nonce %d → %s\n", result.Nonce, result.HashHex())
	}
}
