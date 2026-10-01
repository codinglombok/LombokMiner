package lombokminer

import (
	"encoding/hex"
	"testing"
)

func mustNew(t *testing.T) *Miner {
	t.Helper()
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return m
}

func TestNew(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestVersion(t *testing.T) {
	m := mustNew(t)
	v := m.Version()
	if v == "" {
		t.Fatal("Version() returned empty string")
	}
	t.Logf("Version: %s", v)
}

func TestSHA256d(t *testing.T) {
	m := mustNew(t)

	hash, err := m.SHA256d([]byte("hello"))
	if err != nil {
		t.Fatalf("SHA256d failed: %v", err)
	}

	got := hex.EncodeToString(hash[:])
	// SHA-256d("hello") — known test vector
	if len(got) != 64 {
		t.Fatalf("expected 64-char hex, got %d chars", len(got))
	}

	// Same input must produce same output
	hash2, _ := m.SHA256d([]byte("hello"))
	if hash != hash2 {
		t.Fatal("SHA256d not deterministic")
	}

	// Different input must produce different output
	hash3, _ := m.SHA256d([]byte("world"))
	if hash == hash3 {
		t.Fatal("SHA256d collision on different inputs")
	}
}

func TestSHA256dEmpty(t *testing.T) {
	m := mustNew(t)
	hash, err := m.SHA256d([]byte{})
	if err != nil {
		t.Fatalf("SHA256d empty failed: %v", err)
	}
	if hash == [32]byte{} {
		t.Fatal("SHA256d of empty should not be all zeros")
	}
}

func TestSHA256dHex(t *testing.T) {
	m := mustNew(t)
	h, err := m.SHA256dHex([]byte("hello"))
	if err != nil {
		t.Fatalf("SHA256dHex failed: %v", err)
	}
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex string, got %d", len(h))
	}
}

func TestMidstateRoundtrip(t *testing.T) {
	m := mustNew(t)

	// Build a test header
	var header [80]byte
	for i := range header {
		header[i] = byte(i)
	}

	// Full hash
	fullHash, err := m.BlockHash(header)
	if err != nil {
		t.Fatalf("BlockHash failed: %v", err)
	}

	// Midstate + last 16 bytes
	var first64 [64]byte
	copy(first64[:], header[:64])
	var last16 [16]byte
	copy(last16[:], header[64:])

	midstate, err := m.Midstate(first64)
	if err != nil {
		t.Fatalf("Midstate failed: %v", err)
	}

	midHash, err := m.SHA256dFromMidstate(midstate, last16)
	if err != nil {
		t.Fatalf("SHA256dFromMidstate failed: %v", err)
	}

	if fullHash != midHash {
		t.Fatal("midstate hash does not match full hash")
	}
}

func TestBlockHashGenesis(t *testing.T) {
	m := mustNew(t)

	// Bitcoin genesis block header (80 bytes)
	headerHex := "01000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
		"29ab5f49" +
		"ffff001d" +
		"1dac2b7c"

	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	var header [80]byte
	copy(header[:], headerBytes)

	hashHex, err := m.BlockHashHex(header)
	if err != nil {
		t.Fatalf("BlockHashHex failed: %v", err)
	}

	expected := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	if hashHex != expected {
		t.Fatalf("genesis hash mismatch\ngot:    %s\nexpect: %s", hashHex, expected)
	}
}

func TestDifficulty(t *testing.T) {
	m := mustNew(t)

	diff := m.Difficulty(0x1d00ffff)
	if diff < 0.99 || diff > 1.01 {
		t.Fatalf("genesis difficulty should be ~1.0, got %f", diff)
	}
}

func TestCheckTarget(t *testing.T) {
	m := mustNew(t)

	// All-zero hash should meet any target
	zeroHash := [32]byte{}
	meets, err := m.CheckTarget(zeroHash, 0x1d00ffff)
	if err != nil {
		t.Fatalf("CheckTarget failed: %v", err)
	}
	if !meets {
		t.Fatal("all-zero hash should meet target")
	}

	// All-FF hash should NOT meet target
	var maxHash [32]byte
	for i := range maxHash {
		maxHash[i] = 0xFF
	}
	meets, err = m.CheckTarget(maxHash, 0x1d00ffff)
	if err != nil {
		t.Fatalf("CheckTarget failed: %v", err)
	}
	if meets {
		t.Fatal("all-FF hash should NOT meet target")
	}
}

func TestMineCPU(t *testing.T) {
	m := mustNew(t)

	// Easy target — should find a nonce quickly
	var header [80]byte
	for i := range header {
		header[i] = byte(i * 7)
	}

	result, err := m.MineCPU(header, 0x207fffff, 0, 100_000, 1)
	if err != nil {
		t.Fatalf("MineCPU failed: %v", err)
	}

	t.Logf("Found nonce %d, hash %s", result.Nonce, result.HashHex())

	// Verify the hash meets the target
	meets, _ := m.CheckTarget(result.Hash, 0x207fffff)
	if !meets {
		t.Fatal("found hash does not meet target")
	}
}

func TestMineCPUNotFound(t *testing.T) {
	m := mustNew(t)

	// Impossible target (all zeros) — should not find
	var header [80]byte
	_, err := m.MineCPU(header, 0x01003456, 0, 100, 1)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestValidateAddress(t *testing.T) {
	m := mustNew(t)

	tests := []struct {
		addr    string
		wantNet Network
		wantErr bool
	}{
		{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Mainnet, false},
		{"invalid_address", -1, true},
		{"", -1, true},
	}

	for _, tt := range tests {
		net, err := m.ValidateAddress(tt.addr)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ValidateAddress(%q) expected error, got network=%v", tt.addr, net)
			}
		} else {
			if err != nil {
				t.Errorf("ValidateAddress(%q) failed: %v", tt.addr, err)
			}
			if net != tt.wantNet {
				t.Errorf("ValidateAddress(%q) network=%v, want %v", tt.addr, net, tt.wantNet)
			}
		}
	}
}

func TestNetworkString(t *testing.T) {
	if Mainnet.String() != "mainnet" {
		t.Error("Mainnet.String() wrong")
	}
	if Testnet.String() != "testnet" {
		t.Error("Testnet.String() wrong")
	}
	if Regtest.String() != "regtest" {
		t.Error("Regtest.String() wrong")
	}
}

func TestMineResultHashHex(t *testing.T) {
	r := &MineResult{
		Nonce: 42,
		Hash:  [32]byte{0x01, 0x02, 0x03}, // rest zeros
	}
	h := r.HashHex()
	// Last bytes in display order should be 03, 02, 01
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(h))
	}
	// First chars should be "00...000302010"
	if h[62:64] != "01" {
		t.Errorf("expected last display byte '01', got '%s'", h[62:64])
	}
}

func BenchmarkSHA256d(b *testing.B) {
	m, err := New()
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("benchmark data for sha256d hashing performance test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.SHA256d(data)
	}
}

func BenchmarkMineCPU(b *testing.B) {
	m, err := New()
	if err != nil {
		b.Fatal(err)
	}
	var header [80]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MineCPU(header, 0x01003456, 0, 10_000, 1)
	}
}
