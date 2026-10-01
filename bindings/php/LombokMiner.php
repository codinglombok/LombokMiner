<?php
/**
 * LombokMiner PHP Bindings
 *
 * Uses PHP FFI extension (PHP 7.4+) to call liblombokminer directly.
 * No compilation required — loads the shared library at runtime.
 *
 * Requirements:
 *   - PHP 7.4+ with FFI extension enabled (extension=ffi in php.ini)
 *   - liblombokminer.so / .dylib / .dll built from the Rust crate
 *
 * Usage:
 *   $miner = new LombokMiner('/path/to/liblombokminer.so');
 *   $hash = $miner->sha256d('hello');
 *   $valid = $miner->validateAddress('bc1q...');
 */

declare(strict_types=1);

class LombokMiner
{
    private \FFI $ffi;

    /**
     * Load the LombokMiner shared library.
     *
     * @param string $libPath Path to liblombokminer.so / .dylib / .dll
     */
    public function __construct(string $libPath)
    {
        if (!extension_loaded('ffi')) {
            throw new \RuntimeException('PHP FFI extension is required. Enable it in php.ini.');
        }

        if (!file_exists($libPath)) {
            throw new \RuntimeException("Library not found: {$libPath}");
        }

        $header = <<<CDEF
        const char* lombokminer_version(void);
        int32_t lombokminer_sha256d(const uint8_t* data, size_t data_len, uint8_t* out);
        int32_t lombokminer_block_hash(const uint8_t* header_80, uint8_t* out);
        double lombokminer_difficulty(uint32_t nbits);
        int32_t lombokminer_check_target(const uint8_t* hash, uint32_t nbits);
        int64_t lombokminer_mine_cpu(const uint8_t* header_80, uint32_t nbits,
            uint32_t nonce_start, uint32_t nonce_end, uint32_t threads, uint8_t* out_hash);
        int32_t lombokminer_validate_address(const char* address);
        int32_t lombokminer_selftest(void);
        CDEF;

        $this->ffi = \FFI::cdef($header, $libPath);

        if ($this->ffi->lombokminer_selftest() !== 0) {
            throw new \RuntimeException('LombokMiner self-test failed');
        }
    }

    /**
     * Get library version.
     */
    public function version(): string
    {
        return $this->ffi->lombokminer_version();
    }

    /**
     * Compute SHA-256d (double SHA-256).
     *
     * @param string $data Input bytes
     * @return string 32-byte binary hash
     */
    public function sha256d(string $data): string
    {
        $out = \FFI::new('uint8_t[32]');
        $ret = $this->ffi->lombokminer_sha256d($data, strlen($data), $out);
        if ($ret !== 0) {
            throw new \RuntimeException('sha256d failed');
        }
        return \FFI::string($out, 32);
    }

    /**
     * Compute SHA-256d and return hex string.
     */
    public function sha256dHex(string $data): string
    {
        return bin2hex($this->sha256d($data));
    }

    /**
     * Hash an 80-byte block header.
     *
     * @param string $header80 Exactly 80 bytes
     * @return string 32-byte hash in internal byte order
     */
    public function blockHash(string $header80): string
    {
        if (strlen($header80) !== 80) {
            throw new \InvalidArgumentException('Header must be 80 bytes');
        }
        $out = \FFI::new('uint8_t[32]');
        $ret = $this->ffi->lombokminer_block_hash($header80, $out);
        if ($ret !== 0) {
            throw new \RuntimeException('block_hash failed');
        }
        return \FFI::string($out, 32);
    }

    /**
     * Hash a block header and return display-order hex.
     */
    public function blockHashHex(string $header80): string
    {
        return bin2hex(strrev($this->blockHash($header80)));
    }

    /**
     * Compute difficulty from compact target (nBits).
     */
    public function difficulty(int $nbits): float
    {
        return $this->ffi->lombokminer_difficulty($nbits);
    }

    /**
     * Validate a Bitcoin address.
     *
     * @return array{valid: bool, network: ?string}
     */
    public function validateAddress(string $address): array
    {
        $ret = $this->ffi->lombokminer_validate_address($address);
        $networks = [0 => 'mainnet', 1 => 'testnet', 2 => 'regtest'];

        return [
            'valid'   => isset($networks[$ret]),
            'network' => $networks[$ret] ?? null,
        ];
    }

    /**
     * Mine a nonce range on CPU.
     *
     * @return array{nonce: ?int, hash: ?string}
     */
    public function mineCpu(
        string $header80,
        int    $nbits,
        int    $nonceStart = 0,
        int    $nonceEnd = 0xFFFFFFFF,
        int    $threads = 0
    ): array {
        if (strlen($header80) !== 80) {
            throw new \InvalidArgumentException('Header must be 80 bytes');
        }

        $outHash = \FFI::new('uint8_t[32]');
        $nonce = $this->ffi->lombokminer_mine_cpu(
            $header80, $nbits, $nonceStart, $nonceEnd, $threads, $outHash
        );

        if ($nonce === -2) {
            throw new \RuntimeException('Mining error');
        }
        if ($nonce === -1) {
            return ['nonce' => null, 'hash' => null];
        }

        return [
            'nonce' => $nonce,
            'hash'  => \FFI::string($outHash, 32),
        ];
    }
}
