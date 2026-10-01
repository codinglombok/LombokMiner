"""
LombokMiner Python Bindings

Pure ctypes wrapper — no compilation required, loads liblombokminer directly.

Usage:
    from lombokminer import LombokMiner

    miner = LombokMiner()                # auto-detect library path
    miner = LombokMiner("/path/to/lib")  # explicit path

    # SHA-256d
    hash_bytes = miner.sha256d(b"hello")

    # Mine
    nonce, hash_bytes = miner.mine_cpu(header_bytes, nbits=0x207fffff, threads=4)

    # Validate address
    is_valid, network = miner.validate_address("bc1q...")

Requirements: Python 3.8+, liblombokminer.so/.dylib/.dll in PATH or specified.
"""

import ctypes
import ctypes.util
import os
import platform
import struct
from pathlib import Path
from typing import Optional, Tuple


class LombokMiner:
    """Python interface to the LombokMiner C library."""

    def __init__(self, lib_path: Optional[str] = None):
        """Load the LombokMiner shared library.

        Args:
            lib_path: Explicit path to liblombokminer. If None, searches
                      standard locations and the directory containing this file.
        """
        if lib_path is None:
            lib_path = self._find_library()

        self._lib = ctypes.cdll.LoadLibrary(lib_path)
        self._setup_signatures()

        # Verify library loaded correctly
        if self.selftest() != 0:
            raise RuntimeError("LombokMiner self-test failed — library may be corrupt")

    def _find_library(self) -> str:
        """Search for the shared library."""
        system = platform.system()
        if system == "Linux":
            names = ["liblombokminer.so"]
        elif system == "Darwin":
            names = ["liblombokminer.dylib"]
        elif system == "Windows":
            names = ["lombokminer.dll"]
        else:
            names = ["liblombokminer.so"]

        # Check common paths
        search_dirs = [
            Path(__file__).parent,
            Path(__file__).parent.parent / "target" / "release",
            Path.cwd() / "target" / "release",
            Path.cwd(),
        ]

        for d in search_dirs:
            for name in names:
                p = d / name
                if p.exists():
                    return str(p)

        # Try system library path
        found = ctypes.util.find_library("lombokminer")
        if found:
            return found

        raise FileNotFoundError(
            f"Cannot find LombokMiner library. Build with `cargo build --release` "
            f"or pass lib_path= to LombokMiner(). Searched: {names}"
        )

    def _setup_signatures(self):
        """Define C function signatures for type safety."""
        lib = self._lib

        lib.lombokminer_version.restype = ctypes.c_char_p
        lib.lombokminer_version.argtypes = []

        lib.lombokminer_sha256d.restype = ctypes.c_int32
        lib.lombokminer_sha256d.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p
        ]

        lib.lombokminer_sha256_midstate.restype = ctypes.c_int32
        lib.lombokminer_sha256_midstate.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)
        ]

        lib.lombokminer_sha256d_from_midstate.restype = ctypes.c_int32
        lib.lombokminer_sha256d_from_midstate.argtypes = [
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_char_p
        ]

        lib.lombokminer_block_hash.restype = ctypes.c_int32
        lib.lombokminer_block_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        lib.lombokminer_difficulty.restype = ctypes.c_double
        lib.lombokminer_difficulty.argtypes = [ctypes.c_uint32]

        lib.lombokminer_check_target.restype = ctypes.c_int32
        lib.lombokminer_check_target.argtypes = [ctypes.c_char_p, ctypes.c_uint32]

        lib.lombokminer_mine_cpu.restype = ctypes.c_int64
        lib.lombokminer_mine_cpu.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p
        ]

        lib.lombokminer_validate_address.restype = ctypes.c_int32
        lib.lombokminer_validate_address.argtypes = [ctypes.c_char_p]

        lib.lombokminer_selftest.restype = ctypes.c_int32
        lib.lombokminer_selftest.argtypes = []

    def version(self) -> str:
        """Get library version string."""
        return self._lib.lombokminer_version().decode("utf-8")

    def sha256d(self, data: bytes) -> bytes:
        """Compute SHA-256d (double SHA-256).

        Args:
            data: Input bytes.

        Returns:
            32-byte hash digest.
        """
        out = ctypes.create_string_buffer(32)
        ret = self._lib.lombokminer_sha256d(data, len(data), out)
        if ret != 0:
            raise ValueError("sha256d failed")
        return out.raw

    def block_hash(self, header_80: bytes) -> bytes:
        """Hash an 80-byte block header.

        Args:
            header_80: Exactly 80 bytes of serialized block header.

        Returns:
            32-byte hash in internal byte order.
        """
        if len(header_80) != 80:
            raise ValueError(f"Header must be 80 bytes, got {len(header_80)}")
        out = ctypes.create_string_buffer(32)
        ret = self._lib.lombokminer_block_hash(header_80, out)
        if ret != 0:
            raise ValueError("block_hash failed")
        return out.raw

    def block_hash_hex(self, header_80: bytes) -> str:
        """Hash a block header and return display-order hex string."""
        h = bytearray(self.block_hash(header_80))
        h.reverse()
        return h.hex()

    def difficulty(self, nbits: int) -> float:
        """Compute difficulty from compact target (nBits)."""
        return self._lib.lombokminer_difficulty(nbits)

    def check_target(self, hash_bytes: bytes, nbits: int) -> bool:
        """Check if a hash meets the target."""
        if len(hash_bytes) != 32:
            raise ValueError("Hash must be 32 bytes")
        ret = self._lib.lombokminer_check_target(hash_bytes, nbits)
        if ret < 0:
            raise ValueError("check_target failed")
        return ret == 1

    def mine_cpu(
        self,
        header_80: bytes,
        nbits: int,
        nonce_start: int = 0,
        nonce_end: int = 0xFFFFFFFF,
        threads: int = 0,
    ) -> Tuple[Optional[int], Optional[bytes]]:
        """Mine a nonce range on CPU.

        Args:
            header_80: 80-byte block header template.
            nbits: Compact target.
            nonce_start: First nonce to try.
            nonce_end: Last nonce (exclusive).
            threads: CPU threads (0 = auto-detect).

        Returns:
            (nonce, hash) on success, (None, None) if exhausted.
        """
        if len(header_80) != 80:
            raise ValueError(f"Header must be 80 bytes, got {len(header_80)}")

        out_hash = ctypes.create_string_buffer(32)
        nonce = self._lib.lombokminer_mine_cpu(
            header_80, nbits, nonce_start, nonce_end, threads, out_hash
        )

        if nonce == -2:
            raise RuntimeError("Mining error")
        if nonce == -1:
            return (None, None)
        return (nonce, out_hash.raw)

    def validate_address(self, address: str) -> Tuple[bool, Optional[str]]:
        """Validate a Bitcoin address.

        Returns:
            (is_valid, network) where network is "mainnet"/"testnet"/"regtest" or None.
        """
        addr_bytes = address.encode("utf-8")
        ret = self._lib.lombokminer_validate_address(addr_bytes)
        networks = {0: "mainnet", 1: "testnet", 2: "regtest"}
        if ret in networks:
            return (True, networks[ret])
        return (False, None)

    def selftest(self) -> int:
        """Run SHA-256d self-test. Returns 0 on success."""
        return self._lib.lombokminer_selftest()


if __name__ == "__main__":
    # Quick demo
    m = LombokMiner()
    print(f"LombokMiner Python Bindings v{m.version()}")
    print(f"SHA-256d('hello') = {m.sha256d(b'hello').hex()}")
    print(f"Difficulty(0x1d00ffff) = {m.difficulty(0x1d00ffff)}")

    valid, net = m.validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    print(f"Address valid: {valid}, network: {net}")
