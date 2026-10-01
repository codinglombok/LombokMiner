// LombokMiner — 80-byte Bitcoin block header
//
// Layout (all fields little-endian):
//   [0..4]   version        (i32)
//   [4..36]  prev_block     (32 bytes, internal byte order)
//   [36..68] merkle_root    (32 bytes, internal byte order)
//   [68..72] timestamp      (u32, Unix epoch)
//   [72..76] bits           (u32, compact target encoding)
//   [76..80] nonce          (u32)

use serde::{Deserialize, Serialize};

/// A Bitcoin block header (80 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version (currently 0x20000000 with version bits)
    pub version: i32,
    /// Hash of the previous block (internal byte order)
    pub prev_block: [u8; 32],
    /// Merkle root of all transactions in this block
    pub merkle_root: [u8; 32],
    /// Block timestamp (seconds since Unix epoch)
    pub timestamp: u32,
    /// Compact target encoding (nBits)
    pub bits: u32,
    /// Nonce — iterated by the miner to find a valid hash
    pub nonce: u32,
}

impl BlockHeader {
    /// Serialize to the 80-byte wire format (little-endian).
    #[inline]
    pub fn serialize(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..36].copy_from_slice(&self.prev_block);
        buf[36..68].copy_from_slice(&self.merkle_root);
        buf[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[72..76].copy_from_slice(&self.bits.to_le_bytes());
        buf[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Deserialize from 80-byte wire format.
    pub fn deserialize(data: &[u8; 80]) -> Self {
        Self {
            version: i32::from_le_bytes(data[0..4].try_into().unwrap()),
            prev_block: data[4..36].try_into().unwrap(),
            merkle_root: data[36..68].try_into().unwrap(),
            timestamp: u32::from_le_bytes(data[68..72].try_into().unwrap()),
            bits: u32::from_le_bytes(data[72..76].try_into().unwrap()),
            nonce: u32::from_le_bytes(data[76..80].try_into().unwrap()),
        }
    }

    /// Compute the SHA-256d hash of this header (the "block hash").
    /// Result is in internal byte order (little-endian, as stored).
    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        crate::hash::sha256d(&self.serialize())
    }

    /// Compute the block hash and return it in RPC/display byte order (big-endian).
    pub fn hash_display(&self) -> [u8; 32] {
        let mut h = self.hash();
        h.reverse();
        h
    }

    /// Compute the block hash as a hex string in RPC/display byte order.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash_display())
    }

    /// Split the serialized header into the first 64 bytes (for midstate)
    /// and the last 16 bytes (containing nonce).
    #[inline]
    pub fn split_for_midstate(&self) -> ([u8; 64], [u8; 16]) {
        let buf = self.serialize();
        let first: [u8; 64] = buf[..64].try_into().unwrap();
        let last: [u8; 16] = buf[64..].try_into().unwrap();
        (first, last)
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            version: 0x20000000, // BIP 9 version bits
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            bits: 0,
            nonce: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_header() {
        let header = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: hex_to_32(
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            ),
            timestamp: 1231006505, // 0x495fab29
            bits: 0x1d00ffff,
            nonce: 2083236893, // 0x7c2bac1d
        };

        assert_eq!(
            header.hash_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_roundtrip() {
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0xAB; 32],
            merkle_root: [0xCD; 32],
            timestamp: 1700000000,
            bits: 0x17034219,
            nonce: 42,
        };

        let serialized = header.serialize();
        let deserialized = BlockHeader::deserialize(&serialized);
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_midstate_split() {
        let header = BlockHeader::default();
        let (first, last) = header.split_for_midstate();
        let full = header.serialize();
        assert_eq!(&first[..], &full[..64]);
        assert_eq!(&last[..], &full[64..]);
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        bytes.try_into().unwrap()
    }
}
