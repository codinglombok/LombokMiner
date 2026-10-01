// LombokMiner — Coinbase transaction builder
//
// The coinbase transaction is the first transaction in every block.
// It has no real inputs — instead, it contains the block height (BIP 34),
// an arbitrary "coinbase message", and extranonce fields that miners iterate.
//
// Structure:
//   version (4 bytes) | vin_count (1) | prev_hash (32 zeros) | prev_index (0xFFFFFFFF)
//   | script_len | [height_push] [extranonce1] [extranonce2] [message] |
//   sequence (0xFFFFFFFF) | vout_count (1+) | value | scriptPubKey | locktime (4)

use crate::hash::sha256d;

/// Coinbase transaction builder for solo mining.
#[derive(Debug, Clone)]
pub struct CoinbaseBuilder {
    /// Block height (BIP 34 — encoded in scriptSig)
    pub block_height: u32,
    /// Block reward in satoshis (subsidy + fees)
    pub value: u64,
    /// Output scriptPubKey (the payout script, e.g., P2WPKH)
    pub output_script: Vec<u8>,
    /// Arbitrary coinbase message (e.g., "/LombokMiner/")
    pub message: Vec<u8>,
    /// Extranonce1 (pool-assigned for pool mining, miner-chosen for solo)
    pub extranonce1: Vec<u8>,
    /// Extranonce2 size in bytes (iterated by the miner)
    pub extranonce2_size: usize,
    /// Witness commitment (for SegWit blocks)
    pub witness_commitment: Option<Vec<u8>>,
}

impl CoinbaseBuilder {
    /// Create a new coinbase builder for solo mining.
    pub fn new_solo(block_height: u32, value: u64, output_script: Vec<u8>) -> Self {
        Self {
            block_height,
            value,
            output_script,
            message: b"/LombokMiner/".to_vec(),
            extranonce1: vec![0u8; 4],
            extranonce2_size: 4,
            witness_commitment: None,
        }
    }

    /// Build the coinbase transaction with the given extranonce2.
    ///
    /// Returns the serialized transaction bytes.
    pub fn build(&self, extranonce2: &[u8]) -> Vec<u8> {
        assert_eq!(
            extranonce2.len(),
            self.extranonce2_size,
            "extranonce2 size mismatch"
        );

        let mut tx = Vec::with_capacity(256);

        // --- Version (4 bytes, little-endian) ---
        tx.extend_from_slice(&2i32.to_le_bytes()); // version 2 (BIP 34)

        // --- SegWit marker + flag ---
        // For witness transactions: marker=0x00, flag=0x01
        let has_witness = self.witness_commitment.is_some();
        if has_witness {
            tx.push(0x00); // marker
            tx.push(0x01); // flag
        }

        // --- Input count ---
        tx.push(1); // coinbase always has exactly 1 input

        // --- Input: prev_hash (32 zero bytes) ---
        tx.extend_from_slice(&[0u8; 32]);

        // --- Input: prev_index (0xFFFFFFFF) ---
        tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // --- Input: scriptSig ---
        let scriptsig = self.build_scriptsig(extranonce2);
        encode_varint(&mut tx, scriptsig.len() as u64);
        tx.extend_from_slice(&scriptsig);

        // --- Input: sequence ---
        tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // --- Output count ---
        let output_count = if has_witness { 2u8 } else { 1u8 };
        tx.push(output_count);

        // --- Output 0: miner reward ---
        tx.extend_from_slice(&self.value.to_le_bytes()); // value in satoshis
        encode_varint(&mut tx, self.output_script.len() as u64);
        tx.extend_from_slice(&self.output_script);

        // --- Output 1: witness commitment (if SegWit) ---
        if let Some(ref commitment) = self.witness_commitment {
            tx.extend_from_slice(&0u64.to_le_bytes()); // value = 0
            encode_varint(&mut tx, commitment.len() as u64);
            tx.extend_from_slice(commitment);
        }

        // --- Witness data (for coinbase, it's the witness reserved value) ---
        if has_witness {
            tx.push(1); // number of witness items
            tx.push(32); // length of witness item
            tx.extend_from_slice(&[0u8; 32]); // witness reserved value (32 zero bytes)
        }

        // --- Locktime ---
        tx.extend_from_slice(&0u32.to_le_bytes());

        tx
    }

    /// Build the scriptSig for the coinbase input.
    fn build_scriptsig(&self, extranonce2: &[u8]) -> Vec<u8> {
        let mut script = Vec::with_capacity(100);

        // BIP 34: block height push
        push_block_height(&mut script, self.block_height);

        // Extranonce1 + Extranonce2
        script.extend_from_slice(&self.extranonce1);
        script.extend_from_slice(extranonce2);

        // Coinbase message
        script.extend_from_slice(&self.message);

        script
    }

    /// Build the coinbase transaction and return its txid (SHA-256d hash).
    /// The txid is used in the merkle tree.
    pub fn build_txid(&self, extranonce2: &[u8]) -> [u8; 32] {
        let tx = self.build(extranonce2);

        if self.witness_commitment.is_some() {
            // For SegWit: txid is hash of the transaction WITHOUT witness data
            // We need to strip the marker, flag, and witness sections
            let stripped = strip_witness(&tx);
            sha256d(&stripped)
        } else {
            sha256d(&tx)
        }
    }

    /// Split the coinbase template into parts for Stratum-style mining:
    /// (coinbase1, coinbase2) where the full coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2
    pub fn split_for_stratum(&self) -> (Vec<u8>, Vec<u8>) {
        // Build with dummy extranonce2 to find the split point
        let dummy_en2 = vec![0u8; self.extranonce2_size];
        let full = self.build(&dummy_en2);

        // The extranonce fields are inside the scriptSig.
        // We need to find their position.
        // For simplicity, we split at the known offsets based on our construction.

        // This is a simplified split — in production, track byte offsets during build()
        let en_start = self.find_extranonce_offset();
        let en_end = en_start + self.extranonce1.len() + self.extranonce2_size;

        let coinbase1 = full[..en_start].to_vec();
        let coinbase2 = full[en_end..].to_vec();

        (coinbase1, coinbase2)
    }

    fn find_extranonce_offset(&self) -> usize {
        // Version(4) + [marker(1) + flag(1) if witness] + input_count(1)
        // + prev_hash(32) + prev_index(4) + scriptsig_len(varint)
        // + height_push(variable) = offset to extranonce1

        let mut offset = 4; // version
        if self.witness_commitment.is_some() {
            offset += 2; // marker + flag
        }
        offset += 1; // input count
        offset += 32; // prev hash
        offset += 4; // prev index

        // scriptSig length as varint
        let scriptsig_len = self.build_scriptsig(&vec![0u8; self.extranonce2_size]).len();
        offset += varint_size(scriptsig_len as u64);

        // height push bytes
        offset += height_push_len(self.block_height);

        offset
    }
}

/// Encode a variable-length integer (Bitcoin varint / CompactSize).
fn encode_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0xFD {
        buf.push(value as u8);
    } else if value <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Size of a varint encoding for a given value.
fn varint_size(value: u64) -> usize {
    if value < 0xFD {
        1
    } else if value <= 0xFFFF {
        3
    } else if value <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

/// Push block height into scriptSig per BIP 34.
fn push_block_height(script: &mut Vec<u8>, height: u32) {
    if height == 0 {
        script.push(1); // push 1 byte
        script.push(0);
    } else if height <= 0xFF {
        script.push(2);
        script.push(height as u8);
        script.push(0); // sign byte
    } else if height <= 0xFFFF {
        script.push(3);
        script.extend_from_slice(&(height as u16).to_le_bytes());
        script.push(0);
    } else if height <= 0xFF_FFFF {
        script.push(3);
        script.push((height & 0xFF) as u8);
        script.push(((height >> 8) & 0xFF) as u8);
        script.push(((height >> 16) & 0xFF) as u8);
    } else {
        script.push(4);
        script.extend_from_slice(&height.to_le_bytes());
    }
}

/// Length of the BIP 34 height push for a given height.
fn height_push_len(height: u32) -> usize {
    if height == 0 {
        2
    } else if height <= 0xFF {
        3
    } else if height <= 0xFFFF {
        4
    } else if height <= 0xFF_FFFF {
        4
    } else {
        5
    }
}

/// Strip witness data from a serialized transaction to compute txid.
fn strip_witness(tx: &[u8]) -> Vec<u8> {
    // Version (4) + marker (1) + flag (1) = 6 bytes before inputs
    // We need to remove marker+flag and witness section
    let mut stripped = Vec::with_capacity(tx.len());
    stripped.extend_from_slice(&tx[..4]); // version

    // Skip marker (0x00) and flag (0x01) at bytes 4-5
    let rest = &tx[6..];

    // Copy everything up to witness data (before locktime)
    // We need to parse inputs and outputs to find where witness starts
    // For simplicity in coinbase (1 input, known structure), we know:
    // locktime is always the last 4 bytes
    // witness is between the last output and locktime

    // Find the end of outputs by parsing from after marker/flag
    let mut pos = 0;

    // Input count
    let (input_count, consumed) = read_varint(&rest[pos..]);
    stripped.push(input_count as u8); // we know coinbase has 1 input
    pos += consumed;

    // For each input
    for _ in 0..input_count {
        // prev_hash (32) + prev_index (4)
        stripped.extend_from_slice(&rest[pos..pos + 36]);
        pos += 36;

        // scriptSig
        let (script_len, consumed) = read_varint(&rest[pos..]);
        let varint_bytes = &rest[pos..pos + consumed];
        stripped.extend_from_slice(varint_bytes);
        pos += consumed;

        stripped.extend_from_slice(&rest[pos..pos + script_len as usize]);
        pos += script_len as usize;

        // sequence (4)
        stripped.extend_from_slice(&rest[pos..pos + 4]);
        pos += 4;
    }

    // Output count
    let (output_count, consumed) = read_varint(&rest[pos..]);
    let varint_bytes = &rest[pos..pos + consumed];
    stripped.extend_from_slice(varint_bytes);
    pos += consumed;

    // For each output
    for _ in 0..output_count {
        // value (8)
        stripped.extend_from_slice(&rest[pos..pos + 8]);
        pos += 8;

        // scriptPubKey
        let (script_len, consumed) = read_varint(&rest[pos..]);
        let varint_bytes = &rest[pos..pos + consumed];
        stripped.extend_from_slice(varint_bytes);
        pos += consumed;

        stripped.extend_from_slice(&rest[pos..pos + script_len as usize]);
        pos += script_len as usize;
    }

    // Skip witness data, add locktime (last 4 bytes of original tx)
    stripped.extend_from_slice(&tx[tx.len() - 4..]);

    stripped
}

/// Read a Bitcoin varint from a byte slice. Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> (u64, usize) {
    match data[0] {
        0..=0xFC => (data[0] as u64, 1),
        0xFD => {
            let v = u16::from_le_bytes([data[1], data[2]]);
            (v as u64, 3)
        }
        0xFE => {
            let v = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (v as u64, 5)
        }
        0xFF => {
            let v = u64::from_le_bytes(data[1..9].try_into().unwrap());
            (v, 9)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_build() {
        // Simple P2PKH output script (OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
        let output_script = hex::decode(
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
        ).unwrap();

        let builder = CoinbaseBuilder::new_solo(800_000, 312_500_000, output_script);
        let extranonce2 = [0u8; 4];
        let tx = builder.build(&extranonce2);

        // Should be a valid serialized transaction
        assert!(tx.len() > 80);

        // First 4 bytes = version = 2
        assert_eq!(&tx[..4], &2i32.to_le_bytes());
    }

    #[test]
    fn test_coinbase_txid_deterministic() {
        let output_script = vec![0x51]; // OP_TRUE (for testing)
        let builder = CoinbaseBuilder::new_solo(100, 5_000_000_000, output_script);

        let txid1 = builder.build_txid(&[0u8; 4]);
        let txid2 = builder.build_txid(&[0u8; 4]);
        assert_eq!(txid1, txid2);

        // Different extranonce2 = different txid
        let txid3 = builder.build_txid(&[1u8; 4]);
        assert_ne!(txid1, txid3);
    }

    #[test]
    fn test_height_encoding() {
        let mut script = Vec::new();
        push_block_height(&mut script, 500_000);
        // Height 500000 = 0x07A120 (3 bytes)
        assert_eq!(script[0], 3); // push 3 bytes
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        encode_varint(&mut buf, 252);
        assert_eq!(buf, vec![252]);

        buf.clear();
        encode_varint(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 253, 0]);
    }
}
