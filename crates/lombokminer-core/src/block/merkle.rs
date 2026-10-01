// LombokMiner — Merkle tree construction for Bitcoin blocks
//
// Bitcoin uses a binary merkle tree where each non-leaf node is SHA-256d of
// its two children concatenated. If the number of nodes at a level is odd,
// the last node is duplicated.
//
// Optimization: When the extranonce changes during mining, only the coinbase
// hash changes. We cache the right-side branches so only the path from
// coinbase to root needs recomputation.

use crate::hash::sha256d;

/// Compute the merkle root from a list of transaction hashes.
///
/// `tx_hashes[0]` is the coinbase transaction hash.
/// All hashes are in internal byte order (as stored in blocks).
///
/// Returns the 32-byte merkle root.
pub fn merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    assert!(!tx_hashes.is_empty(), "block must have at least one transaction");

    if tx_hashes.len() == 1 {
        return tx_hashes[0];
    }

    let mut level: Vec<[u8; 32]> = tx_hashes.to_vec();

    while level.len() > 1 {
        level = merkle_level(&level);
    }

    level[0]
}

/// Compute one level of the merkle tree by hashing pairs.
fn merkle_level(hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity((hashes.len() + 1) / 2);

    let mut i = 0;
    while i < hashes.len() {
        let left = &hashes[i];
        // If odd number of hashes, duplicate the last one
        let right = if i + 1 < hashes.len() {
            &hashes[i + 1]
        } else {
            &hashes[i]
        };

        next.push(hash_pair(left, right));
        i += 2;
    }

    next
}

/// SHA-256d(left || right) — hash two 32-byte nodes together.
#[inline]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256d(&combined)
}

/// Precomputed merkle branch for efficient coinbase-only updates.
///
/// When mining, the coinbase transaction changes frequently (extranonce bumps),
/// but all other transactions stay the same. The merkle branch captures the
/// sibling hashes needed to recompute the root from a new coinbase hash.
#[derive(Debug, Clone)]
pub struct MerkleBranch {
    /// Sibling hashes from coinbase leaf to root (bottom-up).
    pub branches: Vec<[u8; 32]>,
}

impl MerkleBranch {
    /// Build a merkle branch for the coinbase (index 0) from a list of tx hashes.
    pub fn from_tx_hashes(tx_hashes: &[[u8; 32]]) -> Self {
        if tx_hashes.len() <= 1 {
            return Self { branches: vec![] };
        }

        let mut branches = Vec::new();
        let mut level: Vec<[u8; 32]> = tx_hashes.to_vec();

        while level.len() > 1 {
            // The sibling of index 0 is index 1 (or index 0 if duplicated)
            let sibling = if level.len() > 1 { level[1] } else { level[0] };
            branches.push(sibling);

            level = merkle_level(&level);
        }

        Self { branches }
    }

    /// Compute the merkle root given a new coinbase hash and this branch.
    pub fn compute_root(&self, coinbase_hash: &[u8; 32]) -> [u8; 32] {
        let mut current = *coinbase_hash;

        for sibling in &self.branches {
            // Coinbase is always at index 0, so it's always the left child
            current = hash_pair(&current, sibling);
        }

        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256d;

    #[test]
    fn test_single_tx() {
        let tx = sha256d(b"coinbase");
        assert_eq!(merkle_root(&[tx]), tx);
    }

    #[test]
    fn test_two_tx() {
        let tx0 = sha256d(b"coinbase");
        let tx1 = sha256d(b"tx1");

        let root = merkle_root(&[tx0, tx1]);
        let expected = hash_pair(&tx0, &tx1);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_tx_odd() {
        // With 3 txs, the third tx is duplicated at level 0
        let tx0 = sha256d(b"coinbase");
        let tx1 = sha256d(b"tx1");
        let tx2 = sha256d(b"tx2");

        let root = merkle_root(&[tx0, tx1, tx2]);

        let h01 = hash_pair(&tx0, &tx1);
        let h22 = hash_pair(&tx2, &tx2); // tx2 paired with itself
        let expected = hash_pair(&h01, &h22);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_branch_single() {
        let tx = sha256d(b"coinbase");
        let branch = MerkleBranch::from_tx_hashes(&[tx]);
        assert_eq!(branch.compute_root(&tx), tx);
    }

    #[test]
    fn test_merkle_branch_consistency() {
        // Verify branch-based root matches full tree computation
        let txs: Vec<[u8; 32]> = (0..7)
            .map(|i| sha256d(format!("tx{i}").as_bytes()))
            .collect();

        let full_root = merkle_root(&txs);
        let branch = MerkleBranch::from_tx_hashes(&txs);
        let branch_root = branch.compute_root(&txs[0]);

        assert_eq!(full_root, branch_root);
    }

    #[test]
    fn test_merkle_branch_coinbase_update() {
        // Simulate mining: coinbase changes, other txs stay the same
        let tx1 = sha256d(b"tx1");
        let tx2 = sha256d(b"tx2");
        let tx3 = sha256d(b"tx3");

        let coinbase_v1 = sha256d(b"coinbase_extranonce_1");
        let coinbase_v2 = sha256d(b"coinbase_extranonce_2");

        let txs_v1 = [coinbase_v1, tx1, tx2, tx3];
        let txs_v2 = [coinbase_v2, tx1, tx2, tx3];

        // Build branch from v1, use it for v2
        let branch = MerkleBranch::from_tx_hashes(&txs_v1);
        let root_via_branch = branch.compute_root(&coinbase_v2);
        let root_full = merkle_root(&txs_v2);

        assert_eq!(root_via_branch, root_full);
    }
}
