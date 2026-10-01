// LombokMiner — getblocktemplate RPC client
//
// For solo mining, the miner communicates with a local bitcoind via
// the getblocktemplate JSON-RPC call (BIP 22/23).
//
// Flow:
//   1. Call getblocktemplate with {"rules":["segwit"]} to get block template
//   2. Build coinbase + merkle tree, iterate nonces
//   3. On block found, call submitblock with the full serialized block

use serde::{Deserialize, Serialize};

/// getblocktemplate response — the block template from bitcoind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    /// Block version
    pub version: u32,
    /// Previous block hash (hex, big-endian display order)
    #[serde(rename = "previousblockhash")]
    pub prev_block_hash: String,
    /// List of transactions to include
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase auxiliary data
    #[serde(default)]
    pub coinbaseaux: serde_json::Value,
    /// Maximum coinbase value in satoshis
    #[serde(rename = "coinbasevalue")]
    pub coinbase_value: u64,
    /// Target hash (hex)
    pub target: String,
    /// Minimum timestamp
    #[serde(rename = "mintime")]
    pub min_time: u64,
    /// Mutable fields list
    pub mutable: Vec<String>,
    /// Nonce range (hex)
    #[serde(rename = "noncerange")]
    pub nonce_range: String,
    /// Sigop limit
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u64,
    /// Size limit
    #[serde(rename = "sizelimit")]
    pub size_limit: u64,
    /// Weight limit
    #[serde(rename = "weightlimit", default)]
    pub weight_limit: u64,
    /// Current time
    #[serde(rename = "curtime")]
    pub cur_time: u64,
    /// Compact target (nBits, hex)
    pub bits: String,
    /// Next block height
    pub height: u64,
    /// Default witness commitment (hex, for SegWit)
    #[serde(rename = "default_witness_commitment", default)]
    pub witness_commitment: Option<String>,
    /// Long poll ID
    #[serde(rename = "longpollid", default)]
    pub longpoll_id: Option<String>,
}

/// A transaction in the block template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateTransaction {
    /// Raw transaction hex
    pub data: String,
    /// Transaction ID
    pub txid: String,
    /// Transaction hash (including witness)
    pub hash: String,
    /// Dependencies (indices of txs that must come before this one)
    #[serde(default)]
    pub depends: Vec<u64>,
    /// Fee in satoshis
    #[serde(default)]
    pub fee: i64,
    /// Sigop cost
    #[serde(default)]
    pub sigops: u64,
    /// Transaction weight
    #[serde(default)]
    pub weight: u64,
}

impl BlockTemplate {
    /// Parse the `bits` field (hex string) into a u32 nBits value.
    pub fn nbits(&self) -> u32 {
        u32::from_str_radix(&self.bits, 16).unwrap_or(0)
    }

    /// Parse the `previousblockhash` field into 32 bytes (internal byte order).
    pub fn prev_block_bytes(&self) -> [u8; 32] {
        let mut bytes = hex::decode(&self.prev_block_hash).unwrap_or_else(|_| vec![0u8; 32]);
        // Display order is big-endian; internal order is reversed
        bytes.reverse();
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    }

    /// Collect all transaction hashes for the merkle tree (internal byte order).
    /// The coinbase hash is NOT included — it's built separately by the miner.
    pub fn tx_hashes(&self) -> Vec<[u8; 32]> {
        self.transactions
            .iter()
            .filter_map(|tx| {
                let bytes = hex::decode(&tx.txid).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                // txid from RPC is in display order (big-endian), reverse to internal
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr.reverse();
                Some(arr)
            })
            .collect()
    }

    /// Total fees from all transactions.
    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee.max(0) as u64).sum()
    }
}

/// JSON-RPC request for bitcoind.
#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: Vec<serde_json::Value>,
}

/// JSON-RPC response from bitcoind.
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// getblocktemplate RPC client errors.
#[derive(Debug)]
pub enum GbtError {
    /// HTTP/network error
    Network(String),
    /// JSON parsing error
    Json(String),
    /// RPC error returned by bitcoind
    Rpc { code: i64, message: String },
    /// Invalid response format
    InvalidResponse(String),
}

impl std::fmt::Display for GbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
            Self::InvalidResponse(e) => write!(f, "invalid response: {e}"),
        }
    }
}

impl std::error::Error for GbtError {}

/// Configuration for the GBT RPC client.
#[derive(Debug, Clone)]
pub struct GbtConfig {
    /// bitcoind RPC URL (e.g., "http://127.0.0.1:8332")
    pub url: String,
    /// RPC username
    pub user: String,
    /// RPC password
    pub password: String,
}

/// Build a getblocktemplate RPC request body.
pub fn build_gbt_request(request_id: u64) -> Vec<u8> {
    let req = RpcRequest {
        jsonrpc: "1.0",
        id: request_id,
        method: "getblocktemplate",
        params: vec![serde_json::json!({"rules": ["segwit"]})],
    };
    serde_json::to_vec(&req).expect("serialize GBT request")
}

/// Build a submitblock RPC request body.
pub fn build_submit_block_request(request_id: u64, block_hex: &str) -> Vec<u8> {
    let req = RpcRequest {
        jsonrpc: "1.0",
        id: request_id,
        method: "submitblock",
        params: vec![serde_json::Value::String(block_hex.to_string())],
    };
    serde_json::to_vec(&req).expect("serialize submitblock request")
}

/// Parse a getblocktemplate response body.
pub fn parse_gbt_response(body: &[u8]) -> Result<BlockTemplate, GbtError> {
    let resp: RpcResponse =
        serde_json::from_slice(body).map_err(|e| GbtError::Json(e.to_string()))?;

    if let Some(err) = resp.error {
        return Err(GbtError::Rpc {
            code: err.code,
            message: err.message,
        });
    }

    let result = resp
        .result
        .ok_or_else(|| GbtError::InvalidResponse("missing result field".into()))?;

    serde_json::from_value(result).map_err(|e| GbtError::Json(e.to_string()))
}

/// Parse a submitblock response body.
pub fn parse_submit_response(body: &[u8]) -> Result<(), GbtError> {
    let resp: RpcResponse =
        serde_json::from_slice(body).map_err(|e| GbtError::Json(e.to_string()))?;

    if let Some(err) = resp.error {
        return Err(GbtError::Rpc {
            code: err.code,
            message: err.message,
        });
    }

    // submitblock returns null on success, or a string reason on failure
    match resp.result {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(reason)) => {
            Err(GbtError::Rpc { code: -1, message: reason })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_gbt_request() {
        let body = build_gbt_request(1);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["method"], "getblocktemplate");
        assert_eq!(json["params"][0]["rules"][0], "segwit");
    }

    #[test]
    fn test_build_submit_request() {
        let body = build_submit_block_request(2, "0100000000000000...");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["method"], "submitblock");
    }

    #[test]
    fn test_parse_gbt_response() {
        let response_json = serde_json::json!({
            "id": 1,
            "result": {
                "version": 536870912_u32,
                "previousblockhash": "0000000000000000000a1b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6",
                "transactions": [],
                "coinbaseaux": {},
                "coinbasevalue": 312500000_u64,
                "target": "0000000000000000000a1b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6",
                "mintime": 1700000000_u64,
                "mutable": ["time", "transactions", "prevblock"],
                "noncerange": "00000000ffffffff",
                "sigoplimit": 80000_u64,
                "sizelimit": 4000000_u64,
                "weightlimit": 4000000_u64,
                "curtime": 1700000100_u64,
                "bits": "17034219",
                "height": 800000_u64
            },
            "error": null
        });

        let body = serde_json::to_vec(&response_json).unwrap();
        let template = parse_gbt_response(&body).unwrap();

        assert_eq!(template.version, 536870912);
        assert_eq!(template.coinbase_value, 312500000);
        assert_eq!(template.height, 800000);
        assert_eq!(template.bits, "17034219");
        assert_eq!(template.nbits(), 0x17034219);
    }

    #[test]
    fn test_parse_rpc_error() {
        let response_json = serde_json::json!({
            "id": 1,
            "result": null,
            "error": {
                "code": -8,
                "message": "Block decode failed"
            }
        });

        let body = serde_json::to_vec(&response_json).unwrap();
        let err = parse_gbt_response(&body).unwrap_err();
        match err {
            GbtError::Rpc { code, message } => {
                assert_eq!(code, -8);
                assert_eq!(message, "Block decode failed");
            }
            _ => panic!("expected RPC error"),
        }
    }

    #[test]
    fn test_template_prev_block_bytes() {
        let template = BlockTemplate {
            version: 1,
            prev_block_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".into(),
            transactions: vec![],
            coinbaseaux: serde_json::Value::Null,
            coinbase_value: 5000000000,
            target: "00".into(),
            min_time: 0,
            mutable: vec![],
            nonce_range: "00000000ffffffff".into(),
            sigop_limit: 80000,
            size_limit: 1000000,
            weight_limit: 4000000,
            cur_time: 0,
            bits: "1d00ffff".into(),
            height: 0,
            witness_commitment: None,
            longpoll_id: None,
        };

        let bytes = template.prev_block_bytes();
        // Internal byte order = reverse of display order
        assert_eq!(bytes[31], 0x00);  // display order starts with 0x00...
        assert_eq!(bytes[0], 0x6f);   // last byte of display = first byte internal
    }
}
