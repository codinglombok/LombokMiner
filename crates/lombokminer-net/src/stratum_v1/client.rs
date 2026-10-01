// LombokMiner — Stratum V1 Client (JSON-RPC over TCP)
//
// Implements the legacy Stratum V1 protocol for backward compatibility
// with pools that don't support Stratum V2 yet.
//
// Protocol flow:
//   1. mining.subscribe    → server assigns extranonce1 + extranonce2_size
//   2. mining.authorize    → authenticate worker
//   3. mining.notify       ← server pushes new jobs
//   4. mining.submit       → miner submits shares
//   5. mining.set_difficulty ← server adjusts share difficulty

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stratum V1 JSON-RPC request.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub id: u64,
    pub method: String,
    pub params: Vec<Value>,
}

impl JsonRpcRequest {
    /// Serialize to JSON line (newline-delimited).
    pub fn to_line(&self) -> String {
        let mut json = serde_json::to_string(self).expect("serialize JSON-RPC request");
        json.push('\n');
        json
    }
}

/// Stratum V1 JSON-RPC response.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    pub id: Option<u64>,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

/// Stratum V1 server notification (no id field).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcNotification {
    pub method: String,
    pub params: Vec<Value>,
}

/// Parsed Stratum V1 message (either response or notification).
#[derive(Debug, Clone)]
pub enum V1Message {
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

/// Parse a JSON line into a V1 message.
pub fn parse_v1_message(line: &str) -> Result<V1Message, V1Error> {
    let value: Value = serde_json::from_str(line).map_err(|e| V1Error::JsonParse(e.to_string()))?;

    if value.get("method").is_some() && value.get("id").is_none() {
        // It's a notification
        let notif: JsonRpcNotification =
            serde_json::from_value(value).map_err(|e| V1Error::JsonParse(e.to_string()))?;
        Ok(V1Message::Notification(notif))
    } else {
        let resp: JsonRpcResponse =
            serde_json::from_value(value).map_err(|e| V1Error::JsonParse(e.to_string()))?;
        Ok(V1Message::Response(resp))
    }
}

// ─── Request Builders ────────────────────────────────────────────────────────

/// Build a `mining.subscribe` request.
pub fn subscribe_request(id: u64, user_agent: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        id,
        method: "mining.subscribe".to_string(),
        params: vec![Value::String(user_agent.to_string())],
    }
}

/// Build a `mining.authorize` request.
pub fn authorize_request(id: u64, username: &str, password: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        id,
        method: "mining.authorize".to_string(),
        params: vec![
            Value::String(username.to_string()),
            Value::String(password.to_string()),
        ],
    }
}

/// Build a `mining.submit` request.
pub fn submit_request(
    id: u64,
    worker: &str,
    job_id: &str,
    extranonce2: &str,
    ntime: &str,
    nonce: &str,
) -> JsonRpcRequest {
    JsonRpcRequest {
        id,
        method: "mining.submit".to_string(),
        params: vec![
            Value::String(worker.to_string()),
            Value::String(job_id.to_string()),
            Value::String(extranonce2.to_string()),
            Value::String(ntime.to_string()),
            Value::String(nonce.to_string()),
        ],
    }
}

// ─── Response Parsers ────────────────────────────────────────────────────────

/// Parsed `mining.subscribe` response.
#[derive(Debug, Clone)]
pub struct SubscribeResult {
    /// Subscriptions (usually mining.notify + mining.set_difficulty)
    pub subscriptions: Vec<(String, String)>,
    /// Extranonce1 assigned by pool (hex)
    pub extranonce1: String,
    /// Extranonce2 size in bytes
    pub extranonce2_size: usize,
}

/// Parse a `mining.subscribe` response.
pub fn parse_subscribe_result(result: &Value) -> Result<SubscribeResult, V1Error> {
    let arr = result.as_array().ok_or(V1Error::InvalidResponse)?;
    if arr.len() < 3 {
        return Err(V1Error::InvalidResponse);
    }

    let subscriptions = if let Some(subs) = arr[0].as_array() {
        subs.iter()
            .filter_map(|s| {
                let pair = s.as_array()?;
                Some((
                    pair.first()?.as_str()?.to_string(),
                    pair.get(1)?.as_str()?.to_string(),
                ))
            })
            .collect()
    } else {
        vec![]
    };

    let extranonce1 = arr[1]
        .as_str()
        .ok_or(V1Error::InvalidResponse)?
        .to_string();

    let extranonce2_size = arr[2]
        .as_u64()
        .ok_or(V1Error::InvalidResponse)? as usize;

    Ok(SubscribeResult {
        subscriptions,
        extranonce1,
        extranonce2_size,
    })
}

/// Parsed `mining.notify` notification parameters.
#[derive(Debug, Clone)]
pub struct MiningNotify {
    /// Job ID
    pub job_id: String,
    /// Previous block hash (hex, 32 bytes)
    pub prev_hash: String,
    /// Coinbase part 1 (hex)
    pub coinbase1: String,
    /// Coinbase part 2 (hex)
    pub coinbase2: String,
    /// Merkle branches (list of hex hashes)
    pub merkle_branches: Vec<String>,
    /// Block version (hex)
    pub version: String,
    /// nBits (hex)
    pub nbits: String,
    /// nTime (hex)
    pub ntime: String,
    /// Whether to clean all previous jobs
    pub clean_jobs: bool,
}

/// Parse a `mining.notify` notification.
pub fn parse_mining_notify(params: &[Value]) -> Result<MiningNotify, V1Error> {
    if params.len() < 9 {
        return Err(V1Error::InvalidResponse);
    }

    let s = |i: usize| -> Result<String, V1Error> {
        params[i]
            .as_str()
            .ok_or(V1Error::InvalidResponse)
            .map(|s| s.to_string())
    };

    let merkle_branches = params[4]
        .as_array()
        .ok_or(V1Error::InvalidResponse)?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(MiningNotify {
        job_id: s(0)?,
        prev_hash: s(1)?,
        coinbase1: s(2)?,
        coinbase2: s(3)?,
        merkle_branches,
        version: s(5)?,
        nbits: s(6)?,
        ntime: s(7)?,
        clean_jobs: params[8].as_bool().unwrap_or(false),
    })
}

/// Parsed `mining.set_difficulty` notification.
#[derive(Debug, Clone)]
pub struct SetDifficulty {
    pub difficulty: f64,
}

pub fn parse_set_difficulty(params: &[Value]) -> Result<SetDifficulty, V1Error> {
    if params.is_empty() {
        return Err(V1Error::InvalidResponse);
    }
    let difficulty = params[0]
        .as_f64()
        .ok_or(V1Error::InvalidResponse)?;
    Ok(SetDifficulty { difficulty })
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum V1Error {
    JsonParse(String),
    InvalidResponse,
    ServerError(String),
    ConnectionClosed,
}

impl std::fmt::Display for V1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonParse(e) => write!(f, "JSON parse error: {e}"),
            Self::InvalidResponse => write!(f, "invalid server response"),
            Self::ServerError(e) => write!(f, "server error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for V1Error {}

/// Line-based decoder for V1 JSON-RPC (newline-delimited JSON).
#[derive(Debug)]
pub struct LineDecoder {
    buffer: String,
}

impl LineDecoder {
    pub fn new() -> Self {
        Self {
            buffer: String::with_capacity(4096),
        }
    }

    /// Feed bytes from the network.
    pub fn feed(&mut self, data: &str) {
        self.buffer.push_str(data);
    }

    /// Try to decode the next complete line.
    pub fn decode_line(&mut self) -> Option<String> {
        if let Some(pos) = self.buffer.find('\n') {
            let line = self.buffer[..pos].trim().to_string();
            self.buffer = self.buffer[pos + 1..].to_string();
            if line.is_empty() {
                return self.decode_line(); // skip empty lines
            }
            Some(line)
        } else {
            None
        }
    }
}

impl Default for LineDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribe_request() {
        let req = subscribe_request(1, "LombokMiner/0.1.0");
        let json = req.to_line();
        assert!(json.contains("mining.subscribe"));
        assert!(json.contains("LombokMiner/0.1.0"));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn test_authorize_request() {
        let req = authorize_request(2, "worker1", "x");
        let json = req.to_line();
        assert!(json.contains("mining.authorize"));
        assert!(json.contains("worker1"));
    }

    #[test]
    fn test_submit_request() {
        let req = submit_request(3, "worker1", "4f", "00000001", "504e86ed", "b2957c02");
        let json = req.to_line();
        assert!(json.contains("mining.submit"));
    }

    #[test]
    fn test_parse_subscribe_result() {
        let result: Value = serde_json::from_str(
            r#"[
                [["mining.set_difficulty","1"],["mining.notify","1"]],
                "08000002",
                4
            ]"#,
        )
        .unwrap();

        let sub = parse_subscribe_result(&result).unwrap();
        assert_eq!(sub.extranonce1, "08000002");
        assert_eq!(sub.extranonce2_size, 4);
        assert_eq!(sub.subscriptions.len(), 2);
    }

    #[test]
    fn test_parse_mining_notify() {
        let params: Vec<Value> = serde_json::from_str(
            r#"[
                "bf",
                "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000",
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",
                "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000",
                [],
                "00000002",
                "1c2ac4af",
                "504e86b9",
                false
            ]"#,
        )
        .unwrap();

        let notify = parse_mining_notify(&params).unwrap();
        assert_eq!(notify.job_id, "bf");
        assert!(!notify.clean_jobs);
        assert_eq!(notify.version, "00000002");
    }

    #[test]
    fn test_parse_set_difficulty() {
        let params: Vec<Value> = serde_json::from_str("[32768]").unwrap();
        let diff = parse_set_difficulty(&params).unwrap();
        assert_eq!(diff.difficulty, 32768.0);
    }

    #[test]
    fn test_line_decoder() {
        let mut decoder = LineDecoder::new();
        decoder.feed("{\"id\":1}\n{\"id\":");
        assert_eq!(decoder.decode_line(), Some("{\"id\":1}".to_string()));
        assert_eq!(decoder.decode_line(), None);

        decoder.feed("2}\n");
        assert_eq!(decoder.decode_line(), Some("{\"id\":2}".to_string()));
    }

    #[test]
    fn test_parse_v1_response() {
        let line = r#"{"id":1,"result":true,"error":null}"#;
        let msg = parse_v1_message(line).unwrap();
        match msg {
            V1Message::Response(r) => {
                assert_eq!(r.id, Some(1));
                assert_eq!(r.result, Some(Value::Bool(true)));
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn test_parse_v1_notification() {
        let line = r#"{"method":"mining.set_difficulty","params":[65536]}"#;
        let msg = parse_v1_message(line).unwrap();
        match msg {
            V1Message::Notification(n) => {
                assert_eq!(n.method, "mining.set_difficulty");
            }
            _ => panic!("expected notification"),
        }
    }
}
