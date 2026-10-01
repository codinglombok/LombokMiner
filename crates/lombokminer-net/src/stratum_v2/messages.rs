// LombokMiner — Stratum V2 Mining Protocol Messages
//
// Implements the core Mining Protocol sub-protocol of Stratum V2.
// Message types are defined in the SV2 spec:
// https://github.com/stratum-mining/sv2-spec

use serde::{Deserialize, Serialize};

// ─── Message Type Constants ──────────────────────────────────────────────────

/// SetupConnection (client → server)
pub const MSG_SETUP_CONNECTION: u8 = 0x00;
/// SetupConnection.Success (server → client)
pub const MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
/// SetupConnection.Error (server → client)
pub const MSG_SETUP_CONNECTION_ERROR: u8 = 0x02;

/// OpenStandardMiningChannel (client → server)
pub const MSG_OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
/// OpenStandardMiningChannel.Success (server → client)
pub const MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;

/// NewMiningJob (server → client)
pub const MSG_NEW_MINING_JOB: u8 = 0x1e;
/// NewExtendedMiningJob (server → client)
pub const MSG_NEW_EXTENDED_MINING_JOB: u8 = 0x1f;

/// SetNewPrevHash (server → client)
pub const MSG_SET_NEW_PREV_HASH: u8 = 0x20;

/// SubmitSharesStandard (client → server)
pub const MSG_SUBMIT_SHARES_STANDARD: u8 = 0x1a;
/// SubmitSharesExtended (client → server)
pub const MSG_SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
/// SubmitShares.Success (server → client)
pub const MSG_SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
/// SubmitShares.Error (server → client)
pub const MSG_SUBMIT_SHARES_ERROR: u8 = 0x1d;

/// SetTarget (server → client)
pub const MSG_SET_TARGET: u8 = 0x21;

/// Reconnect (server → client)
pub const MSG_RECONNECT: u8 = 0x25;

// ─── Message Structs ─────────────────────────────────────────────────────────

/// SetupConnection request from miner to pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnection {
    /// Protocol version (currently 2)
    pub protocol: u16,
    /// Minimum protocol version supported
    pub min_version: u16,
    /// Maximum protocol version supported
    pub max_version: u16,
    /// Feature flags (bit field)
    pub flags: u32,
    /// Endpoint host
    pub endpoint_host: String,
    /// Endpoint port
    pub endpoint_port: u16,
    /// Vendor name
    pub vendor: String,
    /// Hardware version
    pub hardware_version: String,
    /// Firmware version
    pub firmware: String,
    /// Device ID
    pub device_id: String,
}

impl SetupConnection {
    pub fn new(endpoint_host: &str, endpoint_port: u16) -> Self {
        Self {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: endpoint_host.to_string(),
            endpoint_port,
            vendor: "LombokMiner".to_string(),
            hardware_version: "1.0".to_string(),
            firmware: env!("CARGO_PKG_VERSION").to_string(),
            device_id: String::new(),
        }
    }

    /// Serialize to SV2 binary payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.protocol.to_le_bytes());
        buf.extend_from_slice(&self.min_version.to_le_bytes());
        buf.extend_from_slice(&self.max_version.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        write_sv2_string(&mut buf, &self.endpoint_host);
        buf.extend_from_slice(&self.endpoint_port.to_le_bytes());
        write_sv2_string(&mut buf, &self.vendor);
        write_sv2_string(&mut buf, &self.hardware_version);
        write_sv2_string(&mut buf, &self.firmware);
        write_sv2_string(&mut buf, &self.device_id);
        buf
    }
}

/// SetupConnection.Success response from pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnectionSuccess {
    /// Negotiated protocol version
    pub used_version: u16,
    /// Negotiated feature flags
    pub flags: u32,
}

impl SetupConnectionSuccess {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 6 {
            return Err(MessageError::TooShort);
        }
        Ok(Self {
            used_version: u16::from_le_bytes([data[0], data[1]]),
            flags: u32::from_le_bytes([data[2], data[3], data[4], data[5]]),
        })
    }
}

/// SetupConnection.Error response from pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnectionError {
    pub flags: u32,
    pub error_code: String,
}

impl SetupConnectionError {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 4 {
            return Err(MessageError::TooShort);
        }
        let flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let error_code = read_sv2_string(&data[4..])?;
        Ok(Self { flags, error_code })
    }
}

/// OpenStandardMiningChannel request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStandardMiningChannel {
    /// Client-chosen request ID
    pub request_id: u32,
    /// User identity (worker name)
    pub user_identity: String,
    /// Nominal hashrate of the device (H/s)
    pub nominal_hash_rate: f32,
    /// Maximum target the device can accept
    pub max_target: [u8; 32],
}

impl OpenStandardMiningChannel {
    pub fn new(request_id: u32, user_identity: &str, hashrate: f32) -> Self {
        Self {
            request_id,
            user_identity: user_identity.to_string(),
            nominal_hash_rate: hashrate,
            max_target: [0xFF; 32], // accept any target
        }
    }

    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        write_sv2_string(&mut buf, &self.user_identity);
        buf.extend_from_slice(&self.nominal_hash_rate.to_le_bytes());
        buf.extend_from_slice(&self.max_target);
        buf
    }
}

/// OpenStandardMiningChannel.Success response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStandardMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    /// Initial target for this channel
    pub target: [u8; 32],
    /// Extranonce prefix assigned by pool
    pub extranonce_prefix: Vec<u8>,
    /// Group channel ID
    pub group_channel_id: u32,
}

impl OpenStandardMiningChannelSuccess {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 72 {
            return Err(MessageError::TooShort);
        }
        let request_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let channel_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[8..40]);

        let en_len = data[40] as usize;
        let extranonce_prefix = data[41..41 + en_len].to_vec();

        let gid_offset = 41 + en_len;
        let group_channel_id = if data.len() >= gid_offset + 4 {
            u32::from_le_bytes([
                data[gid_offset],
                data[gid_offset + 1],
                data[gid_offset + 2],
                data[gid_offset + 3],
            ])
        } else {
            0
        };

        Ok(Self {
            request_id,
            channel_id,
            target,
            extranonce_prefix,
            group_channel_id,
        })
    }
}

/// NewMiningJob — pool sends new work to the miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    /// If true, this job is for a future prevhash (not yet received)
    pub future_job: bool,
    pub version: u32,
    pub merkle_root: [u8; 32],
}

impl NewMiningJob {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 73 {
            return Err(MessageError::TooShort);
        }
        let channel_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let job_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let future_job = data[8] != 0;
        let version = u32::from_le_bytes(data[9..13].try_into().unwrap());
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[13..45]);

        Ok(Self {
            channel_id,
            job_id,
            future_job,
            version,
            merkle_root,
        })
    }
}

/// SetNewPrevHash — pool announces a new block on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNewPrevHash {
    pub channel_id: u32,
    pub job_id: u32,
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
}

impl SetNewPrevHash {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 48 {
            return Err(MessageError::TooShort);
        }
        let channel_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let job_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&data[8..40]);
        let min_ntime = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let nbits = u32::from_le_bytes(data[44..48].try_into().unwrap());

        Ok(Self {
            channel_id,
            job_id,
            prev_hash,
            min_ntime,
            nbits,
        })
    }
}

/// SubmitSharesStandard — miner submits a share to the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesStandard {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

impl SubmitSharesStandard {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.channel_id.to_le_bytes());
        buf.extend_from_slice(&self.sequence_number.to_le_bytes());
        buf.extend_from_slice(&self.job_id.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.ntime.to_le_bytes());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf
    }
}

/// SubmitShares.Success response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesSuccess {
    pub channel_id: u32,
    pub last_sequence_number: u32,
    pub new_submits_accepted_count: u32,
    pub new_shares_sum: u64,
}

impl SubmitSharesSuccess {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 20 {
            return Err(MessageError::TooShort);
        }
        Ok(Self {
            channel_id: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            last_sequence_number: u32::from_le_bytes(data[4..8].try_into().unwrap()),
            new_submits_accepted_count: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            new_shares_sum: u64::from_le_bytes(data[12..20].try_into().unwrap()),
        })
    }
}

/// SetTarget — pool adjusts miner's share difficulty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTarget {
    pub channel_id: u32,
    pub max_target: [u8; 32],
}

impl SetTarget {
    pub fn from_payload(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 36 {
            return Err(MessageError::TooShort);
        }
        let channel_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut max_target = [0u8; 32];
        max_target.copy_from_slice(&data[4..36]);
        Ok(Self {
            channel_id,
            max_target,
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Write an SV2 STR0_255 (length-prefixed string, max 255 bytes).
fn write_sv2_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    buf.push(len as u8);
    buf.extend_from_slice(&bytes[..len]);
}

/// Read an SV2 STR0_255 from a byte slice.
fn read_sv2_string(data: &[u8]) -> Result<String, MessageError> {
    if data.is_empty() {
        return Err(MessageError::TooShort);
    }
    let len = data[0] as usize;
    if data.len() < 1 + len {
        return Err(MessageError::TooShort);
    }
    String::from_utf8(data[1..1 + len].to_vec()).map_err(|_| MessageError::InvalidUtf8)
}

/// Message parsing errors.
#[derive(Debug, Clone)]
pub enum MessageError {
    TooShort,
    InvalidUtf8,
    UnknownType(u8),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message payload too short"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in string field"),
            Self::UnknownType(t) => write!(f, "unknown message type: 0x{t:02x}"),
        }
    }
}

impl std::error::Error for MessageError {}

/// Dispatch a received frame into the appropriate message type.
pub fn parse_server_message(
    msg_type: u8,
    payload: &[u8],
) -> Result<ServerMessage, MessageError> {
    match msg_type {
        MSG_SETUP_CONNECTION_SUCCESS => Ok(ServerMessage::SetupConnectionSuccess(
            SetupConnectionSuccess::from_payload(payload)?,
        )),
        MSG_SETUP_CONNECTION_ERROR => Ok(ServerMessage::SetupConnectionError(
            SetupConnectionError::from_payload(payload)?,
        )),
        MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
            Ok(ServerMessage::OpenMiningChannelSuccess(
                OpenStandardMiningChannelSuccess::from_payload(payload)?,
            ))
        }
        MSG_NEW_MINING_JOB => Ok(ServerMessage::NewMiningJob(
            NewMiningJob::from_payload(payload)?,
        )),
        MSG_SET_NEW_PREV_HASH => Ok(ServerMessage::SetNewPrevHash(
            SetNewPrevHash::from_payload(payload)?,
        )),
        MSG_SUBMIT_SHARES_SUCCESS => Ok(ServerMessage::SubmitSharesSuccess(
            SubmitSharesSuccess::from_payload(payload)?,
        )),
        MSG_SET_TARGET => Ok(ServerMessage::SetTarget(
            SetTarget::from_payload(payload)?,
        )),
        _ => Err(MessageError::UnknownType(msg_type)),
    }
}

/// Parsed server→client message variants.
#[derive(Debug, Clone)]
pub enum ServerMessage {
    SetupConnectionSuccess(SetupConnectionSuccess),
    SetupConnectionError(SetupConnectionError),
    OpenMiningChannelSuccess(OpenStandardMiningChannelSuccess),
    NewMiningJob(NewMiningJob),
    SetNewPrevHash(SetNewPrevHash),
    SubmitSharesSuccess(SubmitSharesSuccess),
    SetTarget(SetTarget),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_connection_roundtrip() {
        let msg = SetupConnection::new("pool.example.com", 3336);
        let payload = msg.to_payload();
        assert!(payload.len() > 10);

        // Check protocol version at start
        assert_eq!(payload[0], 2);
        assert_eq!(payload[1], 0);
    }

    #[test]
    fn test_setup_connection_success() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // used_version
        payload.extend_from_slice(&0u32.to_le_bytes()); // flags

        let msg = SetupConnectionSuccess::from_payload(&payload).unwrap();
        assert_eq!(msg.used_version, 2);
        assert_eq!(msg.flags, 0);
    }

    #[test]
    fn test_submit_shares() {
        let share = SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 42,
            job_id: 100,
            nonce: 0xDEADBEEF,
            ntime: 1700000000,
            version: 0x20000000,
        };

        let payload = share.to_payload();
        assert_eq!(payload.len(), 24);

        // Verify nonce encoding
        let nonce = u32::from_le_bytes(payload[12..16].try_into().unwrap());
        assert_eq!(nonce, 0xDEADBEEF);
    }

    #[test]
    fn test_sv2_string() {
        let mut buf = Vec::new();
        write_sv2_string(&mut buf, "LombokMiner");
        assert_eq!(buf[0], 11); // length
        assert_eq!(&buf[1..], b"LombokMiner");

        let s = read_sv2_string(&buf).unwrap();
        assert_eq!(s, "LombokMiner");
    }

    #[test]
    fn test_set_target() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // channel_id
        payload.extend_from_slice(&[0x00; 28]); // target high bytes (zeros = hard)
        payload.extend_from_slice(&[0xFF; 4]); // target low bytes

        let msg = SetTarget::from_payload(&payload).unwrap();
        assert_eq!(msg.channel_id, 1);
        assert_eq!(msg.max_target[31], 0xFF);
    }
}
