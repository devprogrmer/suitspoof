//! CandyTunnel wire protocol – the application-level packet that rides inside
//! spoofed UDP (data channel) or ICMP Echo (control channel) payloads.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// 4-byte magic number at the start of every CandyPacket.
pub const MAGIC: u32 = 0xCA_FE_5F_00;
/// Current protocol version.
pub const VERSION: u8 = 1;
/// Minimum wire size of a CandyPacket (no payload).
pub const HEADER_SIZE: usize = 14;

/// Type of a CandyPacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Application data.
    Data = 0,
    /// Tunnel open request (client → server).
    Syn = 1,
    /// Tunnel open acknowledgement (server → client).
    SynAck = 2,
    /// Tunnel teardown.
    Fin = 3,
    /// Keepalive ping.
    Heartbeat = 4,
    /// Keepalive pong.
    HeartbeatAck = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Syn),
            2 => Ok(Self::SynAck),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Heartbeat),
            5 => Ok(Self::HeartbeatAck),
            _ => bail!("unknown packet kind {}", v),
        }
    }
}

/// An application-level CandyTunnel packet.
///
/// Wire format (big-endian):
/// ```text
/// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][payload…]
/// ```
#[derive(Debug, Clone)]
pub struct CandyPacket {
    pub kind: PacketKind,
    pub tunnel_id: u32,
    /// Sequence number of this packet (informational only).
    pub seq: u32,
    /// Payload bytes (may be empty for control packets).
    pub payload: Bytes,
}

impl CandyPacket {
    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn new_syn(tunnel_id: u32, seq: u32) -> Self {
        Self {
            kind: PacketKind::Syn,
            tunnel_id,
            seq,
            payload: Bytes::new(),
        }
    }

    pub fn new_syn_ack(tunnel_id: u32, seq: u32) -> Self {
        Self {
            kind: PacketKind::SynAck,
            tunnel_id,
            seq,
            payload: Bytes::new(),
        }
    }

    pub fn new_data(tunnel_id: u32, seq: u32, payload: Bytes) -> Self {
        Self {
            kind: PacketKind::Data,
            tunnel_id,
            seq,
            payload,
        }
    }

    pub fn new_heartbeat(tunnel_id: u32, seq: u32) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            kind: PacketKind::Heartbeat,
            tunnel_id,
            seq,
            payload: Bytes::copy_from_slice(&ts.to_be_bytes()),
        }
    }

    pub fn new_fin(tunnel_id: u32) -> Self {
        Self {
            kind: PacketKind::Fin,
            tunnel_id,
            seq: 0,
            payload: Bytes::new(),
        }
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Encode the packet to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put_u32(self.seq);
        buf.put(self.payload.clone());
        buf.freeze()
    }

    /// Decode a packet from bytes. Returns an error on invalid input.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!(
                "packet too short: {} bytes (min {})",
                data.len(),
                HEADER_SIZE
            );
        }
        let magic = data.get_u32();
        if magic != MAGIC {
            bail!("bad magic 0x{:08x}", magic);
        }
        let version = data.get_u8();
        if version != VERSION {
            bail!("unsupported version {}", version);
        }
        let kind = PacketKind::try_from(data.get_u8())?;
        let tunnel_id = data.get_u32();
        let seq = data.get_u32();
        let payload = data; // remaining bytes
        Ok(CandyPacket {
            kind,
            tunnel_id,
            seq,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_uses_provided_sequence() {
        let pkt = CandyPacket::new_syn(42, 12345);
        assert_eq!(pkt.kind, PacketKind::Syn);
        assert_eq!(pkt.tunnel_id, 42);
        assert_eq!(pkt.seq, 12345);
    }
}
