use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    Data = 0,
    Syn = 1,
    SynAck = 2,
    Fin = 3,
    Heartbeat = 4,
    HeartbeatAck = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketKind::Data),
            1 => Ok(PacketKind::Syn),
            2 => Ok(PacketKind::SynAck),
            3 => Ok(PacketKind::Fin),
            4 => Ok(PacketKind::Heartbeat),
            5 => Ok(PacketKind::HeartbeatAck),
            _ => bail!("invalid PacketKind {}", value),
        }
    }
}

// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][payload...]
const CURRENT_PROTOCOL_VERSION: u8 = 0x01;
const MAGIC: u32 = 0x5B005B00;

#[derive(Debug, Clone)]
pub struct SuitPacket {
    pub kind: PacketKind,
    pub tunnel_id: u32,
    pub seq: u32,
    pub payload: Bytes,
}

impl SuitPacket {
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
        Self {
            kind: PacketKind::Heartbeat,
            tunnel_id,
            seq,
            payload: Bytes::new(),
        }
    }

    pub fn new_heartbeat_ack(tunnel_id: u32, seq: u32) -> Self {
        Self {
            kind: PacketKind::HeartbeatAck,
            tunnel_id,
            seq,
            payload: Bytes::new(),
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

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(14 + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(CURRENT_PROTOCOL_VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put_u32(self.seq);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(mut buf: Bytes) -> Result<Self> {
        if buf.len() < 14 {
            bail!("packet too short: {}", buf.len());
        }

        let magic = buf.get_u32();
        if magic != MAGIC {
            bail!("invalid magic: {:#x}", magic);
        }

        let version = buf.get_u8();
        if version != CURRENT_PROTOCOL_VERSION {
            bail!("unsupported protocol version: {}", version);
        }

        let kind = PacketKind::try_from(buf.get_u8())?;
        let tunnel_id = buf.get_u32();
        let seq = buf.get_u32();
        let payload = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            kind,
            tunnel_id,
            seq,
            payload,
        })
    }
}
