//! Multiplexing and FEC layer for UDP/ICMP transports.
//!
//! This layer batches multiple CandyPacket payloads into a single wire frame
//! (multiplexing) and optionally adds XOR parity frames (FEC). It is not used
//! for QUIC.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use async_channel as mpsc;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_lite::future;

use crate::packet::CandyPacket;
use crate::raw_socket::{OutPacket, RawSender};
use crate::tunnel::PeerAddr;

const MAGIC: u8 = 0xCB;
const VERSION: u8 = 1;
const FLAG_PARITY: u8 = 0x01;
const FLAG_MUX: u8 = 0x02;
const HEADER_LEN: usize = 1 + 1 + 1 + 4 + 1 + 1; // magic + ver + flags + group_id + group_size + index

#[derive(Debug, Clone)]
pub struct MuxFecConfig {
    pub enable_multiplex: bool,
    pub multiplex_flush_ms: u64,
    pub multiplex_max_payload: usize,
    pub enable_fec: bool,
    pub fec_group_size: u8,
}

impl MuxFecConfig {
    pub fn is_enabled(&self) -> bool {
        self.enable_multiplex || self.enable_fec
    }

    pub fn validate(&self) -> Result<()> {
        if self.enable_fec && self.fec_group_size < 2 {
            bail!("fec_group_size must be >= 2");
        }
        if self.multiplex_max_payload < 64 {
            bail!("multiplex_max_payload too small");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DataFrame {
    group_id: u32,
    group_size: u8,
    index: u8,
    packets: Vec<Bytes>,
    raw: Bytes,
}

#[derive(Debug)]
pub(crate) struct ParityFrame {
    group_id: u32,
    group_size: u8,
    lengths: Vec<u16>,
    parity: Bytes,
}

#[derive(Debug)]
pub(crate) enum WireFrame {
    Data(DataFrame),
    Parity(ParityFrame),
}

pub struct FecDecoder {
    groups: HashMap<u32, GroupState>,
    max_groups: usize,
}

struct GroupState {
    group_size: u8,
    data: Vec<Option<Bytes>>,
    lengths: Option<Vec<u16>>,
    parity: Option<Bytes>,
    created: Instant,
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            max_groups: 128,
        }
    }

    pub(crate) fn on_data(&mut self, frame: &DataFrame) -> Vec<Bytes> {
        let group = self
            .groups
            .entry(frame.group_id)
            .or_insert_with(|| GroupState {
                group_size: frame.group_size,
                data: vec![None; frame.group_size as usize],
                lengths: None,
                parity: None,
                created: Instant::now(),
            });

        if frame.group_size != group.group_size {
            self.groups.remove(&frame.group_id);
            return Vec::new();
        }

        if (frame.index as usize) < group.data.len() {
            group.data[frame.index as usize] = Some(frame.raw.clone());
        }

        self.try_recover(frame.group_id)
    }

    pub(crate) fn on_parity(&mut self, frame: &ParityFrame) -> Vec<Bytes> {
        let group = self
            .groups
            .entry(frame.group_id)
            .or_insert_with(|| GroupState {
                group_size: frame.group_size,
                data: vec![None; frame.group_size as usize],
                lengths: Some(frame.lengths.clone()),
                parity: Some(frame.parity.clone()),
                created: Instant::now(),
            });

        if frame.group_size != group.group_size {
            self.groups.remove(&frame.group_id);
            return Vec::new();
        }

        group.lengths = Some(frame.lengths.clone());
        group.parity = Some(frame.parity.clone());

        self.try_recover(frame.group_id)
    }

    fn try_recover(&mut self, group_id: u32) -> Vec<Bytes> {
        let Some(group) = self.groups.get(&group_id) else {
            return Vec::new();
        };
        let Some(lengths) = &group.lengths else {
            return Vec::new();
        };
        let Some(parity) = &group.parity else {
            return Vec::new();
        };

        let mut missing = None;
        for (idx, item) in group.data.iter().enumerate() {
            if item.is_none() {
                if missing.is_some() {
                    return Vec::new();
                }
                missing = Some(idx);
            }
        }

        let Some(missing_idx) = missing else {
            return Vec::new();
        };
        let max_len = lengths.iter().copied().max().unwrap_or(0) as usize;
        if max_len == 0 {
            self.groups.remove(&group_id);
            return Vec::new();
        }

        let mut buf = vec![0u8; max_len];
        buf[..parity.len()].copy_from_slice(parity);

        for (idx, item) in group.data.iter().enumerate() {
            if idx == missing_idx {
                continue;
            }
            let Some(frame) = item else {
                continue;
            };
            for (i, b) in frame.iter().enumerate() {
                buf[i] ^= b;
            }
        }

        let missing_len = lengths[missing_idx] as usize;
        let recovered = Bytes::copy_from_slice(&buf[..missing_len]);
        self.groups.remove(&group_id);
        vec![recovered]
    }

    pub fn prune(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.groups
            .retain(|_, g| now.duration_since(g.created) < max_age);
        if self.groups.len() > self.max_groups {
            let keys: Vec<u32> = self
                .groups
                .keys()
                .take(self.groups.len() / 2)
                .copied()
                .collect();
            for k in keys {
                self.groups.remove(&k);
            }
        }
    }
}

pub fn encode_data_frame(
    packets: &[Bytes],
    group_id: u32,
    group_size: u8,
    index: u8,
) -> Result<Bytes> {
    let mut payload_len = 1; // count
    for p in packets {
        if p.len() > u16::MAX as usize {
            bail!("packet too large for mux frame");
        }
        payload_len += 2 + p.len();
    }

    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload_len);
    buf.put_u8(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(FLAG_MUX);
    buf.put_u32(group_id);
    buf.put_u8(group_size);
    buf.put_u8(index);

    buf.put_u8(packets.len() as u8);
    for p in packets {
        buf.put_u16(p.len() as u16);
        buf.extend_from_slice(p);
    }

    Ok(buf.freeze())
}

pub fn encode_parity_frame(group_id: u32, group_size: u8, frames: &[Bytes]) -> Result<Bytes> {
    if frames.len() != group_size as usize {
        bail!("parity frames length mismatch");
    }

    let mut lengths = Vec::with_capacity(frames.len());
    let mut max_len = 0usize;
    for f in frames {
        if f.len() > u16::MAX as usize {
            bail!("frame too large for parity");
        }
        lengths.push(f.len() as u16);
        max_len = max_len.max(f.len());
    }

    let mut parity = vec![0u8; max_len];
    for f in frames {
        for (i, b) in f.iter().enumerate() {
            parity[i] ^= b;
        }
    }

    let mut buf = BytesMut::with_capacity(HEADER_LEN + 1 + lengths.len() * 2 + parity.len());
    buf.put_u8(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(FLAG_MUX | FLAG_PARITY);
    buf.put_u32(group_id);
    buf.put_u8(group_size);
    buf.put_u8(0xFF);

    buf.put_u8(group_size);
    for l in lengths {
        buf.put_u16(l);
    }
    buf.extend_from_slice(&parity);

    Ok(buf.freeze())
}

pub(crate) fn decode_payload(payload: Bytes) -> Result<WireFrame> {
    if payload.len() < HEADER_LEN + 1 {
        bail!("mux frame too short");
    }
    let mut buf = payload.clone();
    let magic = buf.get_u8();
    if magic != MAGIC {
        bail!("mux frame bad magic");
    }
    let version = buf.get_u8();
    if version != VERSION {
        bail!("mux frame bad version");
    }
    let flags = buf.get_u8();
    let group_id = buf.get_u32();
    let group_size = buf.get_u8();
    let index = buf.get_u8();
    let count = buf.get_u8() as usize;

    if flags & FLAG_PARITY != 0 {
        if count != group_size as usize {
            bail!("parity count mismatch");
        }
        let mut lengths = Vec::with_capacity(count);
        for _ in 0..count {
            if buf.remaining() < 2 {
                bail!("parity lengths truncated");
            }
            lengths.push(buf.get_u16());
        }
        let parity = buf.copy_to_bytes(buf.remaining());
        return Ok(WireFrame::Parity(ParityFrame {
            group_id,
            group_size,
            lengths,
            parity,
        }));
    }

    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        if buf.remaining() < 2 {
            bail!("mux length truncated");
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            bail!("mux payload truncated");
        }
        packets.push(buf.copy_to_bytes(len));
    }

    Ok(WireFrame::Data(DataFrame {
        group_id,
        group_size,
        index,
        packets,
        raw: payload,
    }))
}

pub(crate) fn decode_packets_from_frame(
    frame: WireFrame,
    fec: Option<&mut FecDecoder>,
) -> Result<Vec<CandyPacket>> {
    let mut out = Vec::new();
    match frame {
        WireFrame::Data(df) => {
            for p in &df.packets {
                out.push(CandyPacket::decode(p.clone())?);
            }

            if let Some(fec_state) = fec {
                let recovered = fec_state.on_data(&df);
                if !recovered.is_empty() {
                    log::debug!("fec recovered frames count={}", recovered.len());
                }
                for raw in recovered {
                    let recovered_frame = decode_payload(raw)?;
                    if let WireFrame::Data(df2) = recovered_frame {
                        for p in df2.packets {
                            out.push(CandyPacket::decode(p)?);
                        }
                    }
                }
                fec_state.prune(Duration::from_secs(5));
            }
        }
        WireFrame::Parity(pf) => {
            if let Some(fec_state) = fec {
                let recovered = fec_state.on_parity(&pf);
                if !recovered.is_empty() {
                    log::debug!("fec recovered frames count={}", recovered.len());
                }
                for raw in recovered {
                    let recovered_frame = decode_payload(raw)?;
                    if let WireFrame::Data(df2) = recovered_frame {
                        for p in df2.packets {
                            out.push(CandyPacket::decode(p)?);
                        }
                    }
                }
                fec_state.prune(Duration::from_secs(5));
            }
        }
    }
    Ok(out)
}

// Intentionally no public size helper; keep framing internal.

#[derive(Clone)]
pub struct MuxFecSender {
    tx: mpsc::Sender<Bytes>,
}

impl MuxFecSender {
    pub fn spawn(
        cfg: MuxFecConfig,
        sender: RawSender,
        addr: PeerAddr,
        protocol: crate::config::TunnelProtocol,
        capacity: usize,
    ) -> Result<Self> {
        cfg.validate()?;
        log::debug!(
            "mux_fec spawn enable_mux={} enable_fec={} group={} max_payload={} proto={:?}",
            cfg.enable_multiplex,
            cfg.enable_fec,
            cfg.fec_group_size,
            cfg.multiplex_max_payload,
            protocol
        );
        let cap = capacity.max(1);
        let (tx, rx) = mpsc::bounded(cap);
        let mut encoder = Encoder::new(cfg, sender, addr, protocol);

        tokio::spawn(async move {
            encoder.run(rx).await;
        });

        Ok(Self { tx })
    }

    pub async fn send(&self, pkt: CandyPacket) -> Result<()> {
        self.tx
            .send(pkt.encode())
            .await
            .map_err(|_| anyhow!("mux sender closed"))
    }
}

struct Encoder {
    cfg: MuxFecConfig,
    sender: RawSender,
    addr: PeerAddr,
    protocol: crate::config::TunnelProtocol,
    batch: Vec<Bytes>,
    batch_size: usize,
    group_id: u32,
    group_frames: Vec<Bytes>,
    icmp_seq: u16,
}

impl Encoder {
    fn new(
        cfg: MuxFecConfig,
        sender: RawSender,
        addr: PeerAddr,
        protocol: crate::config::TunnelProtocol,
    ) -> Self {
        Self {
            cfg,
            sender,
            addr,
            protocol,
            batch: Vec::new(),
            batch_size: 0,
            group_id: rand::random(),
            group_frames: Vec::new(),
            icmp_seq: rand::random(),
        }
    }

    async fn run(&mut self, rx: mpsc::Receiver<Bytes>) {
        let flush_ms = self.cfg.multiplex_flush_ms.max(1);
        loop {
            if self.batch.is_empty() {
                match rx.recv().await {
                    Ok(pkt) => self.push_packet(pkt).await,
                    Err(_) => break,
                }
                continue;
            }

            let recv_fut = async {
                match rx.recv().await {
                    Ok(pkt) => RecvEvent::Packet(pkt),
                    Err(_) => RecvEvent::Closed,
                }
            };
            let timeout_fut = async {
                tokio::time::sleep(Duration::from_millis(flush_ms)).await;
                RecvEvent::Timeout
            };

            match future::race(recv_fut, timeout_fut).await {
                RecvEvent::Packet(pkt) => self.push_packet(pkt).await,
                RecvEvent::Timeout => {
                    let _ = self.flush_batch().await;
                }
                RecvEvent::Closed => break,
            }
        }

        let _ = self.flush_batch().await;
    }

    async fn push_packet(&mut self, pkt: Bytes) {
        if !self.cfg.enable_multiplex {
            let _ = self.send_frame(vec![pkt]).await;
            return;
        }

        let projected = estimate_mux_size_with_packet(&self.batch, &pkt);
        if projected > self.cfg.multiplex_max_payload && !self.batch.is_empty() {
            let _ = self.flush_batch().await;
        }

        self.batch_size = estimate_mux_size_with_packet(&self.batch, &pkt);
        self.batch.push(pkt);

        if self.batch_size >= self.cfg.multiplex_max_payload {
            let _ = self.flush_batch().await;
        }
    }

    async fn flush_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let packets = std::mem::take(&mut self.batch);
        self.batch_size = 0;
        self.send_frame(packets).await
    }

    async fn send_frame(&mut self, packets: Vec<Bytes>) -> Result<()> {
        let group_size = if self.cfg.enable_fec {
            self.cfg.fec_group_size
        } else {
            1
        };
        let index = self.group_frames.len() as u8;
        log::trace!(
            "mux_fec send_frame group_id={} index={} packets={} fec={}",
            self.group_id,
            index,
            packets.len(),
            self.cfg.enable_fec
        );
        let frame = encode_data_frame(&packets, self.group_id, group_size, index)?;
        self.send_wire(frame.clone()).await?;

        if self.cfg.enable_fec {
            self.group_frames.push(frame);
            if self.group_frames.len() == self.cfg.fec_group_size as usize {
                let parity = encode_parity_frame(
                    self.group_id,
                    self.cfg.fec_group_size,
                    &self.group_frames,
                )?;
                self.send_wire(parity).await?;
                self.group_frames.clear();
                self.group_id = self.group_id.wrapping_add(1);
            }
        }

        Ok(())
    }

    async fn send_wire(&mut self, payload: Bytes) -> Result<()> {
        let out = match self.protocol {
            crate::config::TunnelProtocol::Udp => OutPacket::Udp {
                src_ip: self.addr.local_spoof,
                dst_ip: self.addr.peer_real,
                src_port: self.addr.pick_data_port(),
                dst_port: self.addr.pick_data_port(),
                payload,
            },
            crate::config::TunnelProtocol::Icmp => {
                let seq = self.icmp_seq;
                self.icmp_seq = self.icmp_seq.wrapping_add(1);
                OutPacket::Icmp {
                    src_ip: self.addr.local_spoof,
                    dst_ip: self.addr.peer_real,
                    id: self.addr.pick_icmp_id(),
                    seq,
                    payload,
                }
            }
            crate::config::TunnelProtocol::Proto58 => OutPacket::Proto58 {
                src_ip: self.addr.local_spoof,
                dst_ip: self.addr.peer_real,
                payload,
            },
            crate::config::TunnelProtocol::Ipip => OutPacket::Ipip {
                src_ip: self.addr.local_spoof,
                dst_ip: self.addr.peer_real,
                payload,
            },
            crate::config::TunnelProtocol::Gre => OutPacket::Gre {
                src_ip: self.addr.local_spoof,
                dst_ip: self.addr.peer_real,
                payload,
            },
            crate::config::TunnelProtocol::Tcp => {
                return Err(anyhow!("mux/fec sender used with tcp"));
            }
            crate::config::TunnelProtocol::Quic => {
                return Err(anyhow!("mux/fec sender used with quic"));
            }
        };

        self.sender.send(out).await
    }
}

enum RecvEvent {
    Packet(Bytes),
    Timeout,
    Closed,
}

fn estimate_mux_size_with_packet(existing: &[Bytes], next: &Bytes) -> usize {
    let mut size = HEADER_LEN + 1;
    for p in existing {
        size += 2 + p.len();
    }
    size += 2 + next.len();
    size
}
