//! Raw-socket I/O layer.
//!
//! Provides two abstractions:
//!
//! - [`RawSender`] – builds and transmits spoofed IPv4/UDP, IPv4/ICMP, or
//!   IPv4/TCP packets
//!   via a `SOCK_RAW | IPPROTO_RAW` socket with `IP_HDRINCL`.
//! - [`RawReceiver`] – receives raw IP packets from a `SOCK_RAW | IPPROTO_UDP`,
//!   `SOCK_RAW | IPPROTO_ICMP`, or `SOCK_RAW | IPPROTO_TCP` socket and
//!   demultiplexes them into
//!   `CandyPacket`s.
//!
//! Both types are bridge objects between the blocking raw-socket world and the
//! async task graph.  Each spawns background `std::thread`s that communicate
//! through `async-channel` channels.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_channel as mpsc;
use bytes::Bytes;
use pnet_packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::Packet;

use crate::config::{DpiObfuscation, TunnelProtocol};
use crate::mux_fec::{decode_packets_from_frame, decode_payload, FecDecoder, MuxFecConfig};
use crate::packet::CandyPacket;
use crate::xor::XorCipher;

// ── Constants ────────────────────────────────────────────────────────────────

const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const TCP_HDR_LEN: usize = 20;
const ICMP_ECHO_HDR_LEN: usize = 8;
/// Minimal RFC 2784 GRE header: 2-byte flags/version (both zero) + 2-byte protocol type.
const GRE_HDR_LEN: usize = 4;
/// GRE protocol type – 0x0800 = IPv4 payload (used as a plausible inner type).
const GRE_PROTO_IPV4: u16 = 0x0800;

/// Default TTL when TTL jitter is disabled.
const SPOOF_TTL: u8 = 64;
/// Realistic OS TTL pool: Linux=64, Windows=128, Cisco/BSD=255.
const TTL_POOL: [u8; 3] = [64, 128, 255];
/// Fake TLS Application Data record header: type=0x17, version=TLS1.2, len follows.
const TLS_RECORD_TYPE: u8 = 0x17;
const TLS_VERSION: [u8; 2] = [0x03, 0x03];
/// DSCP value pool: 0=default, 0x28=AF11 (assured forwarding), 0x10=CS1.
const DSCP_POOL: [u8; 3] = [0x00, 0x28, 0x10];
/// Magic byte that marks a padding-suffixed frame on the wire.
/// The last byte of a padded payload is the pad length (1–255).
/// This is stripped by the receiver before decoding.
const PAD_MARKER_SHIFT: u8 = 0; // pad_len stored as the last byte

/// Fast wrapping counter for IPv4 identification field.
/// Avoids calling `rand::random()` on every outgoing packet.
static IP_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

// ── Outgoing packet descriptor ────────────────────────────────────────────────

/// A request to transmit a single spoofed packet.
#[derive(Debug)]
pub enum OutPacket {
    /// Send a UDP packet carrying `payload` on the data channel.
    Udp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: Bytes,
    },
    /// Send an ICMP Echo Request carrying `payload` on the control channel.
    Icmp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: Bytes,
    },
    /// Send an ICMP Echo Reply (server → client) on the control channel.
    IcmpReply {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: Bytes,
    },
    /// Send a raw IPv4 packet with protocol number 58 and no L4 header.
    Proto58 {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send an IP-in-IP (protocol 4) packet.  The `payload` is placed
    /// directly after the outer IPv4 header with no additional L4 header.
    Ipip {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send a GRE (protocol 47, RFC 2784) packet.
    /// A minimal 4-byte GRE header (flags=0, proto=0x0800 IPv4) is inserted
    /// between the outer IPv4 header and the CandyTunnel payload.
    Gre {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Bytes,
    },
    /// Send a TCP packet carrying `payload` on the data channel.
    Tcp {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Bytes,
    },
}

/// A received packet that has been validated and parsed.
#[derive(Debug)]
pub struct InPacket {
    /// True source IP (from the IP header).
    pub src_ip: Ipv4Addr,
    /// Parsed CandyTunnel application packet.
    pub pkt: CandyPacket,
}

/// A raw UDP datagram (payload only) received from a spoofed packet.
#[derive(Debug)]
pub struct UdpDatagram {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

// ── Port filtering ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PortFilter {
    single: u16,
    set: Option<Arc<HashSet<u16>>>,
    range: Option<(u16, u16)>,
}

impl PortFilter {
    pub fn new(single: u16, pool: Option<Arc<Vec<u16>>>, range: Option<(u16, u16)>) -> Self {
        let set = pool.and_then(|ports| {
            if ports.is_empty() {
                None
            } else {
                Some(Arc::new(ports.iter().copied().collect()))
            }
        });
        Self { single, set, range }
    }

    pub fn matches(&self, port: u16) -> bool {
        if let Some((min_port, max_port)) = self.range {
            if port >= min_port && port <= max_port {
                return true;
            }
        }
        if let Some(set) = &self.set {
            set.contains(&port)
        } else {
            port == self.single
        }
    }
}

// ── RawSender ────────────────────────────────────────────────────────────────

/// Sends spoofed IPv4 packets using a background thread.
///
/// Clone the inner `mpsc::Sender` to send packets from multiple tasks.
#[derive(Clone)]
pub struct RawSender {
    tx: mpsc::Sender<OutPacket>,
}

impl RawSender {
    /// Spawn the background sender thread and return a `RawSender` handle.
    ///
    /// When `xor` is `Some`, every outgoing packet payload is XOR-encrypted.
    /// `dpi` controls optional DPI obfuscation (padding, TTL jitter, etc.).
    pub fn spawn(capacity: usize, xor: Option<XorCipher>, dpi: DpiObfuscation) -> Result<Self> {
        log::debug!(
            "raw sender spawn capacity={} xor={} padding={} ttl_jitter={} fake_tls={} dscp={}",
            capacity.max(1),
            xor.is_some(),
            dpi.packet_padding,
            dpi.ttl_jitter,
            dpi.fake_tls_header,
            dpi.random_dscp,
        );
        let fd = create_raw_send_socket()?;
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<OutPacket>, mpsc::Receiver<OutPacket>) = mpsc::bounded(cap);

        std::thread::Builder::new()
            .name("raw-send".into())
            .spawn(move || {
                while let Ok(out) = rx.recv_blocking() {
                    // 1. Optionally apply fake TLS header (TCP only, before XOR).
                    let out = if dpi.fake_tls_header {
                        apply_fake_tls(out)
                    } else {
                        out
                    };
                    // 2. Optionally append random padding (before XOR so padding is encrypted).
                    let out = if dpi.packet_padding {
                        apply_padding(out, dpi.packet_padding_max)
                    } else {
                        out
                    };
                    // 3. Optionally XOR-encrypt.
                    let out = match &xor {
                        Some(cipher) => encrypt_out_packet(out, cipher),
                        None => out,
                    };
                    // 4. Build and send the wire packet (TTL jitter + DSCP applied inside).
                    if let Err(e) = send_out_packet(fd, out, &dpi) {
                        log::warn!("raw-send error: {}", e);
                    }
                }
                unsafe { libc::close(fd) };
            })
            .context("spawn raw send thread")?;

        Ok(Self { tx })
    }

    /// Enqueue an [`OutPacket`] for transmission.
    pub async fn send(&self, pkt: OutPacket) -> Result<()> {
        self.tx.send(pkt).await.context("raw sender closed")
    }
}

// ── RawReceiver ───────────────────────────────────────────────────────────────

/// Receives and parses incoming raw IP packets in a background thread.
pub struct RawReceiver {
    rx: mpsc::Receiver<InPacket>,
}

/// Receives raw UDP payloads without CandyPacket decoding.
pub struct RawUdpReceiver {
    rx: mpsc::Receiver<UdpDatagram>,
}

impl RawReceiver {
    /// Spawn background threads for reception and return a `RawReceiver`.
    ///
    /// `icmp_id` – the ICMP identifier to match (filters out foreign pings).
    /// `allow_any_icmp_id` – accept any ICMP identifier.
    /// `allowed` – set of peer IPs whose packets are trusted.
    pub fn spawn(
        protocol: TunnelProtocol,
        port_filter: PortFilter,
        icmp_id: u16,
        allow_any_icmp_id: bool,
        allowed: Vec<Ipv4Addr>,
        mux_fec: MuxFecConfig,
        capacity: usize,
        xor: Option<XorCipher>,
        dpi: DpiObfuscation,
    ) -> Result<Self> {
        log::debug!(
            "raw receiver spawn proto={:?} allow_any_icmp_id={} allowed_peers={} mux_fec={} xor={} padding={}",
            protocol,
            allow_any_icmp_id,
            allowed.len(),
            mux_fec.is_enabled(),
            xor.is_some(),
            dpi.packet_padding,
        );
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<InPacket>, mpsc::Receiver<InPacket>) = mpsc::bounded(cap);

        let padding = dpi.packet_padding;
        let fake_tls = dpi.fake_tls_header;

        match protocol {
            TunnelProtocol::Udp => {
                let udp_fd = create_raw_recv_socket(libc::IPPROTO_UDP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let port_filter2 = port_filter.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-udp".into())
                    .spawn(move || {
                        udp_recv_loop(
                            udp_fd,
                            port_filter2,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn udp recv thread")?;
            }
            TunnelProtocol::Icmp => {
                let icmp_fd = create_raw_recv_socket(libc::IPPROTO_ICMP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-icmp".into())
                    .spawn(move || {
                        icmp_recv_loop(
                            icmp_fd,
                            icmp_id,
                            allow_any_icmp_id,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn icmp recv thread")?;
            }
            TunnelProtocol::Proto58 => {
                let proto_fd = create_raw_recv_socket(libc::IPPROTO_ICMPV6 as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-proto58".into())
                    .spawn(move || {
                        proto58_recv_loop(
                            proto_fd,
                            &allowed2,
                            tx2,
                            mux_fec2,
                            xor2.as_ref(),
                            padding,
                        );
                    })
                    .context("spawn proto58 recv thread")?;
            }
            TunnelProtocol::Tcp => {
                let tcp_fd = create_raw_recv_socket(libc::IPPROTO_TCP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let port_filter2 = port_filter.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-tcp".into())
                    .spawn(move || {
                        tcp_recv_loop(
                            tcp_fd,
                            port_filter2,
                            &allowed2,
                            tx2,
                            xor2.as_ref(),
                            padding,
                            fake_tls,
                        );
                    })
                    .context("spawn tcp recv thread")?;
            }
            TunnelProtocol::Ipip => {
                let ipip_fd = create_raw_recv_socket(libc::IPPROTO_IPIP as libc::c_int)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-ipip".into())
                    .spawn(move || {
                        ipip_recv_loop(ipip_fd, &allowed2, tx2, mux_fec2, xor2.as_ref(), padding);
                    })
                    .context("spawn ipip recv thread")?;
            }
            TunnelProtocol::Gre => {
                const IPPROTO_GRE: libc::c_int = 47;
                let gre_fd = create_raw_recv_socket(IPPROTO_GRE)?;
                let tx2 = tx;
                let allowed2 = allowed;
                let mux_fec2 = mux_fec.clone();
                let xor2 = xor;
                std::thread::Builder::new()
                    .name("raw-recv-gre".into())
                    .spawn(move || {
                        gre_recv_loop(gre_fd, &allowed2, tx2, mux_fec2, xor2.as_ref(), padding);
                    })
                    .context("spawn gre recv thread")?;
            }
            TunnelProtocol::Quic => {
                bail!("raw receiver does not support quic");
            }
        }

        Ok(Self { rx })
    }

    /// Await the next validated incoming packet.
    pub async fn recv(&mut self) -> Option<InPacket> {
        self.rx.recv().await.ok()
    }
}

impl RawUdpReceiver {
    /// Spawn background thread for UDP payload reception.
    pub fn spawn(port_filter: PortFilter, allowed: Vec<Ipv4Addr>, capacity: usize) -> Result<Self> {
        let cap = capacity.max(1);
        let (tx, rx): (mpsc::Sender<UdpDatagram>, mpsc::Receiver<UdpDatagram>) = mpsc::bounded(cap);
        let udp_fd = create_raw_recv_socket(libc::IPPROTO_UDP as libc::c_int)?;
        std::thread::Builder::new()
            .name("raw-recv-udp-raw".into())
            .spawn(move || {
                udp_payload_loop(udp_fd, port_filter, &allowed, tx);
            })
            .context("spawn udp raw recv thread")?;

        Ok(Self { rx })
    }

    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        self.rx.recv().await.ok()
    }
}

// ── Socket creation helpers ───────────────────────────────────────────────────

/// 4 MiB kernel socket send/receive buffer – large enough to absorb 1 Gbps+ bursts.
const SOCK_BUF_SIZE: libc::c_int = 4 * 1024 * 1024;

fn set_sock_buf(fd: RawFd) {
    let size = SOCK_BUF_SIZE;
    unsafe {
        // SO_SNDBUF / SO_RCVBUF: try the requested size; kernel may cap to
        // net.core.rmem_max / wmem_max but will not error out.
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
    }
}

fn create_raw_send_socket() -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed – CAP_NET_RAW required");
    }
    // Tell the kernel we are supplying the IP header ourselves.
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    set_sock_buf(fd);
    Ok(fd)
}

fn create_raw_recv_socket(proto: libc::c_int) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, …) failed – CAP_NET_RAW required");
    }
    set_sock_buf(fd);
    Ok(fd)
}

// ── Packet transmission ───────────────────────────────────────────────────────

fn send_out_packet(fd: RawFd, out: OutPacket, dpi: &DpiObfuscation) -> Result<()> {
    match out {
        OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        } => {
            let mut raw = build_udp_packet(src_ip, dst_ip, src_port, dst_port, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => {
            let mut raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, false);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => {
            let mut raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, true);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload,
        } => {
            let mut raw = build_proto58_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => {
            let mut raw = build_tcp_packet(
                src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &payload,
            );
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload,
        } => {
            let mut raw = build_ipip_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Gre {
            src_ip,
            dst_ip,
            payload,
        } => {
            let mut raw = build_gre_packet(src_ip, dst_ip, &payload);
            patch_ip_header(&mut raw, dpi);
            raw_sendto(fd, &raw, dst_ip)
        }
    }
}

// ── DPI obfuscation helpers ──────────────────────────────────────────────────────

/// Patch TTL and DSCP in an already-built wire packet (bytes 8 and 1).
/// Also recomputes the IPv4 checksum.
fn patch_ip_header(raw: &mut [u8], dpi: &DpiObfuscation) {
    if raw.len() < IP_HDR_LEN {
        return;
    }

    if dpi.ttl_jitter {
        // Pick a random TTL from the realistic OS pool.
        let idx = (rand::random::<u8>() as usize) % TTL_POOL.len();
        raw[8] = TTL_POOL[idx];
    }
    if dpi.random_dscp {
        // Byte 1 of IPv4 header = DSCP(6 bits) | ECN(2 bits).
        // Preserve ECN (lower 2 bits), replace DSCP.
        let ecn = raw[1] & 0x03;
        let idx = (rand::random::<u8>() as usize) % DSCP_POOL.len();
        raw[1] = (DSCP_POOL[idx] & 0xfc) | ecn;
    }
    // Recompute checksum if any field changed.
    if dpi.ttl_jitter || dpi.random_dscp {
        // Zero checksum field then recompute.
        raw[10] = 0;
        raw[11] = 0;
        let cksum = ipv4_checksum_raw(&raw[..IP_HDR_LEN]);
        raw[10] = (cksum >> 8) as u8;
        raw[11] = (cksum & 0xff) as u8;
    }
}

/// Pure-Rust IPv4 header checksum (RFC 1071) – avoids re-parsing with pnet.
fn ipv4_checksum_raw(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    if i < hdr.len() {
        sum += (hdr[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Append `1..=max_pad` random bytes and store the count in the final byte.
/// Format: `[ original payload ][ random_bytes... ][ pad_len : 1 byte ]`
/// The receiver reads the last byte as `pad_len` and strips `pad_len + 1` bytes.
fn apply_padding(pkt: OutPacket, max_pad: u8) -> OutPacket {
    let max = max_pad.max(1);
    let pad_len = 1u8.max(rand::random::<u8>() % max + 1);
    let add_pad = |payload: Bytes| -> Bytes {
        let mut buf = bytes::BytesMut::with_capacity(payload.len() + pad_len as usize + 1);
        buf.extend_from_slice(&payload);
        for _ in 0..pad_len {
            buf.extend_from_slice(&[rand::random::<u8>()]);
        }
        buf.extend_from_slice(&[pad_len]); // length marker
        buf.freeze()
    };
    match pkt {
        OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        } => OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload: add_pad(payload),
        },
        OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: add_pad(payload),
        },
        OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: add_pad(payload),
        },
        OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload: add_pad(payload),
        },
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload: add_pad(payload),
        },
        OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload: add_pad(payload),
        },
        OutPacket::Gre {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Gre {
            src_ip,
            dst_ip,
            payload: add_pad(payload),
        },
    }
}

/// Strip padding added by [`apply_padding`] from a received payload.
/// Returns `None` if the payload is too short to contain a valid pad marker.
pub fn strip_padding(mut payload: Bytes) -> Option<Bytes> {
    if payload.is_empty() {
        return Some(payload);
    }
    let pad_len = *payload.last()? as usize;
    let total_strip = pad_len + 1; // random bytes + length marker
    if payload.len() <= total_strip {
        return None;
    }
    let new_len = payload.len() - total_strip;
    payload.truncate(new_len);
    Some(payload)
}

/// Prepend a fake TLS Application Data record header to TCP payloads.
/// DPI that only checks the first 5 bytes of TCP data sees a valid TLS record.
/// Only applied to TCP; other protocols are returned unchanged.
fn apply_fake_tls(pkt: OutPacket) -> OutPacket {
    let wrap = |payload: Bytes| -> Bytes {
        // TLS record: type(1) + version(2) + length(2) + data
        let inner_len = payload.len() as u16;
        let mut buf = bytes::BytesMut::with_capacity(5 + payload.len());
        buf.extend_from_slice(&[TLS_RECORD_TYPE]);
        buf.extend_from_slice(&TLS_VERSION);
        buf.extend_from_slice(&inner_len.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf.freeze()
    };
    match pkt {
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload: wrap(payload),
        },
        other => other, // only TCP gets the fake TLS header
    }
}

/// Encrypt the payload bytes of an [`OutPacket`] using the supplied cipher.
fn encrypt_out_packet(pkt: OutPacket, cipher: &XorCipher) -> OutPacket {
    match pkt {
        OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        } => OutPacket::Udp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => OutPacket::Icmp {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload,
        } => OutPacket::IcmpReply {
            src_ip,
            dst_ip,
            id,
            seq,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Proto58 {
            src_ip,
            dst_ip,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        } => OutPacket::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Ipip {
            src_ip,
            dst_ip,
            payload: cipher.encrypt(&payload),
        },
        OutPacket::Gre {
            src_ip,
            dst_ip,
            payload,
        } => OutPacket::Gre {
            src_ip,
            dst_ip,
            payload: cipher.encrypt(&payload),
        },
    }
}

fn raw_sendto(fd: RawFd, data: &[u8], dst: Ipv4Addr) -> Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from(dst).to_be(),
    };

    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("sendto failed");
    }
    Ok(())
}

// ── Packet reception loops ────────────────────────────────────────────────────

fn udp_recv_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("udp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        // Validate source IP against whitelist
        if !is_allowed(src_ip, allowed) {
            log::trace!("udp drop src_not_allowed={}", src_ip);
            continue;
        }

        // Parse IP header (variable-length)
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + UDP_HDR_LEN {
            continue;
        }
        let udp_data = &data[ihl..];

        // Check destination port
        let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
        if !port_filter.matches(dst_port) {
            log::trace!("udp drop dst_port={}", dst_port);
            continue;
        }

        // UDP payload starts at offset 8
        if udp_data.len() < UDP_HDR_LEN {
            continue;
        }
        let raw_payload = bytes::Bytes::copy_from_slice(&udp_data[UDP_HDR_LEN..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("udp xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("udp pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("udp mux decode: {}", e),
                },
                Err(e) => log::trace!("udp mux frame: {}", e),
            }
        } else {
            match CandyPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("udp decode: {}", e),
            }
        }
    }
}

fn udp_payload_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<UdpDatagram>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("udp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("udp-raw drop src_not_allowed={}", src_ip);
            continue;
        }

        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + UDP_HDR_LEN {
            continue;
        }
        let udp_data = &data[ihl..];

        let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
        let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
        if !port_filter.matches(dst_port) {
            log::trace!("udp-raw drop dst_port={}", dst_port);
            continue;
        }

        if udp_data.len() < UDP_HDR_LEN {
            continue;
        }
        let payload = bytes::Bytes::copy_from_slice(&udp_data[UDP_HDR_LEN..]);
        let _ = tx.send_blocking(UdpDatagram {
            src_ip,
            src_port,
            dst_port,
            payload,
        });
    }
}

fn icmp_recv_loop(
    fd: RawFd,
    icmp_id: u16,
    allow_any_icmp_id: bool,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("icmp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("icmp drop src_not_allowed={}", src_ip);
            continue;
        }

        // Parse IP header
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + ICMP_ECHO_HDR_LEN {
            continue;
        }
        let icmp_data = &data[ihl..];

        // Type must be 8 (echo request) or 0 (echo reply)
        let icmp_type = icmp_data[0];
        if icmp_type != 8 && icmp_type != 0 {
            continue;
        }

        // Match our ICMP identifier unless randomization is enabled.
        let id = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
        if !allow_any_icmp_id && id != icmp_id {
            log::trace!("icmp drop id_mismatch id={}", id);
            continue;
        }

        let raw_payload = bytes::Bytes::copy_from_slice(&icmp_data[ICMP_ECHO_HDR_LEN..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("icmp xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("icmp pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("icmp mux decode: {}", e),
                },
                Err(e) => log::trace!("icmp mux frame: {}", e),
            }
        } else {
            match CandyPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("icmp decode: {}", e),
            }
        }
    }
}

fn proto58_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("proto58 recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("proto58 drop src_not_allowed={}", src_ip);
            continue;
        }

        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl {
            continue;
        }
        let raw_payload = bytes::Bytes::copy_from_slice(&data[ihl..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("proto58 xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("proto58 pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("proto58 mux decode: {}", e),
                },
                Err(e) => log::trace!("proto58 mux frame: {}", e),
            }
        } else {
            match CandyPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("proto58 decode: {}", e),
            }
        }
    }
}

/// IP-in-IP (protocol 4) receive loop.
///
/// The kernel delivers the full outer IPv4 packet via the raw socket.  We
/// skip the outer IP header and treat the remaining bytes as the CandyTunnel
/// payload (possibly XOR-encrypted, possibly a mux frame).
fn ipip_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("ipip recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("ipip drop src_not_allowed={}", src_ip);
            continue;
        }

        // Skip the outer IPv4 header (variable length).
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() <= ihl {
            continue;
        }
        let raw_payload = bytes::Bytes::copy_from_slice(&data[ihl..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("ipip xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("ipip pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("ipip mux decode: {}", e),
                },
                Err(e) => log::trace!("ipip mux frame: {}", e),
            }
        } else {
            match CandyPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("ipip decode: {}", e),
            }
        }
    }
}

/// GRE (protocol 47) receive loop.
///
/// Skips the outer IPv4 header then the 4-byte minimal GRE header, then
/// treats the remaining bytes as the CandyTunnel payload.
fn gre_recv_loop(
    fd: RawFd,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    mux_fec: MuxFecConfig,
    xor: Option<&XorCipher>,
    padding: bool,
) {
    let mut buf = vec![0u8; 65535];
    let mut fec_state = if mux_fec.enable_fec {
        Some(FecDecoder::new())
    } else {
        None
    };
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("gre recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("gre drop src_not_allowed={}", src_ip);
            continue;
        }

        // Skip outer IPv4 header (variable length).
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        // Require at least outer IP header + 4-byte GRE header.
        if data.len() < ihl + GRE_HDR_LEN {
            continue;
        }

        // Skip the 4-byte minimal GRE header.
        let payload_start = ihl + GRE_HDR_LEN;
        if data.len() <= payload_start {
            continue;
        }
        let raw_payload = bytes::Bytes::copy_from_slice(&data[payload_start..]);
        let payload = match xor {
            Some(c) => match c.decrypt(raw_payload) {
                Some(p) => p,
                None => {
                    log::trace!("gre xor decrypt failed");
                    continue;
                }
            },
            None => raw_payload,
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("gre pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        if mux_fec.is_enabled() {
            match decode_payload(payload) {
                Ok(frame) => match decode_packets_from_frame(frame, fec_state.as_mut()) {
                    Ok(pkts) => {
                        for pkt in pkts {
                            let _ = tx.send_blocking(InPacket { src_ip, pkt });
                        }
                    }
                    Err(e) => log::trace!("gre mux decode: {}", e),
                },
                Err(e) => log::trace!("gre mux frame: {}", e),
            }
        } else {
            match CandyPacket::decode(payload) {
                Ok(pkt) => {
                    let _ = tx.send_blocking(InPacket { src_ip, pkt });
                }
                Err(e) => log::trace!("gre decode: {}", e),
            }
        }
    }
}

fn tcp_recv_loop(
    fd: RawFd,
    port_filter: PortFilter,
    allowed: &[Ipv4Addr],
    tx: mpsc::Sender<InPacket>,
    xor: Option<&XorCipher>,
    padding: bool,
    fake_tls: bool,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("tcp recvfrom: {}", e);
                continue;
            }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            log::trace!("tcp drop src_not_allowed={}", src_ip);
            continue;
        }

        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + TCP_HDR_LEN {
            continue;
        }
        let tcp_data = &data[ihl..];
        let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
            Some(p) => p,
            None => continue,
        };

        let dst_port = tcp.get_destination();
        if !port_filter.matches(dst_port) {
            log::trace!("tcp drop dst_port={}", dst_port);
            continue;
        }

        let raw_payload = tcp.payload();
        if raw_payload.is_empty() {
            continue;
        }

        let payload = match xor {
            Some(c) => match c.decrypt(Bytes::copy_from_slice(raw_payload)) {
                Some(p) => p,
                None => {
                    log::trace!("tcp xor decrypt failed");
                    continue;
                }
            },
            None => Bytes::copy_from_slice(raw_payload),
        };
        // Strip fake TLS record header (5 bytes) if enabled.
        let payload = if fake_tls {
            if payload.len() < 5 {
                log::trace!("tcp tls strip too short");
                continue;
            }
            payload.slice(5..)
        } else {
            payload
        };
        let payload = if padding {
            match strip_padding(payload) {
                Some(p) => p,
                None => {
                    log::trace!("tcp pad strip failed");
                    continue;
                }
            }
        } else {
            payload
        };
        match CandyPacket::decode(payload) {
            Ok(pkt) => {
                let _ = tx.send_blocking(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("tcp decode: {}", e),
        }
    }
}

fn raw_recvfrom(fd: RawFd, buf: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addrlen,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("recvfrom failed");
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok((n as usize, ip))
}

fn is_allowed(ip: Ipv4Addr, allowed: &[Ipv4Addr]) -> bool {
    // If caller provided an empty allow-list, treat that as "allow all".
    if allowed.is_empty() {
        true
    } else {
        allowed.contains(&ip)
    }
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Build a spoofed IPv4/UDP packet.
pub fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_total = UDP_HDR_LEN + payload.len();
    let ip_total = IP_HDR_LEN + udp_total;

    let mut buf = vec![0u8; ip_total];

    // Fill UDP header (starts at byte 20)
    {
        let udp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt = MutableUdpPacket::new(udp_buf).unwrap();
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_length(udp_total as u16);
        pkt.set_payload(payload);
        let cksum = pnet_packet::udp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Udp,
        ip_total,
    );
    buf
}

/// Build a spoofed IPv4/ICMP echo request (or reply) packet.
pub fn build_icmp_echo(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
    reply: bool,
) -> Vec<u8> {
    let icmp_total = ICMP_ECHO_HDR_LEN + payload.len();
    let ip_total = IP_HDR_LEN + icmp_total;

    let mut buf = vec![0u8; ip_total];

    {
        let icmp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt = MutableEchoRequestPacket::new(icmp_buf).unwrap();
        pkt.set_icmp_type(if reply {
            IcmpTypes::EchoReply
        } else {
            IcmpTypes::EchoRequest
        });
        pkt.set_icmp_code(IcmpCode::new(0));
        pkt.set_identifier(id);
        pkt.set_sequence_number(seq);
        pkt.set_payload(payload);
        // Compute ICMP checksum over the full ICMP portion.
        let cksum = pnet_packet::icmp::checksum(&IcmpPacket::new(pkt.packet()).unwrap());
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Icmp,
        ip_total,
    );
    buf
}

/// Build a spoofed IPv4 packet with protocol number 58 and no L4 header.
pub fn build_proto58_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let ip_total = IP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; ip_total];

    buf[IP_HDR_LEN..].copy_from_slice(payload);
    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Icmpv6,
        ip_total,
    );
    buf
}

/// Build an IP-in-IP (protocol 4) packet.
///
/// The outer IPv4 header uses `src_ip` / `dst_ip` with `protocol = 4`.
/// `payload` is placed directly after the outer header with no L4 header.
pub fn build_ipip_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let ip_total = IP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; ip_total];
    buf[IP_HDR_LEN..].copy_from_slice(payload);
    // Protocol 4 = IP-in-IP (IANA assigned)
    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Ipv4,
        ip_total,
    );
    buf
}

/// Build a minimal GRE (protocol 47, RFC 2784) packet.
///
/// Wire layout:
/// ```text
/// [ Outer IPv4 header : 20 B  (proto = 47) ]
/// [ GRE header        :  4 B  (flags=0, proto=0x0800) ]
/// [ CandyTunnel payload      ]
/// ```
pub fn build_gre_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let ip_total = IP_HDR_LEN + GRE_HDR_LEN + payload.len();
    let mut buf = vec![0u8; ip_total];

    // GRE header at offset 20: flags/version = 0x0000, protocol = 0x0800
    buf[IP_HDR_LEN] = 0x00; // flags + version (no checksum, no key, no seq)
    buf[IP_HDR_LEN + 1] = 0x00;
    buf[IP_HDR_LEN + 2] = (GRE_PROTO_IPV4 >> 8) as u8;
    buf[IP_HDR_LEN + 3] = (GRE_PROTO_IPV4 & 0xff) as u8;

    buf[IP_HDR_LEN + GRE_HDR_LEN..].copy_from_slice(payload);

    // Protocol 47 = GRE
    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Gre,
        ip_total,
    );
    buf
}

/// Build a spoofed IPv4/TCP packet.
pub fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_total = TCP_HDR_LEN + payload.len();
    let ip_total = IP_HDR_LEN + tcp_total;

    let mut buf = vec![0u8; ip_total];

    {
        let tcp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt = MutableTcpPacket::new(tcp_buf).unwrap();
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_sequence(seq);
        pkt.set_acknowledgement(ack);
        pkt.set_data_offset(5);
        pkt.set_flags(flags);
        pkt.set_window(65535);
        pkt.set_payload(payload);
        let cksum = pnet_packet::tcp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(
        &mut buf,
        src_ip,
        dst_ip,
        IpNextHeaderProtocols::Tcp,
        ip_total,
    );
    buf
}

fn fill_ipv4_header(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: pnet_packet::ip::IpNextHeaderProtocol,
    ip_total: usize,
) {
    let mut pkt = MutableIpv4Packet::new(buf).unwrap();
    pkt.set_version(4);
    pkt.set_header_length(5); // 5 × 4 = 20 bytes
    pkt.set_dscp(0);
    pkt.set_ecn(0);
    pkt.set_total_length(ip_total as u16);
    pkt.set_identification(IP_ID_COUNTER.fetch_add(1, Ordering::Relaxed));
    // Leave DF clear: let the network fragment if needed.  CandyTunnel already
    // limits payload to the configured MTU so fragmentation is rare in practice,
    // but a hard DF causes silent black-holes when the path MTU is smaller.
    pkt.set_flags(0u8);
    pkt.set_fragment_offset(0);
    pkt.set_ttl(SPOOF_TTL);
    pkt.set_next_level_protocol(protocol);
    pkt.set_source(src_ip);
    pkt.set_destination(dst_ip);
    pkt.set_checksum(0); // zero before computing
    let cksum = pnet_packet::ipv4::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);
}
