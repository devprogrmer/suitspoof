//! QUIC transport for CandyTunnel using quiche.
//!
//! This module transports CandyPacket payloads over a single QUIC
//! bidirectional stream (stream ID 0) carried in spoofed UDP packets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_channel as mpsc;
use async_lock::Mutex;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::config::Config;
use crate::packet::CandyPacket;
use crate::raw_socket::{InPacket, OutPacket, PortFilter, RawSender, RawUdpReceiver, UdpDatagram};

const STREAM_ID: u64 = 0;

#[derive(Clone)]
pub struct QuicSender {
    inner: Arc<Inner>,
}

pub struct QuicReceiver {
    rx: mpsc::Receiver<CandyPacket>,
    src_ip: Ipv4Addr,
}

struct Inner {
    conn: Mutex<Option<quiche::Connection>>,
    config: Mutex<quiche::Config>,
    sender: RawSender,
    local_spoof: Ipv4Addr,
    peer_real: Ipv4Addr,
    peer_spoof: Ipv4Addr,
    data_port: u16,
    max_udp: usize,
    stream_buf: Mutex<BytesMut>,
    recv_tx: mpsc::Sender<CandyPacket>,
    io_capacity: usize,
}

pub fn spawn_quic_client(
    sender: RawSender,
    cfg: Arc<Config>,
    allowed: Vec<Ipv4Addr>,
) -> Result<(QuicSender, QuicReceiver)> {
    log::info!(
        "quic client init peer_real={} peer_spoof={} port={}",
        cfg.peer_real_ip,
        cfg.peer_spoofed_ip,
        cfg.data_port
    );
    let local_spoof = cfg.pick_spoofed_ip();
    let max_udp = cfg.mtu.max(1200).min(1350);
    let mut config = build_quic_config(&cfg, false, max_udp)?;

    let scid_seed = rand::random::<[u8; 16]>();
    let scid = quiche::ConnectionId::from_ref(&scid_seed[..]);
    let local = SocketAddr::new(IpAddr::V4(local_spoof), cfg.data_port);
    let peer = SocketAddr::new(IpAddr::V4(cfg.peer_spoofed_ip), cfg.data_port);
    let conn = quiche::connect(
        Some(cfg.quic_server_name.as_str()),
        &scid,
        local,
        peer,
        &mut config,
    )
    .context("quic connect")?;

    let (recv_tx, recv_rx) = mpsc::bounded(cfg.channel_capacity);
    let inner = Arc::new(Inner {
        conn: Mutex::new(Some(conn)),
        config: Mutex::new(config),
        sender,
        local_spoof,
        peer_real: cfg.peer_real_ip,
        peer_spoof: cfg.peer_spoofed_ip,
        data_port: cfg.data_port,
        max_udp,
        stream_buf: Mutex::new(BytesMut::new()),
        recv_tx,
        io_capacity: cfg.io_channel_capacity,
    });

    spawn_quic_tasks(inner.clone(), allowed, true);

    let sender = QuicSender {
        inner: inner.clone(),
    };
    let receiver = QuicReceiver {
        rx: recv_rx,
        src_ip: cfg.peer_spoofed_ip,
    };

    Ok((sender, receiver))
}

pub fn spawn_quic_server(
    sender: RawSender,
    cfg: Arc<Config>,
    allowed: Vec<Ipv4Addr>,
) -> Result<(QuicSender, QuicReceiver)> {
    log::info!(
        "quic server init peer_real={} peer_spoof={} port={}",
        cfg.peer_real_ip,
        cfg.peer_spoofed_ip,
        cfg.data_port
    );
    let local_spoof = cfg.pick_spoofed_ip();
    let max_udp = cfg.mtu.max(1200).min(1350);
    let config = build_quic_config(&cfg, true, max_udp)?;

    let (recv_tx, recv_rx) = mpsc::bounded(cfg.channel_capacity);
    let inner = Arc::new(Inner {
        conn: Mutex::new(None),
        config: Mutex::new(config),
        sender,
        local_spoof,
        peer_real: cfg.peer_real_ip,
        peer_spoof: cfg.peer_spoofed_ip,
        data_port: cfg.data_port,
        max_udp,
        stream_buf: Mutex::new(BytesMut::new()),
        recv_tx,
        io_capacity: cfg.io_channel_capacity,
    });

    spawn_quic_tasks(inner.clone(), allowed, false);

    let sender = QuicSender {
        inner: inner.clone(),
    };
    let receiver = QuicReceiver {
        rx: recv_rx,
        src_ip: cfg.peer_spoofed_ip,
    };

    Ok((sender, receiver))
}

impl QuicSender {
    pub async fn send(&self, pkt: CandyPacket) -> Result<()> {
        let enc = pkt.encode();
        let mut frame = BytesMut::with_capacity(4 + enc.len());
        frame.put_u32(enc.len() as u32);
        frame.extend_from_slice(&enc);
        let data = frame.freeze();

        let mut offset = 0usize;
        while offset < data.len() {
            let mut guard = self.inner.conn.lock().await;
            let Some(conn) = guard.as_mut() else {
                return Err(anyhow!("quic connection not established yet"));
            };

            if !conn.is_established() {
                drop(guard);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            match conn.stream_send(STREAM_ID, &data[offset..], false) {
                Ok(n) => offset += n,
                Err(quiche::Error::Done) | Err(quiche::Error::StreamLimit) => {
                    drop(guard);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
                Err(e) => return Err(anyhow!("quic stream_send: {e}")),
            }

            flush_send_locked(conn, &self.inner).await?;
        }

        Ok(())
    }
}

impl QuicReceiver {
    pub async fn recv(&mut self) -> Option<InPacket> {
        let pkt = self.rx.recv().await.ok()?;
        Some(InPacket {
            src_ip: self.src_ip,
            pkt,
        })
    }
}

fn spawn_quic_tasks(inner: Arc<Inner>, allowed: Vec<Ipv4Addr>, is_client: bool) {
    log::debug!(
        "quic tasks spawn client={} allowed_peers={}",
        is_client,
        allowed.len()
    );
    let port_filter = PortFilter::new(inner.data_port, None, None);
    let mut receiver = match RawUdpReceiver::spawn(port_filter, allowed, inner.io_capacity) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("quic udp receiver failed: {}", e);
            return;
        }
    };

    let recv_inner = inner.clone();
    tokio::spawn(async move {
        if is_client {
            let mut guard = recv_inner.conn.lock().await;
            if let Some(conn) = guard.as_mut() {
                if let Err(e) = flush_send_locked(conn, &recv_inner).await {
                    log::warn!("quic initial flush: {}", e);
                }
            }
        }

        loop {
            let Some(datagram) = receiver.recv().await else {
                break;
            };

            log::trace!(
                "quic udp datagram src={} sport={} dport={} len={}",
                datagram.src_ip,
                datagram.src_port,
                datagram.dst_port,
                datagram.payload.len()
            );

            if let Err(e) = handle_udp_datagram(&recv_inner, datagram).await {
                log::trace!("quic recv: {}", e);
            }
        }
    });

    let timer_inner = inner.clone();
    tokio::spawn(async move {
        loop {
            let timeout = {
                let guard = timer_inner.conn.lock().await;
                guard.as_ref().and_then(|c| c.timeout())
            };

            let Some(delay) = timeout else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };

            tokio::time::sleep(delay).await;

            let mut guard = timer_inner.conn.lock().await;
            let Some(conn) = guard.as_mut() else {
                continue;
            };
            conn.on_timeout();
            if let Err(e) = flush_send_locked(conn, &timer_inner).await {
                log::warn!("quic timeout flush: {}", e);
            }
        }
    });
}

async fn handle_udp_datagram(inner: &Arc<Inner>, datagram: UdpDatagram) -> Result<()> {
    let mut guard = inner.conn.lock().await;
    if guard.is_none() {
        let mut cfg = inner.config.lock().await;
        let mut hdr_buf = datagram.payload.to_vec();
        let hdr = quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN)
            .context("quic parse header")?;
        let scid_seed = rand::random::<[u8; 16]>();
        let scid = quiche::ConnectionId::from_ref(&scid_seed[..]);

        let local = SocketAddr::new(IpAddr::V4(inner.local_spoof), inner.data_port);
        let peer = SocketAddr::new(IpAddr::V4(inner.peer_spoof), inner.data_port);
        let conn = quiche::accept(&scid, Some(&hdr.dcid), local, peer, &mut *cfg)
            .context("quic accept")?;
        *guard = Some(conn);
        log::info!(
            "quic connection accepted scid_len={} peer={}",
            scid.len(),
            datagram.src_ip
        );
    }

    let Some(conn) = guard.as_mut() else {
        return Err(anyhow!("quic connection not ready"));
    };

    let mut buf = datagram.payload.to_vec();
    let from = SocketAddr::new(IpAddr::V4(datagram.src_ip), datagram.src_port);
    let to = SocketAddr::new(IpAddr::V4(inner.local_spoof), datagram.dst_port);
    match conn.recv(&mut buf, quiche::RecvInfo { from, to }) {
        Ok(_) => {}
        Err(quiche::Error::Done) => {}
        Err(e) => return Err(anyhow!("quic recv: {e}")),
    }

    process_readable(conn, inner).await?;
    flush_send_locked(conn, inner).await?;

    Ok(())
}

async fn process_readable(conn: &mut quiche::Connection, inner: &Arc<Inner>) -> Result<()> {
    let readable: Vec<u64> = conn.readable().collect();
    for stream_id in readable {
        loop {
            let mut buf = vec![0u8; 4096];
            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, _fin)) => {
                    if len == 0 {
                        break;
                    }
                    let mut stream_buf = inner.stream_buf.lock().await;
                    stream_buf.extend_from_slice(&buf[..len]);
                    drain_frames(&mut stream_buf, &inner.recv_tx)?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(anyhow!("quic stream_recv: {e}")),
            }
        }
    }
    Ok(())
}

fn drain_frames(buf: &mut BytesMut, tx: &mpsc::Sender<CandyPacket>) -> Result<()> {
    loop {
        if buf.len() < 4 {
            return Ok(());
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return Ok(());
        }
        buf.advance(4);
        let payload = buf.split_to(len).freeze();
        match CandyPacket::decode(payload) {
            Ok(pkt) => {
                let _ = tx.send_blocking(pkt);
            }
            Err(e) => {
                log::trace!("quic decode: {}", e);
            }
        }
    }
}

async fn flush_send_locked(conn: &mut quiche::Connection, inner: &Arc<Inner>) -> Result<()> {
    let mut out = vec![0u8; inner.max_udp];
    loop {
        match conn.send(&mut out) {
            Ok((len, _info)) => {
                let payload = Bytes::copy_from_slice(&out[..len]);
                let out_pkt = OutPacket::Udp {
                    src_ip: inner.local_spoof,
                    dst_ip: inner.peer_real,
                    src_port: inner.data_port,
                    dst_port: inner.data_port,
                    payload,
                };
                inner.sender.send(out_pkt).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(anyhow!("quic send: {e}")),
        }
    }
    Ok(())
}

fn build_quic_config(cfg: &Config, is_server: bool, max_udp: usize) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).context("quic config")?;

    let alpn = vec![cfg.quic_alpn.as_bytes().to_vec()];
    let alpn_refs: Vec<&[u8]> = alpn.iter().map(|p| p.as_slice()).collect();
    config
        .set_application_protos(&alpn_refs)
        .context("quic alpn")?;

    config.set_max_idle_timeout(cfg.quic_idle_timeout_ms);
    config.set_max_recv_udp_payload_size(max_udp);
    config.set_max_send_udp_payload_size(max_udp);
    config.set_initial_max_data(cfg.quic_max_data);
    config.set_initial_max_stream_data_bidi_local(cfg.quic_max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(cfg.quic_max_stream_data);
    config.set_initial_max_streams_bidi(cfg.quic_max_streams_bidi);
    config.set_disable_active_migration(true);
    config.verify_peer(false);

    if is_server {
        config
            .load_cert_chain_from_pem_file(&cfg.quic_cert)
            .context("quic load cert")?;
        config
            .load_priv_key_from_pem_file(&cfg.quic_key)
            .context("quic load key")?;
    }

    Ok(config)
}

// ALPN formatting handled in build_quic_config.
