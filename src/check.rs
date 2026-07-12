//! Spoofed IP reachability and latency check mode.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use pnet_packet::tcp::TcpFlags;
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::io::AsyncWriteExt;

use crate::config::{Config, TunnelProtocol};
use crate::packet::{CandyPacket, PacketKind};
use crate::raw_socket::{InPacket, OutPacket, PortFilter, RawReceiver, RawSender};

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub ips_path: String,
    pub out_path: String,
    pub timeout: Duration,
    pub workers: usize,
}

pub async fn run_spoof_check(cfg: Arc<Config>, opts: CheckOptions) -> Result<()> {
    if cfg.uplink_protocol == TunnelProtocol::Quic || cfg.downlink_protocol == TunnelProtocol::Quic {
        bail!("check mode is not supported with quic transport");
    }

    let ips = read_ip_list(&opts.ips_path)?;
    if ips.is_empty() {
        bail!("no IPs found in {}", opts.ips_path);
    }

    log::info!("check start ips={} timeout_ms={} workers={}", ips.len(), opts.timeout.as_millis(), opts.workers);

    let sender = RawSender::spawn(cfg.io_channel_capacity, cfg.xor_cipher(), cfg.dpi_obfuscation())?;

    let data_ports = cfg.build_data_port_pool()?;
    if let Some(ports) = &data_ports {
        log::debug!("check shuffle pool size={}", ports.len());
    }
    let port_filter = PortFilter::new(
        cfg.data_port,
        data_ports.clone(),
        cfg.shuffle_port_range(),
    );

    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);

    let mut receiver = RawReceiver::spawn(
        cfg.downlink_protocol,
        port_filter,
        cfg.icmp_id,
        cfg.random_icmp_id,
        allowed,
        cfg.mux_fec_config(),
        cfg.io_channel_capacity,
        cfg.xor_cipher(),
        cfg.dpi_obfuscation(),
    )?;

    let pending: Arc<DashMap<u32, oneshot::Sender<Instant>>> = Arc::new(DashMap::new());
    let pending_rx = pending.clone();
    tokio::spawn(async move {
        while let Some(pkt) = receiver.recv().await {
            handle_incoming(pkt, &pending_rx);
        }
    });

    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&opts.out_path)
        .await
        .with_context(|| format!("open {}", opts.out_path))?;
    let file = Arc::new(Mutex::new(file));

    let workers = opts.workers.max(1);
    let sem = Arc::new(Semaphore::new(workers));

    let mut tasks = Vec::with_capacity(ips.len());
    for ip in ips {
        let permit = sem.clone().acquire_owned().await?;
        let sender = sender.clone();
        let pending = pending.clone();
        let cfg = cfg.clone();
        let file = file.clone();
        let file_err = file.clone();
        let timeout = opts.timeout;
        let data_ports = data_ports.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            log::trace!("check ip start={}", ip);
            if let Err(e) = check_one_ip(cfg, sender, pending, file, ip, timeout, &data_ports).await {
                log::warn!("check {} failed: {}", ip, e);
                let mut f = file_err.lock().await;
                let _ = f.write_all(format!("{} error\n", ip).as_bytes()).await;
                let _ = f.flush().await;
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    log::info!("check complete: results written to {}", opts.out_path);
    Ok(())
}

fn handle_incoming(pkt: InPacket, pending: &DashMap<u32, oneshot::Sender<Instant>>) {
    if pkt.pkt.kind != PacketKind::SynAck {
        return;
    }
    if let Some((_, tx)) = pending.remove(&pkt.pkt.tunnel_id) {
        let _ = tx.send(Instant::now());
    }
}

async fn check_one_ip(
    cfg: Arc<Config>,
    sender: RawSender,
    pending: Arc<DashMap<u32, oneshot::Sender<Instant>>>,
    file: Arc<Mutex<tokio::fs::File>>,
    spoof_ip: Ipv4Addr,
    timeout: Duration,
    data_ports: &Option<std::sync::Arc<Vec<u16>>>,
) -> Result<()> {
    let tunnel_id: u32 = rand::random();
    let seq: u32 = rand::random();
    let syn = CandyPacket::new_syn(tunnel_id, seq);

    let (tx, rx) = oneshot::channel();
    pending.insert(tunnel_id, tx);

    let out = build_out_packet(&cfg, spoof_ip, syn.seq, syn.encode(), data_ports)?;
    let start = Instant::now();
    sender.send(out).await?;

    let result = tokio::time::timeout(timeout, rx).await;
    let latency_ms = match result {
        Ok(Ok(_ts)) => start.elapsed().as_millis(),
        _ => {
            pending.remove(&tunnel_id);
            write_result(&file, spoof_ip, None).await?;
            return Ok(());
        }
    };

    write_result(&file, spoof_ip, Some(latency_ms as u64)).await?;
    Ok(())
}

async fn write_result(file: &Arc<Mutex<tokio::fs::File>>, ip: Ipv4Addr, latency_ms: Option<u64>) -> Result<()> {
    let mut f = file.lock().await;
    let line = match latency_ms {
        Some(ms) => format!("{} {}\n", ip, ms),
        None => format!("{} timeout\n", ip),
    };
    f.write_all(line.as_bytes()).await?;
    f.flush().await?;
    Ok(())
}

fn build_out_packet(
    cfg: &Config,
    spoof_ip: Ipv4Addr,
    seq: u32,
    payload: Bytes,
    data_ports: &Option<std::sync::Arc<Vec<u16>>>,
) -> Result<OutPacket> {
    let data_port = crate::config::pick_data_port(cfg.data_port, data_ports);
    match cfg.uplink_protocol {
        TunnelProtocol::Udp => Ok(OutPacket::Udp {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            src_port: data_port,
            dst_port: data_port,
            payload,
        }),
        TunnelProtocol::Icmp => {
            Ok(OutPacket::Icmp {
                src_ip: spoof_ip,
                dst_ip: cfg.peer_real_ip,
                id: cfg.pick_icmp_id(),
                seq: (seq & 0xffff) as u16,
                payload,
            })
        }
        TunnelProtocol::Proto58 => Ok(OutPacket::Proto58 {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Tcp => Ok(OutPacket::Tcp {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            src_port: data_port,
            dst_port: data_port,
            seq,
            ack: seq.wrapping_add(payload.len().max(1) as u32),
            flags: (TcpFlags::PSH | TcpFlags::ACK) as u8,
            payload,
        }),
        TunnelProtocol::Ipip => Ok(OutPacket::Ipip {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Gre => Ok(OutPacket::Gre {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Quic => bail!("check mode does not support quic"),
    }
}

fn read_ip_list(path: &str) -> Result<Vec<Ipv4Addr>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            out.push(ip);
        }
    }
    Ok(out)
}
