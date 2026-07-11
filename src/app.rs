//! Shared runtime for client and server binaries.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::Bytes;
use async_channel as mpsc;
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::StatusCode;
use serde::Serialize;
use sha2::Sha256;

use crate::config::{Config, TunnelProtocol};
use crate::port_forward::PortForwardGuard;
use crate::quic::{spawn_quic_client, spawn_quic_server};
use crate::raw_socket::{PortFilter, RawReceiver, RawSender};
use crate::tun::TunDevice;
use crate::tun_bridge::{
    run_tun_reader, spawn_tun_writer, spawn_tunnel_to_tun, TunnelPool,
};
use crate::tunnel::{PacketSender, PeerAddr, TunnelManager};

const LICENSE_URL: &str = "http://verify.litelag.ir/verify";
const LICENSE_HMAC_KEY: &str = "change-this-to-a-long-random-secret";
const LICENSE_TIMEOUT_SECS: u64 = 10;

#[derive(Serialize)]
struct LicenseVerifyRequest<'a> {
    password: &'a str,
    ts: i64,
    nonce: &'a str,
    sig: &'a str,
}

fn sign_license_args(password: &str, ts: i64, nonce: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(LICENSE_HMAC_KEY.as_bytes())
        .expect("HMAC key must be valid");
    mac.update(ts.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    mac.update(b"|");
    mac.update(password.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub async fn verify_license(password: &str) -> Result<()> {
    let ts = chrono::Utc::now().timestamp();
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    let sig = sign_license_args(password, ts, &nonce);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(LICENSE_TIMEOUT_SECS))
        .build()?;

    let resp = client
        .post(LICENSE_URL)
        .header("X-License-Ts", ts)
        .header("X-License-Nonce", &nonce)
        .header("X-License-Sig", &sig)
        .json(&LicenseVerifyRequest {
            password,
            ts,
            nonce: &nonce,
            sig: &sig,
        })
        .send()
        .await?;

    if resp.status() == StatusCode::OK {
        Ok(())
    } else {
        bail!("license verification failed ({})", resp.status())
    }
}

pub async fn run_client(cfg: Arc<Config>) -> Result<()> {
    log::info!(
        "CandyTunnel client starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    let use_quic = cfg.uplink_protocol == TunnelProtocol::Quic
        || cfg.downlink_protocol == TunnelProtocol::Quic;
    if use_quic
        && (cfg.uplink_protocol != TunnelProtocol::Quic
            || cfg.downlink_protocol != TunnelProtocol::Quic)
    {
        bail!("quic requires both uplink_protocol and downlink_protocol = quic");
    }
    if use_quic && cfg.mux_fec_config().is_enabled() {
        log::warn!("mux/fec is ignored when using quic transport");
    }
    if cfg.uplink_protocol == TunnelProtocol::Tcp && cfg.mux_fec_config().is_enabled() {
        log::warn!("mux/fec is ignored when using tcp transport");
    }
    if use_quic && cfg.shuffle_data_port {
        bail!("shuffle_data_port is not supported with quic transport");
    }

    log::debug!(
        "client transport config uplink={:?} downlink={:?} quic={} mux_fec={} proto58={} shuffle={} range={:?}",
        cfg.uplink_protocol,
        cfg.downlink_protocol,
        use_quic,
        cfg.mux_fec_config().is_enabled(),
        matches!(cfg.uplink_protocol, TunnelProtocol::Proto58) || matches!(cfg.downlink_protocol, TunnelProtocol::Proto58),
        cfg.shuffle_data_port,
        cfg.shuffle_port_range()
    );

    let data_ports = cfg.build_data_port_pool()?;
    if let Some(ports) = &data_ports {
        log::debug!("client shuffle pool size={}", ports.len());
    }
    let port_filter = PortFilter::new(
        cfg.data_port,
        data_ports.clone(),
        cfg.shuffle_port_range(),
    );

    let xor_cipher = cfg.xor_cipher();
    let dpi = cfg.dpi_obfuscation();
    log::debug!("client xor_encryption={} dpi_padding={} ttl_jitter={} fake_tls={} dscp={}",
        xor_cipher.is_some(), dpi.packet_padding, dpi.ttl_jitter, dpi.fake_tls_header, dpi.random_dscp);
    let sender = RawSender::spawn(cfg.io_channel_capacity, xor_cipher.clone(), dpi.clone())?;

    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    log::debug!("client allowed_peers count={}", allowed.len());

    let (packet_sender, mut receiver) = if use_quic {
        let (qs, qr) = spawn_quic_client(sender, cfg.clone(), allowed)?;
        (PacketSender::Quic(qs), PacketReceiver::Quic(qr))
    } else {
        let rx = RawReceiver::spawn(
            cfg.downlink_protocol,
            port_filter,
            cfg.icmp_id,
            cfg.random_icmp_id,
            allowed,
            cfg.mux_fec_config(),
            cfg.io_channel_capacity,
            xor_cipher,
            dpi,
        )?;
        let peer_addr = PeerAddr {
            local_spoof: cfg.pick_spoofed_ip(),
            peer_real:   cfg.peer_real_ip,
            data_port:   cfg.data_port,
            data_ports:  data_ports.clone(),
            icmp_id:     cfg.icmp_id,
            random_icmp_id: cfg.random_icmp_id,
            is_server:   false,
        };
        let mux_fec = if cfg.mux_fec_config().is_enabled()
            && matches!(cfg.uplink_protocol, TunnelProtocol::Udp | TunnelProtocol::Icmp | TunnelProtocol::Proto58 | TunnelProtocol::Ipip | TunnelProtocol::Gre) {
            Some(crate::mux_fec::MuxFecSender::spawn(
                cfg.mux_fec_config(),
                sender.clone(),
                peer_addr.clone(),
                cfg.uplink_protocol,
                cfg.io_channel_capacity,
            )?)
        } else {
            None
        };
        (
            PacketSender::Raw { sender, addr: peer_addr, mux_fec },
            PacketReceiver::Raw(rx),
        )
    };

    let manager = TunnelManager::new(packet_sender, cfg.clone());

    let mgr2 = manager.clone();
    tokio::spawn(async move {
        loop {
            let Some(incoming) = receiver.recv().await else { break; };
            log::trace!("client recv packet kind={:?} src={}", incoming.pkt.kind, incoming.src_ip);
            if let Err(e) = mgr2
                .handle_incoming(incoming.src_ip, incoming.pkt)
                .await
            {
                log::warn!("handle_incoming: {}", e);
            }
        }
    }
    );

    let mgr3 = manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Err(e) = mgr3.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    }
    );

    run_tun_client(cfg, manager).await
}

pub async fn run_server(cfg: Arc<Config>, allow_any: bool) -> Result<()> {
    // License verification should be handled by the server binary.
    if cfg.channel_capacity == 0 {
        bail!("channel_capacity must be > 0");
    }

    log::info!(
        "CandyTunnel server starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    let use_quic = cfg.uplink_protocol == TunnelProtocol::Quic
        || cfg.downlink_protocol == TunnelProtocol::Quic;
    if use_quic
        && (cfg.uplink_protocol != TunnelProtocol::Quic
            || cfg.downlink_protocol != TunnelProtocol::Quic)
    {
        bail!("quic requires both uplink_protocol and downlink_protocol = quic");
    }
    if use_quic && cfg.mux_fec_config().is_enabled() {
        log::warn!("mux/fec is ignored when using quic transport");
    }
    if cfg.uplink_protocol == TunnelProtocol::Tcp && cfg.mux_fec_config().is_enabled() {
        log::warn!("mux/fec is ignored when using tcp transport");
    }
    if use_quic && cfg.shuffle_data_port {
        bail!("shuffle_data_port is not supported with quic transport");
    }

    log::debug!(
        "server transport config uplink={:?} downlink={:?} quic={} mux_fec={} proto58={} shuffle={} range={:?} allow_any={}",
        cfg.uplink_protocol,
        cfg.downlink_protocol,
        use_quic,
        cfg.mux_fec_config().is_enabled(),
        matches!(cfg.uplink_protocol, TunnelProtocol::Proto58) || matches!(cfg.downlink_protocol, TunnelProtocol::Proto58),
        cfg.shuffle_data_port,
        cfg.shuffle_port_range(),
        allow_any
    );

    let data_ports = cfg.build_data_port_pool()?;
    if let Some(ports) = &data_ports {
        log::debug!("server shuffle pool size={}", ports.len());
    }
    let port_filter = PortFilter::new(
        cfg.data_port,
        data_ports.clone(),
        cfg.shuffle_port_range(),
    );

    let xor_cipher = cfg.xor_cipher();
    let dpi = cfg.dpi_obfuscation();
    log::debug!("server xor_encryption={} dpi_padding={} ttl_jitter={} fake_tls={} dscp={}",
        xor_cipher.is_some(), dpi.packet_padding, dpi.ttl_jitter, dpi.fake_tls_header, dpi.random_dscp);
    let sender = RawSender::spawn(cfg.io_channel_capacity, xor_cipher.clone(), dpi.clone())?;

    let mut allowed = if allow_any { Vec::new() } else { cfg.allowed_peers.clone() };
    if !allow_any {
        allowed.push(cfg.peer_real_ip);
        allowed.push(cfg.peer_spoofed_ip);
    }
    log::debug!("server allowed_peers count={}", allowed.len());

    let (packet_sender, mut receiver) = if use_quic {
        let (qs, qr) = spawn_quic_server(sender, cfg.clone(), allowed)?;
        (PacketSender::Quic(qs), PacketReceiver::Quic(qr))
    } else {
        let rx = RawReceiver::spawn(
            cfg.downlink_protocol,
            port_filter,
            cfg.icmp_id,
            cfg.random_icmp_id,
            allowed,
            cfg.mux_fec_config(),
            cfg.io_channel_capacity,
            xor_cipher,
            dpi,
        )?;
        let peer_addr = PeerAddr {
            local_spoof: cfg.pick_spoofed_ip(),
            peer_real:   cfg.peer_real_ip,
            data_port:   cfg.data_port,
            data_ports:  data_ports.clone(),
            icmp_id:     cfg.icmp_id,
            random_icmp_id: cfg.random_icmp_id,
            is_server:   true,
        };
        let mux_fec = if cfg.mux_fec_config().is_enabled()
            && matches!(cfg.uplink_protocol, TunnelProtocol::Udp | TunnelProtocol::Icmp | TunnelProtocol::Proto58 | TunnelProtocol::Ipip | TunnelProtocol::Gre) {
            Some(crate::mux_fec::MuxFecSender::spawn(
                cfg.mux_fec_config(),
                sender.clone(),
                peer_addr.clone(),
                cfg.uplink_protocol,
                cfg.io_channel_capacity,
            )?)
        } else {
            None
        };
        (
            PacketSender::Raw { sender, addr: peer_addr, mux_fec },
            PacketReceiver::Raw(rx),
        )
    };

    let manager = TunnelManager::new(packet_sender, cfg.clone());

    let tun_mtu = if cfg.tun_mtu == 0 { cfg.mtu } else { cfg.tun_mtu.min(cfg.mtu) };
    if cfg.tun_mtu > cfg.mtu {
        log::warn!("tun_mtu {} > mtu {} - clamping", cfg.tun_mtu, cfg.mtu);
    }

    let tun = Arc::new(TunDevice::create(
        &cfg.tun_name,
        cfg.tun_ip,
        cfg.tun_peer_ip,
        cfg.tun_netmask,
        tun_mtu,
    )?);

    let pool = TunnelPool::new();

    let (net_to_tun_tx, net_to_tun_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cfg.channel_capacity);
    spawn_tun_writer(tun.clone(), net_to_tun_rx);

    let tun_reader = tun.clone();
    let pool_reader = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tun_reader(tun_reader, pool_reader, &[]).await {
            log::warn!("tun reader stopped: {}", e);
        }
    }
    );

    log::info!(
        "TUN {} up ({} <-> {}) mtu {}",
        tun.name(),
        cfg.tun_ip,
        cfg.tun_peer_ip,
        tun.mtu()
    );

    let mgr_tick = manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Err(e) = mgr_tick.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    }
    );

    loop {
        let incoming = match receiver.recv().await {
            Some(p) => p,
            None    => break,
        };

        log::trace!("server recv packet kind={:?} src={}", incoming.pkt.kind, incoming.src_ip);

        if !allow_any && !cfg.is_peer_allowed(&incoming.src_ip) {
            log::trace!("dropping packet from disallowed IP {}", incoming.src_ip);
            continue;
        }

        match manager
            .handle_incoming(incoming.src_ip, incoming.pkt)
            .await
        {
            Ok(Some((syn_pkt, src_ip))) => {
                match manager.accept_syn(syn_pkt, src_ip).await {
                    Ok((tid, app_rx, net_tx)) => {
                        pool.add_tunnel(tid, net_tx).await;
                        spawn_tunnel_to_tun(app_rx, net_to_tun_tx.clone());
                        log::info!("tunnel {} ready", tid);
                    }
                    Err(e) => log::warn!("accept_syn: {}", e),
                }
            }
            Ok(None) => {},
            Err(e) => log::warn!("handle_incoming: {}", e),
        }
    }

    Ok(())
}

async fn run_tun_client(cfg: Arc<Config>, manager: TunnelManager) -> Result<()> {
    if cfg.tunnel_count == 0 {
        bail!("tunnel_count must be > 0");
    }
    if cfg.channel_capacity == 0 {
        bail!("channel_capacity must be > 0");
    }

    let tun_mtu = if cfg.tun_mtu == 0 {
        cfg.mtu
    } else {
        cfg.tun_mtu.min(cfg.mtu)
    };
    if cfg.tun_mtu > cfg.mtu {
        log::warn!("tun_mtu {} > mtu {} - clamping", cfg.tun_mtu, cfg.mtu);
    }

    let tun = Arc::new(TunDevice::create(
        &cfg.tun_name,
        cfg.tun_ip,
        cfg.tun_peer_ip,
        cfg.tun_netmask,
        tun_mtu,
    )?);

    let forward_ports = cfg.effective_forward_ports();
    log::debug!("client forward_ports count={}", forward_ports.len());

    let _port_forward = PortForwardGuard::apply(&cfg)?;

    let pool = TunnelPool::new();

    let (net_to_tun_tx, net_to_tun_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cfg.channel_capacity);
    spawn_tun_writer(tun.clone(), net_to_tun_rx);

    for _ in 0..cfg.tunnel_count {
        let (tid, app_rx, net_tx) = manager.open_tunnel().await?;
        if !manager.wait_established(tid, Duration::from_secs(15)).await {
            bail!("tunnel {} handshake timed out", tid);
        }
        pool.add_tunnel(tid, net_tx).await;
        spawn_tunnel_to_tun(app_rx, net_to_tun_tx.clone());
    }

    log::info!("{} tunnels established", cfg.tunnel_count);

    log::info!(
        "TUN {} up ({} <-> {}) mtu {}",
        tun.name(),
        cfg.tun_ip,
        cfg.tun_peer_ip,
        tun.mtu()
    );

    if forward_ports.is_empty() {
        log::warn!("forward_ports empty - forwarding all TCP/UDP ports");
    } else {
        log::info!("forwarding TCP/UDP ports {:?}", forward_ports);
    }

    run_tun_reader(tun, pool, &forward_ports).await
}

enum PacketReceiver {
    Raw(RawReceiver),
    Quic(crate::quic::QuicReceiver),
}

impl PacketReceiver {
    async fn recv(&mut self) -> Option<crate::raw_socket::InPacket> {
        match self {
            PacketReceiver::Raw(r) => r.recv().await,
            PacketReceiver::Quic(r) => r.recv().await,
        }
    }
}
