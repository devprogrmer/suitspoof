//! Tunnel state machine and manager.
//!
//! A [`Tunnel`] represents a single logical bidirectional stream between client
//! and server. It tracks sequencing and liveness for best-effort delivery.
//!
//! [`TunnelManager`] multiplexes/demultiplexes packets across all active tunnels
//! (keyed by `tunnel_id`) and provides the async interface used by the TUN
//! forwarding code on both client and server.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use async_channel as mpsc;
use async_lock::Mutex;
use bytes::Bytes;
use dashmap::DashMap;
use event_listener::Event;
use futures_lite::future;

use crate::config::Config;
use crate::config::TunnelProtocol;
use crate::mux_fec::MuxFecSender;
use crate::packet::{CandyPacket, PacketKind};
use crate::quic::QuicSender;
use crate::raw_socket::{OutPacket, RawSender};

const HEARTBEAT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_MIN_INTERVAL: Duration = Duration::from_secs(2);

// ── Tunnel state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
}

/// Internal state for a single tunnel.
struct Tunnel {
    id: u32,
    state: TunnelState,
    send_next: u32,
    tcp_seq_next: u32,
    tcp_ack_next: u32,
    icmp_seq_next: u16,
    /// Deliver received application data to the owner of this tunnel.
    app_tx: mpsc::Sender<Bytes>,
    last_active: Instant,
    last_heartbeat_sent: Instant,
    /// Notified when the tunnel transitions to Established.
    established_notify: Arc<Event>,
}

impl Tunnel {
    fn new(id: u32, state: TunnelState, init_seq: u32, app_tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            id,
            state,
            send_next: init_seq,
            tcp_seq_next: rand::random::<u32>(),
            tcp_ack_next: rand::random::<u32>(),
            icmp_seq_next: rand::random::<u16>(),
            app_tx,
            last_active: Instant::now(),
            last_heartbeat_sent: Instant::now(),
            established_notify: Arc::new(Event::new()),
        }
    }

    fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_active) > timeout
    }

    fn apply_syn_ack(&mut self, _syn_ack: &CandyPacket) -> bool {
        if self.state != TunnelState::SynSent {
            return false;
        }
        self.state = TunnelState::Established;
        true
    }

    fn make_data_packet(&mut self, payload: Bytes) -> CandyPacket {
        let seq = self.send_next;
        self.send_next = self.send_next.wrapping_add(1);
        CandyPacket::new_data(self.id, seq, payload)
    }
}

// ── Remote addressing ─────────────────────────────────────────────────────────

/// The addressing information needed to build spoofed outgoing packets.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// Source IP we spoof on outgoing packets.
    pub local_spoof: Ipv4Addr,
    /// Destination IP of the peer (their real address).
    pub peer_real: Ipv4Addr,
    /// UDP destination port for the data channel.
    pub data_port: u16,
    /// Optional shuffled data port pool (UDP/TCP only).
    pub data_ports: Option<std::sync::Arc<Vec<u16>>>,
    /// ICMP echo identifier for the control channel.
    pub icmp_id: u16,
    /// Randomize ICMP echo identifier per packet.
    pub random_icmp_id: bool,
    /// Whether this endpoint is running in server mode.
    pub is_server: bool,
}

impl PeerAddr {
    pub fn pick_data_port(&self) -> u16 {
        crate::config::pick_data_port(self.data_port, &self.data_ports)
    }

    pub fn pick_icmp_id(&self) -> u16 {
        if self.random_icmp_id {
            rand::random()
        } else {
            self.icmp_id
        }
    }
}

// ── TunnelManager ─────────────────────────────────────────────────────────────

/// Inner state shared through an `Arc`.
pub enum PacketSender {
    Raw {
        sender: RawSender,
        addr: PeerAddr,
        mux_fec: Option<MuxFecSender>,
    },
    Quic(QuicSender),
}

struct Inner {
    tunnels: DashMap<u32, Arc<Mutex<Tunnel>>>,
    /// Per-tunnel event fired when the tunnel reaches Established state.
    established_notifiers: DashMap<u32, Arc<Event>>,
    sender: PacketSender,
    cfg: Arc<Config>,
}

/// Manages all active tunnels.  Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct TunnelManager(Arc<Inner>);

impl TunnelManager {
    pub fn new(sender: PacketSender, cfg: Arc<Config>) -> Self {
        Self(Arc::new(Inner {
            tunnels: DashMap::new(),
            established_notifiers: DashMap::new(),
            sender,
            cfg,
        }))
    }

    // ── Tunnel lifecycle ──────────────────────────────────────────────────────

    /// Open a new client-side tunnel.
    ///
    /// Returns:
    /// - `app_rx`  – receive application data delivered from the peer
    /// - `net_tx`  – send application data into the tunnel
    pub async fn open_tunnel(&self) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id: u32 = rand::random();
        let syn_seq: u32 = rand::random();

        let cap = self.0.cfg.channel_capacity;
        let (app_tx, app_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cap);
        let (net_tx, net_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cap);

        let tunnel = Tunnel::new(
            id,
            TunnelState::SynSent,
            syn_seq.wrapping_add(1), // SYN consumes syn_seq, first DATA is syn_seq+1
            app_tx,
        );
        let established_notify = tunnel.established_notify.clone();
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));

        // Spawn a task that forwards application data to the raw socket.
        self.spawn_send_task(id, net_rx);

        // Send the initial SYN on the control channel.
        let syn = CandyPacket::new_syn(id, syn_seq);
        self.tx_control(syn).await?;

        log::info!("tunnel {} opened (SYN sent)", id);
        log::debug!("tunnel {} state={:?}", id, TunnelState::SynSent);
        // Store the established notifier so is_established can await it.
        self.0.established_notifiers.insert(id, established_notify);
        Ok((id, app_rx, net_tx))
    }

    /// Accept an incoming SYN packet (server side) and create a tunnel.
    ///
    /// Returns the same triple as `open_tunnel`.
    pub async fn accept_syn(
        &self,
        syn: CandyPacket,
        src_ip: Ipv4Addr,
    ) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id = syn.tunnel_id;

        // Reject duplicate tunnels.
        if self.0.tunnels.contains_key(&id) {
            bail!("duplicate tunnel id {}", id);
        }

        let our_seq: u32 = rand::random();
        let cap = self.0.cfg.channel_capacity;
        let (app_tx, app_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cap);
        let (net_tx, net_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(cap);

        let mut tunnel = Tunnel::new(
            id,
            TunnelState::SynReceived,
            our_seq.wrapping_add(1), // SYN-ACK consumes our_seq; first DATA must be seq+1
            app_tx,
        );
        // Server transitions to Established immediately after SYN-ACK.
        tunnel.state = TunnelState::Established;
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));

        self.spawn_send_task(id, net_rx);

        let syn_ack = CandyPacket::new_syn_ack(id, our_seq);
        self.tx_control(syn_ack).await?;

        log::info!("tunnel {} accepted from {}", id, src_ip);
        log::debug!("tunnel {} state={:?}", id, TunnelState::Established);
        Ok((id, app_rx, net_tx))
    }

    /// Close a tunnel and notify the peer.
    pub async fn close_tunnel(&self, id: u32) {
        if let Some((_, t)) = self.0.tunnels.remove(&id) {
            let mut t = t.lock().await;
            t.state = TunnelState::Closed;
        }
        self.0.established_notifiers.remove(&id);

        let fin = CandyPacket::new_fin(id);
        log::debug!("tunnel {} closing (FIN send)", id);
        let _ = self.tx_control(fin).await;
    }

    // ── Incoming packet handler ───────────────────────────────────────────────

    /// Route an incoming packet to the appropriate tunnel.
    ///
    /// Returns `Some((tunnel_id, src_ip))` when a SYN is received (server should
    /// call `accept_syn` for that packet).  Returns `None` for all other types.
    pub async fn handle_incoming(
        &self,
        src_ip: Ipv4Addr,
        pkt: CandyPacket,
    ) -> Result<Option<(CandyPacket, Ipv4Addr)>> {
        // SYN packets are not handled internally – hand them back to the caller.
        if pkt.kind == PacketKind::Syn {
            return Ok(Some((pkt, src_ip)));
        }

        let tunnel = match self.0.tunnels.get(&pkt.tunnel_id) {
            Some(t) => t.clone(),
            None => {
                log::trace!(
                    "received packet for unknown tunnel {} from {}",
                    pkt.tunnel_id,
                    src_ip
                );
                return Ok(None);
            }
        };

        let mut t = tunnel.lock().await;

        t.touch();

        match pkt.kind {
            PacketKind::Syn => unreachable!(), // handled above

            PacketKind::SynAck => {
                if t.apply_syn_ack(&pkt) {
                    log::info!("tunnel {} established", pkt.tunnel_id);
                    log::debug!(
                        "tunnel {} state={:?}",
                        pkt.tunnel_id,
                        TunnelState::Established
                    );
                    let notify = t.established_notify.clone();
                    drop(t);
                    // Wake any task waiting for establishment.
                    notify.notify(usize::MAX);
                }
            }

            PacketKind::Data => {
                let tid = t.id;
                let app_tx = t.app_tx.clone();
                drop(t);

                log::trace!("tunnel {} data len={}", tid, pkt.payload.len());
                if app_tx.send(pkt.payload).await.is_err() {
                    self.close_tunnel(tid).await;
                    return Ok(None);
                }
            }

            PacketKind::Fin => {
                t.state = TunnelState::Closed;
                log::info!("tunnel {} closed by peer", pkt.tunnel_id);
            }

            PacketKind::Heartbeat => {
                let tid = t.id;
                let hb_ack = CandyPacket {
                    kind: PacketKind::HeartbeatAck,
                    tunnel_id: tid,
                    seq: pkt.seq,
                    payload: pkt.payload,
                };
                drop(t);
                log::trace!("tunnel {} heartbeat ack", tid);
                self.tx_control(hb_ack).await?;
            }

            PacketKind::HeartbeatAck => {
                let _ = src_ip;
            }
        }

        Ok(None)
    }

    // ── Periodic tick ─────────────────────────────────────────────────────────

    /// Drive retransmissions and send heartbeats.  Call every ~100 ms.
    pub async fn tick(&self) -> Result<()> {
        let heartbeats: Vec<_> = {
            let mut hbs = Vec::new();
            let mut dead = Vec::new();
            let now = Instant::now();

            let tunnels: Vec<(u32, Arc<Mutex<Tunnel>>)> = self
                .0
                .tunnels
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect();

            for (id, tunnel) in tunnels {
                let mut t = tunnel.lock().await;

                if t.state == TunnelState::Closed {
                    dead.push(id);
                    continue;
                }
                if t.state == TunnelState::Established
                    && t.is_idle(HEARTBEAT_IDLE_TIMEOUT)
                    && now.duration_since(t.last_heartbeat_sent) >= HEARTBEAT_MIN_INTERVAL
                {
                    t.last_heartbeat_sent = now;
                    hbs.push(CandyPacket::new_heartbeat(t.id, rand::random()));
                }
            }

            for id in &dead {
                self.0.tunnels.remove(id);
                self.0.established_notifiers.remove(id);
            }
            hbs
        };

        for hb in heartbeats {
            self.tx_control(hb).await?;
        }
        Ok(())
    }

    // ── Status helpers ────────────────────────────────────────────────────────

    /// Wait until the tunnel with `id` is in the Established state (or the
    /// supplied deadline elapses).  Uses `Notify` – no polling.
    pub async fn wait_established(&self, id: u32, timeout: Duration) -> bool {
        // If already established, return immediately.
        if self.is_established(id).await {
            return true;
        }

        // Retrieve the notifier registered during open_tunnel.
        let notifier = { self.0.established_notifiers.get(&id).map(|n| n.clone()) };
        let Some(notifier) = notifier else {
            return false;
        };

        let established = future::race(
            async {
                notifier.listen().await;
                true
            },
            async {
                tokio::time::sleep(timeout).await;
                false
            },
        )
        .await
            && self.is_established(id).await;

        if established {
            self.0.established_notifiers.remove(&id);
        }
        established
    }

    /// True if the tunnel with `id` is in the Established state.
    pub async fn is_established(&self, id: u32) -> bool {
        let Some(tunnel) = self.0.tunnels.get(&id).map(|t| t.clone()) else {
            return false;
        };
        let established = {
            let guard = tunnel.lock().await;
            guard.state == TunnelState::Established
        };
        established
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Spawn a background task that drains `net_rx` and sends each chunk as a
    /// data packet through the tunnel.
    fn spawn_send_task(&self, tunnel_id: u32, net_rx: mpsc::Receiver<Bytes>) {
        let this = self.clone();
        let mtu = self.0.cfg.mtu;
        tokio::spawn(async move {
            while let Ok(data) = net_rx.recv().await {
                // Fragment large buffers into MTU-sized chunks.
                let mut offset = 0;
                while offset < data.len() {
                    let end = (offset + mtu).min(data.len());
                    let chunk = data.slice(offset..end);

                    if let Err(e) = this.enqueue_and_send(tunnel_id, chunk).await {
                        log::debug!("send task tunnel {}: {}", tunnel_id, e);
                        return;
                    }
                    offset = end;
                }
            }
            log::debug!("send task for tunnel {} finished", tunnel_id);
        });
    }

    async fn enqueue_and_send(&self, tunnel_id: u32, payload: Bytes) -> Result<()> {
        let pkt = {
            let tunnel = self
                .0
                .tunnels
                .get(&tunnel_id)
                .map(|t| t.clone())
                .ok_or_else(|| anyhow!("tunnel {} gone", tunnel_id))?;
            let mut t = tunnel.lock().await;
            t.make_data_packet(payload)
        };
        self.tx_packet(pkt).await
    }

    async fn tx_control(&self, pkt: CandyPacket) -> Result<()> {
        self.tx_packet(pkt).await
    }

    async fn tx_packet(&self, pkt: CandyPacket) -> Result<()> {
        log::trace!(
            "tx packet kind={:?} tunnel={} proto={:?}",
            pkt.kind,
            pkt.tunnel_id,
            self.0.cfg.uplink_protocol
        );
        match &self.0.sender {
            PacketSender::Raw {
                sender,
                addr,
                mux_fec,
            } => {
                if let Some(mux_sender) = mux_fec {
                    return mux_sender.send(pkt).await;
                }

                let enc = pkt.encode();
                let out = match self.0.cfg.uplink_protocol {
                    TunnelProtocol::Udp => OutPacket::Udp {
                        src_ip: addr.local_spoof,
                        dst_ip: addr.peer_real,
                        src_port: addr.pick_data_port(),
                        dst_port: addr.pick_data_port(),
                        payload: enc,
                    },
                    TunnelProtocol::Icmp => {
                        let seq = match self.0.tunnels.get(&pkt.tunnel_id) {
                            Some(tunnel) => {
                                let mut t = tunnel.lock().await;
                                let s = t.icmp_seq_next;
                                t.icmp_seq_next = t.icmp_seq_next.wrapping_add(1);
                                s
                            }
                            None => (pkt.seq & 0xffff) as u16,
                        };
                        OutPacket::Icmp {
                            src_ip: addr.local_spoof,
                            dst_ip: addr.peer_real,
                            id: addr.pick_icmp_id(),
                            seq,
                            payload: enc,
                        }
                    }
                    TunnelProtocol::Proto58 => OutPacket::Proto58 {
                        src_ip: addr.local_spoof,
                        dst_ip: addr.peer_real,
                        payload: enc,
                    },
                    TunnelProtocol::Ipip => OutPacket::Ipip {
                        src_ip: addr.local_spoof,
                        dst_ip: addr.peer_real,
                        payload: enc,
                    },
                    TunnelProtocol::Gre => OutPacket::Gre {
                        src_ip: addr.local_spoof,
                        dst_ip: addr.peer_real,
                        payload: enc,
                    },
                    TunnelProtocol::Tcp => {
                        let (seq, ack) = match self.0.tunnels.get(&pkt.tunnel_id) {
                            Some(tunnel) => {
                                let mut t = tunnel.lock().await;
                                let s = t.tcp_seq_next;
                                let a = t.tcp_ack_next;
                                let inc = (enc.len().max(1)) as u32;
                                t.tcp_seq_next = t.tcp_seq_next.wrapping_add(inc);
                                t.tcp_ack_next = t.tcp_ack_next.wrapping_add(1);
                                (s, a)
                            }
                            None => (pkt.seq, 0),
                        };
                        OutPacket::Tcp {
                            src_ip: addr.local_spoof,
                            dst_ip: addr.peer_real,
                            src_port: addr.pick_data_port(),
                            dst_port: addr.pick_data_port(),
                            seq,
                            ack,
                            flags: (pnet_packet::tcp::TcpFlags::PSH
                                | pnet_packet::tcp::TcpFlags::ACK)
                                as u8,
                            payload: enc,
                        }
                    }
                    TunnelProtocol::Quic => {
                        return Err(anyhow!("quic sender used with raw transport"));
                    }
                };
                sender.send(out).await
            }
            PacketSender::Quic(sender) => sender.send(pkt).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_first_data_seq_is_syn_ack_seq_plus_one() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            const TID: u32 = 9;
            const OUR_SYN_ACK_SEQ: u32 = 777;
            let (app_tx, _app_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) = mpsc::bounded(1);

            let mut tunnel = Tunnel::new(
                TID,
                TunnelState::Established,
                OUR_SYN_ACK_SEQ.wrapping_add(1),
                app_tx,
            );
            let syn_ack = CandyPacket::new_syn_ack(TID, OUR_SYN_ACK_SEQ);
            let first_data = tunnel.make_data_packet(Bytes::from_static(b"x"));

            assert_eq!(first_data.seq, syn_ack.seq.wrapping_add(1));
        });
    }
}
