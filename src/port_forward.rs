use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::packet::{PacketKind, SuitPacket};

#[derive(Debug, Clone)]
pub struct PortForwardRule {
    pub listen_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct ForwardFrame {
    pub tunnel_id: u32,
    pub packet: SuitPacket,
}

pub struct PortForwardManager {
    rules: Vec<PortForwardRule>,
    next_tunnel_id: Arc<Mutex<u32>>,
    tcp_writers: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    out_tx: mpsc::Sender<ForwardFrame>,
}

impl PortForwardManager {
    pub fn new(rules: Vec<PortForwardRule>, out_tx: mpsc::Sender<ForwardFrame>) -> Self {
        Self {
            rules,
            next_tunnel_id: Arc::new(Mutex::new(1)),
            tcp_writers: Arc::new(Mutex::new(HashMap::new())),
            out_tx,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        if self.rules.is_empty() {
            warn!("port_forward: no rules configured");
            return Ok(());
        }

        for rule in self.rules.clone() {
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.run_rule(rule).await {
                    error!("port_forward rule task exited with error: {e:#}");
                }
            });
        }

        Ok(())
    }

    async fn run_rule(self: Arc<Self>, rule: PortForwardRule) -> Result<()> {
        let listener = TcpListener::bind(rule.listen_addr)
            .await
            .with_context(|| format!("bind failed on {}", rule.listen_addr))?;

        info!(
            "port_forward listening on {} -> remote target {}",
            rule.listen_addr, rule.target_addr
        );

        loop {
            let (stream, peer) = listener.accept().await.context("accept failed")?;
            let this = self.clone();
            let rule_cloned = rule.clone();

            tokio::spawn(async move {
                if let Err(e) = this.handle_local_tcp(stream, peer, rule_cloned).await {
                    warn!("port_forward connection {} closed with error: {e:#}", peer);
                }
            });
        }
    }

    async fn alloc_tunnel_id(&self) -> u32 {
        let mut g = self.next_tunnel_id.lock().await;
        let id = *g;
        *g = g.wrapping_add(1).max(1);
        id
    }

    async fn send_packet(&self, packet: SuitPacket) -> Result<()> {
        let tunnel_id = packet.tunnel_id;
        self.out_tx
            .send(ForwardFrame { tunnel_id, packet })
            .await
            .context("failed to queue forward frame")
    }

    async fn remove_tunnel(&self, tunnel_id: u32) {
        let mut writers = self.tcp_writers.lock().await;
        writers.remove(&tunnel_id);
    }

    async fn handle_local_tcp(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        rule: PortForwardRule,
    ) -> Result<()> {
        let tunnel_id = self.alloc_tunnel_id().await;
        info!(
            "port_forward new tcp {} -> {} (tunnel_id={})",
            peer, rule.target_addr, tunnel_id
        );

        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Bytes>(1024);

        {
            let mut writers = self.tcp_writers.lock().await;
            writers.insert(tunnel_id, to_tcp_tx);
        }

        self.send_packet(SuitPacket {
            kind: PacketKind::Syn,
            tunnel_id,
            seq: 0,
            payload: Bytes::from(rule.target_addr.to_string().into_bytes()),
        })
        .await
        .context("failed to send SYN packet")?;


        let writer_owner = self.clone();
        tokio::spawn(async move {
            while let Some(buf) = to_tcp_rx.recv().await {
                if let Err(e) = tcp_write.write_all(&buf).await {
                    warn!("port_forward write to local tcp failed (tunnel_id={}): {e:#}", tunnel_id);
                    break;
                }
            }

            let _ = tcp_write.shutdown().await;
            writer_owner.remove_tunnel(tunnel_id).await;
        });

        let mut seq: u32 = 1;
        let mut buf = vec![0u8; 16 * 1024];

        loop {
            let n = tcp_read
                .read(&mut buf)
                .await
                .context("read from local tcp failed")?;

            if n == 0 {
                debug!("port_forward local tcp EOF (tunnel_id={})", tunnel_id);
                break;
            }

            let payload = Bytes::copy_from_slice(&buf[..n]);

            self.send_packet(SuitPacket {
                kind: PacketKind::Data,
                tunnel_id,
                seq,
                payload,
            })
            .await
            .with_context(|| format!("failed to send DATA packet for tunnel_id={}", tunnel_id))?;

            seq = seq.wrapping_add(1);
        }

        let _ = self
            .send_packet(SuitPacket {
                kind: PacketKind::Fin,
                tunnel_id,
                seq,
                payload: Bytes::new(),
            })
            .await;

        self.remove_tunnel(tunnel_id).await;
        Ok(())
    }

    pub async fn handle_inbound_packet(&self, packet: SuitPacket) -> Result<()> {
        match packet.kind {
            PacketKind::Data => {
                let tx = {
                    let writers = self.tcp_writers.lock().await;
                    writers.get(&packet.tunnel_id).cloned()
                };

                if let Some(tx) = tx {
                    tx.send(packet.payload)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to deliver inbound DATA to local tcp (tunnel_id={})",
                                packet.tunnel_id
                            )
                        })?;
                } else {
                    debug!(
                        "port_forward received DATA for unknown tunnel_id={}",
                        packet.tunnel_id
                    );
                }
            }

            PacketKind::Fin => {
                debug!("port_forward received FIN tunnel_id={}", packet.tunnel_id);
                self.remove_tunnel(packet.tunnel_id).await;
            }
            
            PacketKind::Syn => {
                debug!("port_forward received unexpected SYN tunnel_id={}", packet.tunnel_id);
            }
            PacketKind::SynAck => {
                debug!("port_forward received SYN-ACK tunnel_id={}", packet.tunnel_id);
            }
            PacketKind::Heartbeat => {
                 debug!("port_forward ignoring HEARTBEAT tunnel_id={}", packet.tunnel_id);
            }
            PacketKind::HeartbeatAck => {
                debug!("port_forward ignoring HEARTBEAT-ACK tunnel_id={}", packet.tunnel_id);
            }
        }
        Ok(())
    }
}
