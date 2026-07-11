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

/// Server-side port-forward session map:
/// tunnel_id -> TCP writer channel (toward target service)
type SessionMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

/// Suit server handles packets received from transport and bridges to target TCP services.
pub struct SuitServer {
    sessions: SessionMap,
    out_tx: mpsc::Sender<SuitPacket>,
}

impl SuitServer {
    pub fn new(out_tx: mpsc::Sender<SuitPacket>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            out_tx,
        }
    }

    /// Handle a single packet received from tunnel transport.
    pub async fn on_packet(&self, pkt: SuitPacket) -> Result<()> {
        match pkt.kind {
            PacketKind::Syn => self.handle_syn(pkt).await,
            PacketKind::Data => self.handle_data(pkt).await,
            PacketKind::Fin => self.handle_fin(pkt).await,
            PacketKind::Heartbeat => self.handle_heartbeat(pkt).await,
            PacketKind::SynAck | PacketKind::HeartbeatAck => Ok(()),
        }
    }

    async fn handle_syn(&self, pkt: SuitPacket) -> Result<()> {
        let target = std::str::from_utf8(&pkt.payload)
            .context("SYN payload is not valid utf8 target addr")?
            .trim()
            .to_string();

        let target_addr: SocketAddr = target
            .parse()
            .with_context(|| format!("invalid target addr in SYN payload: {}", target))?;

        info!(
            "server SYN tunnel_id={} target={}",
            pkt.tunnel_id, target_addr
        );

        let stream = TcpStream::connect(target_addr)
            .await
            .with_context(|| format!("connect to target {} failed", target_addr))?;

        let (mut rd, mut wr) = stream.into_split();
        let (tx_to_tcp, mut rx_to_tcp) = mpsc::channel::<Bytes>(1024);

        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(pkt.tunnel_id, tx_to_tcp);
        }

        // ACK SYN
        self.out_tx
            .send(SuitPacket {
                kind: PacketKind::SynAck,
                tunnel_id: pkt.tunnel_id,
                seq: pkt.seq,
                payload: Bytes::new(),
            })
            .await
            .context("failed to send SynAck")?;

        // task: tunnel DATA -> target TCP write
        let sessions_for_writer = self.sessions.clone();
        let tunnel_id = pkt.tunnel_id;
        tokio::spawn(async move {
            while let Some(chunk) = rx_to_tcp.recv().await {
                if chunk.is_empty() {
                    continue;
                }
                if let Err(e) = wr.write_all(&chunk).await {
                    debug!("server write target failed tunnel_id={}: {}", tunnel_id, e);
                    break;
                }
            }
            let mut map = sessions_for_writer.lock().await;
            map.remove(&tunnel_id);
        });

        // task: target TCP read -> tunnel DATA
        let out_tx = self.out_tx.clone();
        tokio::spawn(async move {
            let mut seq: u32 = 1;
            let mut buf = vec![0u8; 16 * 1024];

            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => {
                        let _ = out_tx
                            .send(SuitPacket {
                                kind: PacketKind::Fin,
                                tunnel_id,
                                seq,
                                payload: Bytes::new(),
                            })
                            .await;
                        break;
                    }
                    Ok(n) => {
                        let payload = Bytes::copy_from_slice(&buf[..n]);
                        if out_tx
                            .send(SuitPacket {
                                kind: PacketKind::Data,
                                tunnel_id,
                                seq,
                                payload,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        seq = seq.wrapping_add(1);
                    }
                    Err(e) => {
                        debug!("server read target failed tunnel_id={}: {}", tunnel_id, e);
                        let _ = out_tx
                            .send(SuitPacket {
                                kind: PacketKind::Fin,
                                tunnel_id,
                                seq,
                                payload: Bytes::new(),
                            })
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_data(&self, pkt: SuitPacket) -> Result<()> {
        let tx = {
            let sessions = self.sessions.lock().await;
            sessions.get(&pkt.tunnel_id).cloned()
        };

        if let Some(tx) = tx {
            tx.send(pkt.payload)
                .await
                .with_context(|| format!("failed forwarding DATA to target for tunnel_id={}", pkt.tunnel_id))?;
        } else {
            warn!("DATA for unknown tunnel_id={}", pkt.tunnel_id);
        }

        Ok(())
    }

    async fn handle_fin(&self, pkt: SuitPacket) -> Result<()> {
        info!("server FIN tunnel_id={}", pkt.tunnel_id);
        let mut sessions = self.sessions.lock().await;
        sessions.remove(&pkt.tunnel_id);
        Ok(())
    }

    async fn handle_heartbeat(&self, pkt: SuitPacket) -> Result<()> {
        self.out_tx
            .send(SuitPacket {
                kind: PacketKind::HeartbeatAck,
                tunnel_id: pkt.tunnel_id,
                seq: pkt.seq,
                payload: Bytes::new(),
            })
            .await
            .context("failed to send HeartbeatAck")?;
        Ok(())
    }
}

/// Optional helper: expose a plain TCP listener and bridge each accepted socket
/// into a fixed upstream address (debug/local testing utility).
pub async fn run_plain_tcp_bridge(listen: SocketAddr, upstream: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind bridge listener failed on {}", listen))?;

    info!("plain bridge listening on {} -> {}", listen, upstream);

    loop {
        let (mut inbound, peer) = listener.accept().await.context("bridge accept failed")?;
        tokio::spawn(async move {
            match TcpStream::connect(upstream).await {
                Ok(mut outbound) => {
                    let res = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    if let Err(e) = res {
                        debug!("bridge copy failed peer={}: {}", peer, e);
                    }
                }
                Err(e) => {
                    error!("bridge connect upstream failed peer={}: {}", peer, e);
                }
            }
        });
    }
}
