use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::packet::{PacketKind, SuitPacket};

/// Local port-forward rule.
///
/// Example:
/// - listen_addr = 127.0.0.1:1081
/// - target_addr = 127.0.0.1:1080
///
/// Incoming TCP on listen_addr is tunneled and connected to target_addr on peer side.
#[derive(Debug, Clone)]
pub struct PortForwardRule {
    pub listen_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

/// Frame emitted by port-forward side and should be sent through tunnel transport.
#[derive(Debug, Clone)]
pub struct ForwardFrame {
    pub tunnel_id: u32,
    pub packet: SuitPacket,
}

/// TCP port-forward manager (local listener side).
///
/// This module is intentionally transport-agnostic:
/// - It emits `ForwardFrame` for outbound tunnel send path.
/// - It accepts inbound `SuitPacket` from tunnel receive path.
pub struct PortForwardManager {
    rules: Vec<PortForwardRule>,
    next_tunnel_id: Arc<Mutex<u32>>,

    /// tunnel_id -> writer channel (to TCP stream task)
    tcp_writers: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,

    /// outbound frames to tunnel transport
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

    /// Start listeners for all configured rules.
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

        let (tcp_read, mut tcp_write) = stream.into_split();
        let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Bytes>(1024);

        {
            let mut writers = self.tcp_writers.lock().await;
            writers.insert(tunnel_id, to_tcp_tx);
        }

        // Send SYN (includes target addr as payload).
        let syn_payload = Bytes::from(rule.target_addr.to_string().into_bytes());
        self.send_packet(SuitPacket {
            kind: PacketKind::Syn,
