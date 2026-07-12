mod app;
mod config;
mod logging;
mod mux_fec;
mod packet;
mod port_forward;
mod quic;
mod raw_socket;
mod tun;
mod tun_bridge;
mod tuning;
mod tunnel;
mod xor;

use std::sync::Arc;

use anyhow::Result;
use config::{Config, TunnelRole};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/client.toml".to_string());

    let cfg = Config::from_file(&config_path)?;
    logging::init_logging(&cfg.log_level);

    match cfg.role {
        TunnelRole::Client => app::run_client(Arc::new(cfg)).await,
        TunnelRole::Server => app::run_server(Arc::new(cfg), false).await,
    }
}
