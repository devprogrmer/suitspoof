//! CandyTunnel **server** binary.
//!
//! Listens for incoming tunnel connections from clients and forwards raw IP
//! packets to the local TUN interface.
//!
//! Usage:
//!   cargo run --bin server -- --config config/server.toml

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use CandyTunnel::app::{run_server, verify_license};
use CandyTunnel::config::Config;
use CandyTunnel::logging::{init_logging, log_tune_summary, print_banner};
use CandyTunnel::tuning::{apply_auto_tune, effective_runtime_threads};

#[derive(Parser, Debug)]
#[command(name = "server", about = "CandyTunnel server (tunnel endpoint)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/server.toml")]
    config: String,

    /// Override log level.
    #[arg(short, long)]
    log_level: Option<String>,

    /// Allow any source IP (bypass allowlist) for check mode.
    #[arg(long)]
    check_allow_any: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut cfg = Config::from_file(&args.config)?;
    let level = args
        .log_level
        .as_deref()
        .unwrap_or(cfg.log_level.as_str());
    init_logging(level);
    print_banner("server", env!("CARGO_PKG_VERSION"));
    let summary = apply_auto_tune(&mut cfg);
    if let Some(s) = &summary {
        log_tune_summary(s);
    }

    let cfg = Arc::new(cfg);
    let threads = effective_runtime_threads(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cfg, args.check_allow_any))
}

async fn async_main(cfg: Arc<Config>, allow_any: bool) -> Result<()> {
    // Prompt for license password here (binary-level interaction)
    let password = rpassword::prompt_password("License password: ")?;
    verify_license(&password).await?;

    run_server(cfg, allow_any).await
}
