//! CandyTunnel **client** binary.
//!
//! Creates a local TUN interface and forwards IP packets to the remote
//! CandyTunnel server via a spoofed UDP/ICMP tunnel.
//!
//! Usage:
//!   cargo run --bin client -- --config config/client.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use CandyTunnel::app::run_client;
use CandyTunnel::check::{run_spoof_check, CheckOptions};
use CandyTunnel::config::Config;
use CandyTunnel::logging::{init_logging, log_tune_summary, print_banner};
use CandyTunnel::tuning::{apply_auto_tune, effective_runtime_threads};

#[derive(Parser, Debug)]
#[command(name = "client", about = "CandyTunnel client (TUN forwarder)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    /// Override log level (e.g. debug, info, warn).
    #[arg(short, long)]
    log_level: Option<String>,

    /// Run spoofed IP check mode (no TUN, no tunnel forwarding).
    #[arg(long)]
    check: bool,

    /// IP list file (one IPv4 per line) used for check mode.
    #[arg(long, required_if_eq("check", "true"))]
    check_ips: Option<String>,

    /// Output file for check results.
    #[arg(long, default_value = "check_latency.txt")]
    check_out: String,

    /// Timeout per IP in milliseconds.
    #[arg(long, default_value = "1500")]
    check_timeout_ms: u64,

    /// Concurrent workers for check mode.
    #[arg(long, default_value = "64")]
    check_workers: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut cfg = Config::from_file(&args.config)?;
    let level = args
        .log_level
        .as_deref()
        .unwrap_or(cfg.log_level.as_str());
    init_logging(level);
    print_banner("client", env!("CARGO_PKG_VERSION"));
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
    rt.block_on(async_main(cfg, args))?;

    Ok(())
}

async fn async_main(cfg: Arc<Config>, args: Args) -> Result<()> {
    if args.check {
        let ips_path = args.check_ips.unwrap_or_else(|| "check_ips.txt".to_string());
        let opts = CheckOptions {
            ips_path,
            out_path: args.check_out,
            timeout: Duration::from_millis(args.check_timeout_ms),
            workers: args.check_workers,
        };
        return run_spoof_check(cfg, opts).await;
    }

    run_client(cfg).await
}
