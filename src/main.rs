use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;

use suitspoof::app::{run_client, run_server};
use suitspoof::check::{run_spoof_check, CheckOptions};
use suitspoof::config::{Config, TunnelRole};
use suitspoof::logging::{init_logging, log_tune_summary, print_banner};
use suitspoof::tuning::{apply_auto_tune, effective_runtime_threads};

#[derive(Parser, Debug)]
#[command(name = "suitspoof", about = "suitspoof unified client/server")]
struct Args {
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    #[arg(short, long)]
    log_level: Option<String>,

    #[arg(long)]
    check: bool,

    #[arg(long, required_if_eq("check", "true"))]
    check_ips: Option<String>,

    #[arg(long, default_value = "check_latency.txt")]
    check_out: String,

    #[arg(long, default_value = "1500")]
    check_timeout_ms: u64,

    #[arg(long, default_value = "64")]
    check_workers: usize,

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

    let role = format!("{:?}", cfg.role);
    print_banner(&role, env!("CARGO_PKG_VERSION"));

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

    rt.block_on(async_main(cfg, args))
}

async fn async_main(cfg: Arc<Config>, args: Args) -> Result<()> {
    match cfg.role {
        TunnelRole::Client => {
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
        TunnelRole::Server => run_server(cfg, args.check_allow_any).await,
        #[allow(unreachable_patterns)]
        _ => bail!("unknown role"),
    }
}
