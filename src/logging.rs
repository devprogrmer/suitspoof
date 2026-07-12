//! Logging setup using [`simplelog`].
//!
//! Provides:
//! - Coloured terminal output via `TermLogger`
//! - Optional simultaneous file logging via `WriteLogger`
//! - The same startup banner and auto-tune summary helpers as before
//!
//! Output format (terminal):
//! ```
//! 14:23:01 [INFO ] [app] CandyTunnel client starting …
//! ```
//! Level colours (simplelog built-in):
//!   ERROR → red   WARN → yellow   INFO → cyan   DEBUG → blue   TRACE → white

use simplelog::{
    ColorChoice, CombinedLogger, Config, ConfigBuilder, LevelFilter, TermLogger, TerminalMode,
    WriteLogger,
};

use crate::tuning::TuningSummary;

// ── ANSI helpers (banner only) ────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[1;96m";
const YELLOW: &str = "\x1b[1;93m";

// ── Logger ────────────────────────────────────────────────────────────────────

/// Parse a level string into a [`LevelFilter`].
fn parse_level(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    }
}

/// Build a `simplelog` [`Config`] that:
/// - Shows timestamp, level, and target (module path)
/// - Strips the noisy `CandyTunnel::` crate prefix from target strings
fn build_config() -> Config {
    ConfigBuilder::new()
        .set_time_format_rfc3339() // ISO-8601 timestamps
        .set_time_offset_to_local() // local timezone (falls back to UTC)
        .unwrap_or_else(|b| b) // unwrap_or_else handles offset errors
        .set_target_level(LevelFilter::Error) // show module path for errors only
        .set_thread_level(LevelFilter::Off) // don't print thread IDs
        .build()
}

/// Initialise the global logger.
///
/// - Always writes coloured output to **stderr**.
/// - If `log_file` is `Some(path)`, also appends plain-text logs to that file.
pub fn init_logging(level: &str) {
    init_logging_with_file(level, None::<&str>);
}

/// Initialise the global logger with an optional log file path.
pub fn init_logging_with_file<P: AsRef<std::path::Path>>(level: &str, log_file: Option<P>) {
    let filter = parse_level(level);
    let cfg = build_config();

    let term = TermLogger::new(
        filter,
        cfg.clone(),
        TerminalMode::Stderr, // always write to stderr, not stdout
        ColorChoice::Auto,    // ANSI colour when stderr is a TTY, plain otherwise
    );

    if let Some(path) = log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => {
                CombinedLogger::init(vec![term, WriteLogger::new(filter, cfg, file)])
                    .unwrap_or_else(|e| eprintln!("logger init error: {e}"));
            }
            Err(e) => {
                eprintln!("cannot open log file {:?}: {e}", path.as_ref());
                CombinedLogger::init(vec![term])
                    .unwrap_or_else(|e| eprintln!("logger init error: {e}"));
            }
        }
    } else {
        CombinedLogger::init(vec![term]).unwrap_or_else(|e| eprintln!("logger init error: {e}"));
    }
}

// ── Banner ────────────────────────────────────────────────────────────────────

/// Print a stylised startup banner to stderr.
/// Call once after `init_logging`.
pub fn print_banner(role: &str, version: &str) {
    eprintln!(
        "\n\
{c1} ██████╗ █████╗ ███╗   ██╗██████╗ ██╗   ██╗{R}\n\
{c2}██╔════╝██╔══██╗████╗  ██║██╔══██╗╚██╗ ██╔╝{R}\n\
{c3}██║     ███████║██╔██╗ ██║██║  ██║ ╚████╔╝ {R}\n\
{c4}██║     ██╔══██║██║╚██╗██║██║  ██║  ╚██╔╝  {R}\n\
{c5}╚██████╗██║  ██║██║ ╚████║██████╔╝   ██║   {R}\n\
{c6} ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝    ╚═╝  {R}\n\
{DIM} ─────────────────────────────────────────{R}\n\
 {BOLD}{CYAN}CandyTunnel{R}  {DIM}v{version}{R}  {YELLOW}{role}{R}\n\
{DIM} ─────────────────────────────────────────{R}\n",
        c1 = "\x1b[1;38;5;208m",
        c2 = "\x1b[1;38;5;214m",
        c3 = "\x1b[1;38;5;220m",
        c4 = "\x1b[1;38;5;226m",
        c5 = "\x1b[1;38;5;229m",
        c6 = "\x1b[1;38;5;231m",
        R = RESET,
        DIM = DIM,
        BOLD = BOLD,
        CYAN = CYAN,
        YELLOW = YELLOW,
        version = version,
        role = role.to_uppercase(),
    );
}

// ── Tune summary ──────────────────────────────────────────────────────────────

/// Log the auto-tune result as a readable bordered block.
pub fn log_tune_summary(s: &TuningSummary) {
    log::info!("┌─ Auto-Tune ────────────────────────────────────");
    log::info!(
        "│  mode={:?}  cores={}  mem={:.1}GB  nic={nic}Mbps",
        s.perf_mode,
        s.profile.cpu_cores,
        s.profile.mem_gb,
        nic = s
            .profile
            .nic_mbps
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
    );
    log::info!(
        "│  threads={}  tunnels={}  chan={}  io_chan={}",
        s.runtime_worker_threads,
        s.tunnel_count,
        s.channel_capacity,
        s.io_channel_capacity,
    );
    log::info!(
        "│  mux={}  flush={}ms  payload={}B",
        s.enable_multiplex,
        s.multiplex_flush_ms,
        s.multiplex_max_payload,
    );
    log::info!("└────────────────────────────────────────────────");
}
