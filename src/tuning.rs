//! Runtime tuning and system detection.

use std::fs;

use crate::config::{Config, PerfMode};

#[derive(Debug, Clone)]
pub struct SystemProfile {
    pub cpu_cores: usize,
    pub mem_gb: f64,
    pub nic_mbps: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TuningSummary {
    pub profile: SystemProfile,
    pub perf_mode: PerfMode,
    pub runtime_worker_threads: usize,
    pub tunnel_count: usize,
    pub channel_capacity: usize,
    pub io_channel_capacity: usize,
    pub enable_multiplex: bool,
    pub multiplex_flush_ms: u64,
    pub multiplex_max_payload: usize,
}

pub fn detect_system_profile(interface: &str) -> SystemProfile {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mem_gb = read_mem_gb().unwrap_or(1.0);
    let nic_mbps = read_nic_speed_mbps(interface);

    SystemProfile {
        cpu_cores,
        mem_gb,
        nic_mbps,
    }
}

pub fn apply_auto_tune(cfg: &mut Config) -> Option<TuningSummary> {
    if !cfg.auto_tune {
        return None;
    }

    let profile = detect_system_profile(&cfg.interface);

    let runtime_worker_threads =
        tune_worker_threads(cfg.runtime_worker_threads, cfg.perf_mode, &profile);
    cfg.runtime_worker_threads = runtime_worker_threads;

    let (tunnels, chan_cap, io_cap) = tune_channels(cfg.perf_mode, &profile);
    cfg.tunnel_count = tunnels;
    cfg.channel_capacity = chan_cap;
    cfg.io_channel_capacity = io_cap;

    let (enable_mux, flush_ms, max_payload) = tune_mux(cfg.perf_mode, cfg.mtu);
    cfg.enable_multiplex = enable_mux;
    cfg.multiplex_flush_ms = flush_ms;
    cfg.multiplex_max_payload = max_payload;

    Some(TuningSummary {
        profile,
        perf_mode: cfg.perf_mode,
        runtime_worker_threads,
        tunnel_count: cfg.tunnel_count,
        channel_capacity: cfg.channel_capacity,
        io_channel_capacity: cfg.io_channel_capacity,
        enable_multiplex: cfg.enable_multiplex,
        multiplex_flush_ms: cfg.multiplex_flush_ms,
        multiplex_max_payload: cfg.multiplex_max_payload,
    })
}

pub fn effective_runtime_threads(cfg: &Config) -> usize {
    if cfg.runtime_worker_threads > 0 {
        return cfg.runtime_worker_threads;
    }

    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

fn tune_worker_threads(current: usize, mode: PerfMode, profile: &SystemProfile) -> usize {
    if current > 0 {
        return current;
    }

    let cores = profile.cpu_cores.max(1);
    // Use all available cores for throughput/balanced; cap latency mode to
    // avoid context-switch noise on a few cores.
    match mode {
        PerfMode::Throughput => cores.max(2),
        PerfMode::Latency => cores.min(4).max(2),
        PerfMode::Balanced => cores.max(2), // removed artificial cap of 8
    }
}

fn tune_channels(mode: PerfMode, profile: &SystemProfile) -> (usize, usize, usize) {
    let cores = profile.cpu_cores.max(1);
    let nic = profile.nic_mbps.unwrap_or(1000) as usize;

    let base_tunnels = match mode {
        PerfMode::Throughput => (cores * 2).max(4),
        PerfMode::Latency => (cores / 2).max(1),
        PerfMode::Balanced => cores.max(2),
    };

    // Boost tunnel count proportionally with NIC speed.
    let nic_boost = if nic >= 10000 {
        4
    } else if nic >= 5000 {
        3
    } else if nic >= 2000 {
        2
    } else if nic >= 1000 {
        1
    } else {
        0
    };
    // Raised cap from 16 → 64 to support high-core / high-speed deployments.
    let tunnel_count = (base_tunnels + nic_boost).min(64).max(1);

    let base_capacity = match mode {
        PerfMode::Throughput => 8192,
        PerfMode::Latency => 2048,
        PerfMode::Balanced => 4096,
    };

    let mem_mult = if profile.mem_gb >= 32.0 {
        8
    } else if profile.mem_gb >= 16.0 {
        4
    } else if profile.mem_gb >= 8.0 {
        2
    } else {
        1
    };

    let channel_capacity = (base_capacity * mem_mult).max(512);
    // I/O queue should be at least 2× the per-tunnel channel to avoid back-pressure
    // when multiple tunnels are all active simultaneously.
    let io_channel_capacity = (channel_capacity * 2).max(1024);

    (tunnel_count, channel_capacity, io_channel_capacity)
}

fn tune_mux(mode: PerfMode, mtu: usize) -> (bool, u64, usize) {
    // Allow the mux payload to use the full MTU budget.
    let max_payload = mtu.min(1400).max(256);
    match mode {
        // Throughput: aggressive batching; 1 ms flush keeps latency tolerable
        // while still amortising per-packet syscall overhead.
        PerfMode::Throughput => (true, 1, max_payload),
        // Latency: disable mux so every packet is sent immediately.
        PerfMode::Latency => (false, 1, max_payload.min(900)),
        // Balanced: light batching with a 1 ms flush window.
        PerfMode::Balanced => (true, 1, max_payload),
    }
}

fn read_mem_gb() -> Option<f64> {
    let data = fs::read_to_string("/proc/meminfo").ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(kb) = parts[0].parse::<f64>() {
                    return Some(kb / 1024.0 / 1024.0);
                }
            }
        }
    }
    None
}

fn read_nic_speed_mbps(interface: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/speed", interface);
    let data = fs::read_to_string(path).ok()?;
    data.trim().parse::<u32>().ok()
}
