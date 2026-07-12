//! Client-side port-forward setup using iptables (Linux).
//!
//! This installs DNAT/SNAT rules so that traffic hitting the configured ports
//! on the client is redirected through the TUN interface to the server TUN
//! address.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::config::Config;

#[cfg(target_os = "linux")]
pub struct PortForwardGuard {
    chain: String,
    ports: Vec<u16>,
    tun_name: String,
    tun_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
}

#[cfg(not(target_os = "linux"))]
pub struct PortForwardGuard;

#[cfg(target_os = "linux")]
impl PortForwardGuard {
    /// Install iptables rules for client-side port forwarding.
    ///
    /// Returns `Ok(None)` if no ports are configured.
    pub fn apply(cfg: &Config) -> Result<Option<Self>> {
        let ports = cfg.effective_forward_ports();
        if ports.is_empty() {
            log::info!("forward_ports empty - iptables port forwarding disabled");
            return Ok(None);
        }

        log::debug!(
            "port_forward setup ports={} tun={} tun_ip={} peer_ip={}",
            ports.len(),
            cfg.tun_name,
            cfg.tun_ip,
            cfg.tun_peer_ip
        );

        enable_ip_forward()?;
        if let Err(e) = set_rp_filter(&cfg.tun_name, 0) {
            log::warn!("rp_filter update failed for {}: {}", cfg.tun_name, e);
        }

        let chain = format!("CandyTunnel_{}", std::process::id());
        log::debug!("port_forward chain={}", chain);
        ensure_chain(&chain)?;
        install_rules(&chain, cfg, &ports)?;

        log::info!("iptables port-forward installed on ports {:?}", ports);

        Ok(Some(Self {
            chain,
            ports,
            tun_name: cfg.tun_name.clone(),
            tun_ip: cfg.tun_ip,
            peer_ip: cfg.tun_peer_ip,
        }))
    }
}

#[cfg(target_os = "linux")]
impl Drop for PortForwardGuard {
    fn drop(&mut self) {
        let _ = cleanup_rules(
            &self.chain,
            &self.ports,
            &self.tun_name,
            self.tun_ip,
            self.peer_ip,
        );
    }
}

#[cfg(not(target_os = "linux"))]
impl PortForwardGuard {
    pub fn apply(_cfg: &Config) -> Result<Option<Self>> {
        bail!("iptables port forwarding is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn enable_ip_forward() -> Result<()> {
    write_sysctl("/proc/sys/net/ipv4/ip_forward", "1").context("enable net.ipv4.ip_forward")
}

#[cfg(target_os = "linux")]
fn set_rp_filter(iface: &str, value: u8) -> Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", iface);
    write_sysctl(&path, &value.to_string())
}

#[cfg(target_os = "linux")]
fn write_sysctl(path: &str, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("write {}", path))
}

#[cfg(target_os = "linux")]
fn ensure_chain(chain: &str) -> Result<()> {
    let _ = run_iptables(vec![
        "-w".into(),
        "-t".into(),
        "nat".into(),
        "-N".into(),
        chain.into(),
    ]);

    run_iptables(vec![
        "-w".into(),
        "-t".into(),
        "nat".into(),
        "-F".into(),
        chain.into(),
    ])
}

#[cfg(target_os = "linux")]
fn install_rules(chain: &str, cfg: &Config, ports: &[u16]) -> Result<()> {
    let dnat = cfg.tun_peer_ip.to_string();
    let snat = cfg.tun_ip.to_string();

    ensure_rule(
        "nat",
        chain,
        &rule(&["-p", "tcp", "-j", "DNAT", "--to-destination", &dnat]),
    )?;
    ensure_rule(
        "nat",
        chain,
        &rule(&["-p", "udp", "-j", "DNAT", "--to-destination", &dnat]),
    )?;

    for p in ports {
        let port = p.to_string();
        ensure_rule(
            "nat",
            "PREROUTING",
            &rule(&["-p", "tcp", "--dport", &port, "-j", chain]),
        )?;
        ensure_rule(
            "nat",
            "PREROUTING",
            &rule(&["-p", "udp", "--dport", &port, "-j", chain]),
        )?;

        ensure_rule(
            "nat",
            "OUTPUT",
            &rule(&["-p", "tcp", "--dport", &port, "-j", chain]),
        )?;
        ensure_rule(
            "nat",
            "OUTPUT",
            &rule(&["-p", "udp", "--dport", &port, "-j", chain]),
        )?;

        ensure_rule(
            "nat",
            "POSTROUTING",
            &rule(&[
                "-o",
                &cfg.tun_name,
                "-p",
                "tcp",
                "--dport",
                &port,
                "-j",
                "SNAT",
                "--to-source",
                &snat,
            ]),
        )?;
        ensure_rule(
            "nat",
            "POSTROUTING",
            &rule(&[
                "-o",
                &cfg.tun_name,
                "-p",
                "udp",
                "--dport",
                &port,
                "-j",
                "SNAT",
                "--to-source",
                &snat,
            ]),
        )?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_rules(
    chain: &str,
    ports: &[u16],
    tun_name: &str,
    tun_ip: Ipv4Addr,
    tun_peer_ip: Ipv4Addr,
) -> Result<()> {
    log::debug!("port_forward cleanup chain={} ports={}", chain, ports.len());
    let dnat = tun_peer_ip.to_string();
    let snat = tun_ip.to_string();

    for p in ports {
        let port = p.to_string();
        let _ = delete_rule(
            "nat",
            "PREROUTING",
            &rule(&["-p", "tcp", "--dport", &port, "-j", chain]),
        );
        let _ = delete_rule(
            "nat",
            "PREROUTING",
            &rule(&["-p", "udp", "--dport", &port, "-j", chain]),
        );
        let _ = delete_rule(
            "nat",
            "OUTPUT",
            &rule(&["-p", "tcp", "--dport", &port, "-j", chain]),
        );
        let _ = delete_rule(
            "nat",
            "OUTPUT",
            &rule(&["-p", "udp", "--dport", &port, "-j", chain]),
        );

        let _ = delete_rule(
            "nat",
            "POSTROUTING",
            &rule(&[
                "-o",
                tun_name,
                "-p",
                "tcp",
                "--dport",
                &port,
                "-j",
                "SNAT",
                "--to-source",
                &snat,
            ]),
        );
        let _ = delete_rule(
            "nat",
            "POSTROUTING",
            &rule(&[
                "-o",
                tun_name,
                "-p",
                "udp",
                "--dport",
                &port,
                "-j",
                "SNAT",
                "--to-source",
                &snat,
            ]),
        );
    }

    let _ = delete_rule(
        "nat",
        chain,
        &rule(&["-p", "tcp", "-j", "DNAT", "--to-destination", &dnat]),
    );
    let _ = delete_rule(
        "nat",
        chain,
        &rule(&["-p", "udp", "-j", "DNAT", "--to-destination", &dnat]),
    );

    let _ = run_iptables(vec![
        "-w".into(),
        "-t".into(),
        "nat".into(),
        "-F".into(),
        chain.into(),
    ]);
    let _ = run_iptables(vec![
        "-w".into(),
        "-t".into(),
        "nat".into(),
        "-X".into(),
        chain.into(),
    ]);

    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_rule(table: &str, chain: &str, rule: &[String]) -> Result<()> {
    let mut del = vec![
        "-w".into(),
        "-t".into(),
        table.into(),
        "-D".into(),
        chain.into(),
    ];
    del.extend(rule.iter().cloned());
    let _ = run_iptables(del);

    let mut add = vec![
        "-w".into(),
        "-t".into(),
        table.into(),
        "-A".into(),
        chain.into(),
    ];
    add.extend(rule.iter().cloned());
    run_iptables(add)
}

#[cfg(target_os = "linux")]
fn delete_rule(table: &str, chain: &str, rule: &[String]) -> Result<()> {
    let mut del = vec![
        "-w".into(),
        "-t".into(),
        table.into(),
        "-D".into(),
        chain.into(),
    ];
    del.extend(rule.iter().cloned());
    run_iptables(del)
}

#[cfg(target_os = "linux")]
fn rule(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[cfg(target_os = "linux")]
fn run_iptables(args: Vec<String>) -> Result<()> {
    let output = Command::new("iptables")
        .args(&args)
        .output()
        .with_context(|| format!("iptables {:?}", args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("iptables failed: {}", stderr.trim());
    }
    Ok(())
}
