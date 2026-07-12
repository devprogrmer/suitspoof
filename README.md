# SuitTunnel Manager

[![ShellCheck](https://github.com/devprogrmer/suitspoof/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/devprogrmer/suitspoof/actions/workflows/shellcheck.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://github.com/devprogrmer/suitspoof/actions/workflows/release.yml/badge.svg)](https://github.com/devprogrmer/suitspoof/actions/workflows/release.yml)

Operational toolkit for deploying and managing **SuitTunnel** , an IP-spoofing-focused tunneling system for filtered or unstable networks.

---

## What this project is

`suittunnel-manager` is a production-oriented management layer for the `suit-tunnel` binary.

It automates installation, configuration, lifecycle management, and updates for multi-instance tunnel deployments on Linux.

SuitTunnel itself is built around:

- Real endpoint identity + spoof/cover endpoint identity
- Multi-protocol transport modes
- Optional obfuscation and traffic-shaping features
- Performance controls such as multiplexing, FEC, MTU tuning, and runtime knobs

---

## Why SuitTunnel

Many tunnel systems are easy to fingerprint because they produce static flow behavior over time.

SuitTunnel reduces signature stability by combining:

1. Endpoint role separation between real and spoof-oriented fields
2. Transport flexibility with protocol fallback/adaptation
3. Packet-shape controls such as padding, jitter, and field variation
4. Runtime performance tuning with mux/FEC/channel/MTU controls

This makes traffic classification harder for simple DPI pipelines while preserving practical throughput.

---

## IP spoofing-focused model

SuitTunnel configuration includes dedicated fields for real and cover identities:

- `real_ip`
- `peer_real_ip`
- `spoofed_ip`
- `spoofed_ip_pool`
- `peer_spoofed_ip`

### Conceptual behavior

- Real endpoints maintain actual tunnel connectivity and control.
- Spoof-related fields influence outer traffic appearance and profile diversity.
- Pool-based spoofing reduces deterministic single-identity patterns.
- Combined with transport and obfuscation settings, this lowers repetitive tunnel signatures.

> Important: effectiveness depends on route policy, provider filtering behavior, and protocol choice. No single bypass profile works everywhere.

---

## High-level architecture
```text
+-------------------------+                          +-------------------------+
|        Client Node      |                          |       Server Node       |
|-------------------------|                          |-------------------------|
| Apps / LAN              |                          | Apps / LAN              |
|    |                    |                          |    |                    |
| [TUN Interface]         |<==== encapsulated ======>| [TUN Interface]         |
|    |                    |      encrypted flow      |    |                    |
| suit-tunnel process     |   over udp/tcp/icmp/...  | suit-tunnel process     |
| managed by systemd      |                          | managed by systemd      |
| suittunnel@<instance>   |                          | suittunnel@<instance>   |
+-------------------------+                          +-------------------------+

---

## Tunnel data flow

text
Ingress traffic
  -> TUN capture
  -> optional multiplex queue
  -> optional FEC encode
  -> encrypt/authenticate with PSK
  -> optional obfuscation stage:
- packet_padding
- ttl_jitter
- random_dscp
- fake_tls_header
- spoofing profile behavior
  -> encapsulate into selected transport
  -> network transit
  -> peer decapsulation/de-obfuscation/decrypt
  -> optional FEC recovery + demux
  -> TUN egress / forwarding

---

## DPI-resistance and traffic-shaping controls

SuitTunnel ecosystem can apply:

- **Protocol agility**: `udp`, `tcp`, `icmp`, `quic`, and other supported outer modes
- **Padding**: reduces deterministic packet-size fingerprints
- **TTL jitter**: avoids rigid TTL signatures
- **Random DSCP**: weakens naive QoS-based classification
- **Fake TLS-like framing**: blends with common encrypted traffic shapes
- **Port shuffle**: lowers static port correlation
- **Multiplexing**: aggregates microflows efficiently
- **FEC**: improves delivery over lossy paths
- **Spoof IP pool rotation**: reduces single-identity repetition

---

## Manager script capabilities

`suit-manager.sh` supports:

- Download/install `suit-tunnel`
- Update from GitHub releases
- Interactive config generation
- QUIC self-signed certificate generation
- systemd template creation with `suittunnel@.service`
- Instance lifecycle operations:
  - `start`
  - `stop`
  - `restart`
  - `enable`
  - `disable`
  - `remove`
- Observability:
  - `status`
  - `list`
  - `logs`
  - `follow`
  - `check`
- Uninstall options:
  - `keep-config`
  - `purge`

---

## Configuration highlights

Typical parameters exposed by manager-generated TOML files:

- Role and endpoint fields:
  - `role`
  - `real_ip`
  - `peer_real_ip`
  - `spoofed_ip`
  - `spoofed_ip_pool`
  - `peer_spoofed_ip`
- Transport:
  - `uplink_protocol`
  - `downlink_protocol`
  - `data_port`
  - shuffle controls and port ranges
- Reliability/performance:
  - `enable_multiplex`
  - `multiplex_*`
  - `enable_fec`
  - `fec_group_size`
  - `tunnel_count`
  - `mtu`
  - channel capacities
  - worker threads
- QUIC:
  - SNI
  - cert/key paths
  - ALPN
  - flow-control limits
- Obfuscation:
  - `packet_padding`
  - `ttl_jitter`
  - `fake_tls_header`
  - `random_dscp`
- Access/security:
  - `pre_shared_key`
  - `allowed_peers`

---

## One-Line Install

Download the manager script:

bash
curl -fsSL https://raw.githubusercontent.com/devprogrmer/suitspoof/main/suit-manager.sh -o suit-manager.sh
chmod +x suit-manager.sh

Run setup:

bash
sudo ./suit-manager.sh setup

Show help:

bash
./suit-manager.sh help

> If your manager script has a different filename in the repository, rename it to `suit-manager.sh` or update the URL above.

---

## Installation

bash
chmod +x suit-manager.sh
sudo ./suit-manager.sh setup

---

## Quick start

bash
sudo ./suit-manager.sh gen-quic-cert
sudo ./suit-manager.sh configure
sudo ./suit-manager.sh start suit0
sudo ./suit-manager.sh status

Logs:

bash
sudo ./suit-manager.sh logs suit0 200
sudo ./suit-manager.sh follow suit0

---

## Command reference

bash
sudo ./suit-manager.sh setup
sudo ./suit-manager.sh download
sudo ./suit-manager.sh update
sudo ./suit-manager.sh configure
sudo ./suit-manager.sh gen-quic-cert

sudo ./suit-manager.sh start <name>
sudo ./suit-manager.sh stop <name>
sudo ./suit-manager.sh restart <name>
sudo ./suit-manager.sh enable <name>
sudo ./suit-manager.sh disable <name>
sudo ./suit-manager.sh remove <name>

sudo ./suit-manager.sh status
sudo ./suit-manager.sh list
sudo ./suit-manager.sh logs <name> [lines]
sudo ./suit-manager.sh follow <name>
sudo ./suit-manager.sh check
sudo ./suit-manager.sh uninstall [keep-config|purge]

---

## Instance naming convention

- Config file: `/etc/suittunnel/<instance>.toml`
- Service unit: `suittunnel@<instance>.service`

Example:

- `/etc/suittunnel/suit0.toml`
- `suittunnel@suit0.service`

---

## Example deployment pattern

- Node A: `client`
- Node B: `server`
- Shared PSK on both nodes
- Aligned transport profile on both nodes
- Consistent spoofing-related fields according to your topology
- TUN subnet routing enabled on both ends
- Fallback profiles prepared, for example `UDP -> QUIC -> TCP`

---

## Example configs

Example configuration templates are available in:

- `examples/client.toml`
- `examples/server.toml`

These files are templates and must be edited before use.

Important fields to change:

- `real_ip`
- `peer_real_ip`
- `spoofed_ip`
- `peer_spoofed_ip`
- `spoofed_ip_pool`
- `pre_shared_key`
- `interface`
- `tun_ip`
- `tun_peer_ip`

---

## Security and operations notes

- Use a strong random `pre_shared_key`
- Keep the same `pre_shared_key` on both peers
- Restrict config file permissions
- Minimize exposed ports and protocols at firewall level
- Rotate keys and review logs regularly
- Keep multiple profiles for fast fallback
- Tune MTU/FEC/multiplexing per route quality

---

## Troubleshooting checklist

### 1. Service health

bash
sudo systemctl status suittunnel@suit0
sudo journalctl -u suittunnel@suit0 -n 200 --no-pager

### 2. Follow logs

bash
sudo journalctl -u suittunnel@suit0 -f

### 3. Check config file

bash
sudo ls -lah /etc/suittunnel/
sudo cat /etc/suittunnel/suit0.toml

### 4. Check binary

bash
which suit-tunnel
suit-tunnel --help

### 5. Check TUN interface

bash
ip addr
ip route

### 6. Check firewall

bash
sudo ss -tulpn
sudo iptables -S
sudo nft list ruleset

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
`
This project was just for testing, nothing else.
