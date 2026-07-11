# SuitTunnel Manager

Operational toolkit for deploying and managing **SuitTunnel** (formerly CandyTunnel), an IP-spoofing-focused tunneling system for filtered or unstable networks.

---

## What this project is

`suittunnel-manager` is a production-oriented management layer for the `suit-tunnel` binary.  
It automates installation, configuration, lifecycle management, and updates for multi-instance tunnel deployments on Linux.

SuitTunnel itself is built around:

- Real endpoint identity + spoof/cover endpoint identity
- Multi-protocol transport modes
- Optional obfuscation and traffic-shaping features
- Performance controls (multiplexing, FEC, tuning knobs)

---

## Why SuitTunnel (core idea)

Many tunnel systems are easy to fingerprint because they produce static flow behavior over time.  
SuitTunnel reduces signature stability by combining:

1. Endpoint role separation (real vs spoof-oriented fields)
2. Transport flexibility (protocol fallback/adaptation)
3. Packet-shape controls (padding/jitter/field variation)
4. Runtime performance tuning (mux/FEC/channel/MTU)

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
- Combined with transport/obfuscation settings, this lowers repetitive tunnel signatures.

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

## Tunnel data flow (conceptual)

text
Ingress traffic
  -> TUN capture
  -> (optional) multiplex queue
  -> (optional) FEC encode
  -> encrypt/authenticate (PSK)
  -> (optional) obfuscation stage:
- packet_padding
- ttl_jitter
- random_dscp
- fake_tls_header (mode-dependent)
- spoofing profile behavior
  -> encapsulate into selected transport
  -> network transit
  -> peer decapsulation/de-obfuscation/decrypt
  -> (optional) FEC recovery + demux
  -> TUN egress / forwarding

---

## DPI-resistance and traffic-shaping controls

SuitTunnel ecosystem can apply:

- **Protocol agility**: `udp`, `tcp`, `icmp`, `quic`, and other supported outer modes
- **Padding**: reduces deterministic packet-size fingerprints
- **TTL jitter**: avoids rigid TTL signatures
- **Random DSCP**: weakens naive QoS-based classification
- **Fake TLS-like framing**: blend with common encrypted traffic shapes
- **Port shuffle**: lower static port correlation
- **Multiplexing**: aggregate microflows efficiently
- **FEC**: improve delivery over lossy paths
- **Spoof IP pool rotation**: reduce single-identity repetition

---

## Manager script capabilities (`suit-manager.sh`)

- Download/install `suit-tunnel`
- Update from GitHub releases
- Interactive config generation
- QUIC self-signed cert generation
- systemd template creation (`suittunnel@.service`)
- Instance lifecycle operations:
  - `start`, `stop`, `restart`
  - `enable`, `disable`, `remove`
- Observability:
  - `status`, `list`, `logs`, `follow`, `check`
- Uninstall options (`keep-config` / `purge`)

---

## Configuration highlights

Typical parameters exposed by manager-generated TOML:

- Role and endpoint fields:
  - `role`, `real_ip`, `peer_real_ip`
  - `spoofed_ip`, `spoofed_ip_pool`, `peer_spoofed_ip`
- Transport:
  - `uplink_protocol`, `downlink_protocol`, `data_port`
  - shuffle controls (`shuffle_data_port`, ranges)
- Reliability/performance:
  - `enable_multiplex`, `multiplex_*`
  - `enable_fec`, `fec_group_size`
  - `tunnel_count`, `mtu`, channel capacities, worker threads
- QUIC:
  - SNI/cert/key/ALPN and flow-control limits
- Obfuscation:
  - `packet_padding`, `ttl_jitter`, `fake_tls_header`, `random_dscp`
- Access/security:
  - `pre_shared_key`, `allowed_peers`

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

- Node A (edge): `client`
- Node B (core): `server`
- Shared PSK and aligned transport profile
- Consistent spoofing-related fields according to your topology
- TUN subnet routing enabled on both ends
- Fallback profiles prepared (e.g., UDP -> QUIC -> TCP)

---

## Security and operations notes

- Use strong random `pre_shared_key`
- Restrict config permissions
- Minimize exposed ports/protocols at firewall level
- Rotate keys and review logs regularly
- Keep multiple profiles for fast fallback
- Tune MTU/FEC/multiplexing per route quality

---

## Troubleshooting checklist

1. **Service health**
   
```bash
   sudo systemctl status suittunnel@suit0
   sudo journalctl -u suittunnel@suit0 -n 200 --no-pager
