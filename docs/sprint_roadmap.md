# ADG Sprint 7/8 Roadmap

## Sprint 7: Destination Intelligence (2 weeks)

### Goal
Extend XDP telemetry to track destination IPs and ports, enabling port scan and lateral movement detection.

### 7.1 — Extend HOST_STATS struct
- Add `dst_ip_hash` field (u64) — rolling hash of unique destination IPs
- Add `unique_dst_ports` (u32) — approximate unique port count via bitmap
- Add `rst_packets` (u64) — TCP RST counter
- **Risk**: Increases map value size → must verify eBPF stack limits

### 7.2 — XDP: extract and store destination fields
- Store `dst_addr` from `Ipv4Hdr` alongside `src_addr`
- Store `dst_port` from `TcpHdr` into new counter
- Extract TCP RST flag from `data_offset_reserved_flags` (bit 0x0004)
- **Constraint**: eBPF complexity limits — use simple counters, not sets

### 7.3 — Rust Profiler: new behavioral signals
- `destination_diversity()` — unique_dst_ips / flow_count ratio
- `port_scan_score()` — unique_dst_ports / tcp_packets ratio
- `rst_ratio()` — rst_packets / syn_packets ratio
- Add `PortScanBehavior` and `LateralMovementBehavior` enums to profiler

### 7.4 — TrustEngine: integrate new signals
- Port scan penalty: −30 (>20 unique ports in window)
- Lateral movement penalty: −40 (>10 unique internal IPs in window)
- RST ratio penalty: −15 (>50% RST:SYN)
- **Constraint**: Additive penalties only — do NOT change existing SYN/frag formula

### 7.5 — Tests
- Unit tests for new profiler signals
- Unit tests for new TrustEngine penalties
- Integration test: SYN scan + port diversity → trust < 40

### Deliverables
- [ ] Extended `HostStats` struct in `adg-xdp-common`
- [ ] XDP program storing destination fields
- [ ] New profiler signals with classification enums
- [ ] New TrustEngine penalties (additive, backward-compatible)
- [ ] 10+ new unit tests

---

## Sprint 8: Behavioral Intelligence (2 weeks)

### Goal
Add temporal analysis, trust history, and flow-level intelligence.

### 8.1 — Trust History Ring Buffer
- Rust daemon maintains last N trust scores per host
- Detect oscillation pattern (attack → pause → attack)
- Anti-gaming: if trust oscillated >3 times in 60s, apply decay multiplier

### 8.2 — Packet Size Statistics
- Track min/max/mean packet size per host in HOST_STATS
- Signal: uniform small packets → scan, uniform large → exfiltration
- New profiler enum: `PacketSizeBehavior { Normal, SmallUniform, LargeUniform }`

### 8.3 — Bandwidth Rate Computation
- Compute `bytes / window_duration` in Rust daemon
- Signal: sudden 10x bandwidth spike → volumetric attack or exfiltration
- New profiler enum: `BandwidthBehavior { Normal, Spike, Sustained }`

### 8.4 — Failed Connection Ratio
- Track SYN-sent vs SYN-ACK-received (requires stateful TCP tracking)
- Alternative: use RST ratio as proxy (simpler, already in Sprint 7)
- Decision point: full TCP state tracking vs. RST proxy

### 8.5 — Controller Enrichment
- Extend `TrustEntry` with `flags` field usage:
  - bit 0: port_scan_detected
  - bit 1: lateral_movement_detected
  - bit 2: trust_oscillation
  - bit 3: bandwidth_anomaly
- Python controller can read flags for richer logging

### Deliverables
- [ ] Trust history ring buffer in Rust daemon
- [ ] Anti-gaming oscillation detection
- [ ] Packet size statistics
- [ ] Bandwidth rate computation
- [ ] TrustEntry flags usage
- [ ] 10+ new tests

---

## Sprint 9+ (Future)

### Graph Intelligence
- Construct host communication graph from flow data
- Identify attack propagation paths (temporal correlation)
- Risk-aware routing (steer traffic away from compromised segments)

### WMMF Resource Control
- Weighted Max-Min Fairness bandwidth allocation
- Gradual throttling instead of binary DROP
- Requires OpenFlow meter table integration

### Active Deception
- Honeypot redirection via REDIRECT policy
- Moving target defense (IP/port randomization)
- Tarpit integration for slow-drain attackers
