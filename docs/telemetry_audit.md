# ADG Telemetry Audit — Field Inventory

> Audit Date: 2026-08-13
> Auditor: Automated analysis of ADG repository

## 1. XDP Observation Plane — Fields Collected

The eBPF/XDP program (`adg-xdp-ebpf/src/main.rs`) parses the following from every IPv4 packet:

### Ethernet Layer
| Field | Parsed | Stored | Used |
|-------|--------|--------|------|
| `dst_addr` (MAC) | ✅ | ❌ | ❌ |
| `src_addr` (MAC) | ✅ | ❌ | ❌ |
| `ether_type` | ✅ | ❌ | ✅ IPv4 filter (0x0800) |

### IPv4 Layer
| Field | Parsed | Stored in HOST_STATS | Used by TrustEngine |
|-------|--------|---------------------|---------------------|
| `src_addr` | ✅ | ✅ (map key) | ✅ (host identity) |
| `dst_addr` | ✅ (in `Ipv4Hdr`) | ❌ **NOT STORED** | ❌ |
| `tot_len` | ✅ | ✅ (as `bytes`) | ❌ (not directly) |
| `protocol` | ✅ | ✅ (tcp/udp/icmp split) | ✅ (ProtocolProfile) |
| `frag_off` | ✅ | ✅ (as `frag_packets`) | ✅ (FragBehavior) |
| `version_ihl` | ✅ | ❌ | ❌ |
| `tos` | ✅ (in struct) | ❌ | ❌ |
| `id` | ✅ (in struct) | ❌ | ❌ |
| `ttl` | ✅ (in struct) | ❌ | ❌ |
| `check` | ✅ (in struct) | ❌ | ❌ |

### TCP Layer
| Field | Parsed | Stored in HOST_STATS | Used by TrustEngine |
|-------|--------|---------------------|---------------------|
| `src_port` | ✅ (in `TcpHdr`) | ❌ **NOT STORED** | ❌ |
| `dst_port` | ✅ (in `TcpHdr`) | ❌ **NOT STORED** | ❌ |
| SYN flag | ✅ | ✅ (as `syn_packets`) | ✅ (SynBehavior) |
| RST flag | ❌ (flags parsed but only SYN extracted) | ❌ | ❌ |
| FIN flag | ❌ | ❌ | ❌ |
| ACK flag | ❌ | ❌ | ❌ |
| `seq` / `ack_seq` | ✅ (in struct) | ❌ | ❌ |
| `window` | ✅ (in struct) | ❌ | ❌ |

---

## 2. HOST_STATS BPF Map — Stored Fields

```rust
pub struct HostStats {
    pub packets: u64,       // Total packet count
    pub bytes: u64,         // Total byte volume
    pub tcp_packets: u64,   // TCP packet count
    pub udp_packets: u64,   // UDP packet count
    pub icmp_packets: u64,  // ICMP packet count
    pub syn_packets: u64,   // TCP SYN packet count
    pub frag_packets: u64,  // Fragmented packet count
    pub last_seen: u64,     // Kernel timestamp (bpf_ktime_get_ns)
}
```

**Map type**: `HashMap<u32, HostStats>` — keyed by source IPv4 address (host byte order).
**Max entries**: 10,240.

---

## 3. TrustEngine — Fields Consumed

The Rust TrustEngine (`trust.rs`) consumes a `HostProfile` built from `HostStats`:

| Signal | Derivation | Penalty |
|--------|-----------|---------|
| SYN ratio | `syn_packets / tcp_packets` | MODERATE: −20, AGGRESSIVE: −50 |
| Frag ratio | `frag_packets / packets` | ANOMALOUS (>5%): −85 |
| Activity level | `packets` thresholds | No penalty (classification only) |
| Protocol profile | Dominant of tcp/udp/icmp | No penalty (classification only) |
| Idle time | `ktime_ns - last_seen` | No penalty (classification only) |

**Windowed evaluation**: The userspace daemon computes delta stats between polling intervals (2s), so the TrustEngine evaluates only recent behavior — enabling natural trust recovery.

---

## 4. Fields Currently Ignored

These fields are **parsed by the XDP program** or **present in shared structs** but are **never stored or used** for trust computation:

### Critical Gaps (HIGH priority for Sprint 7)
| Field | Available In | Why It Matters |
|-------|-------------|----------------|
| `dst_addr` | `Ipv4Hdr.dst_addr` | Destination diversity → port scan / lateral movement detection |
| `dst_port` | `TcpHdr.dst_port` | Unique port count → port scan signature |
| `src_port` | `TcpHdr.src_port` | Source port entropy → evasion detection |
| TCP RST flag | `TcpHdr.data_offset_reserved_flags` | Failed connection ratio → scan fingerprint |

### Lower Priority Gaps
| Field | Available In | Why It Matters |
|-------|-------------|----------------|
| `ttl` | `Ipv4Hdr.ttl` | TTL anomalies → OS fingerprinting / spoofing |
| `tos` | `Ipv4Hdr.tos` | DSCP abuse → covert channels |
| `window` | `TcpHdr.window` | Zero-window probes → resource exhaustion |
| `id` | `Ipv4Hdr.id` | Predictable IP IDs → idle scanning |

---

## 5. HOST_TRUST BPF Map — Output

```rust
pub struct TrustEntry {
    pub score: u8,    // 0-100 trust score
    pub level: u8,    // TrustLevel enum ordinal
    pub version: u8,  // Schema version (currently 1)
    pub flags: u8,    // Reserved for future use
}
```

**Pinned at**: `/sys/fs/bpf/HOST_TRUST`
**Consumed by**: Python OS-Ken controller via raw `bpf()` syscall through ctypes.

---

## 6. Pipeline Data Flow Summary

```
NIC Packet
    │
    ▼
┌─────────────────────────────┐
│ XDP eBPF Program            │
│ Parse: Eth → IPv4 → TCP     │
│ Extract: src_ip, protocol,  │
│   SYN flag, frag flag,      │
│   packet length             │
│ Store → HOST_STATS map      │
└──────────┬──────────────────┘
           │ (BPF map)
           ▼
┌─────────────────────────────┐
│ Rust Userspace Daemon       │
│ Read HOST_STATS (2s poll)   │
│ Compute windowed delta      │
│ Build HostProfile           │
│ TrustEngine::compute()      │
│ Write → HOST_TRUST map      │
└──────────┬──────────────────┘
           │ (pinned BPF map)
           ▼
┌─────────────────────────────┐
│ Python OS-Ken Controller    │
│ TrustStore.get(ip)          │
│   → bpf() syscall lookup   │
│ PolicyEngine.evaluate()     │
│ FlowInstaller → OpenFlow    │
│ TrustChangeDetector (bg)    │
└─────────────────────────────┘
```
