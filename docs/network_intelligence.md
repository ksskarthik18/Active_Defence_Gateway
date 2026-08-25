# Active Defense Gateway (ADG) — Network Intelligence Layer

## Overview

The **Network Intelligence Layer** is an advanced analytical extension built on top of the Active Defense Gateway (ADG) observation plane. It operates without modifying the core `TrustEngine`, `HostStats` struct, eBPF map layouts, or OpenFlow `ALLOW`/`MIRROR`/`DROP` policy enforcement.

---

## 1. Current ADG Telemetry

The existing production BPF map (`HOST_STATS`) tracks cumulative host metrics per source IPv4 address:

| Field | Type | Description |
|---|---|---|
| `packets` | `u64` | Total packet count |
| `bytes` | `u64` | Total byte count |
| `tcp_packets` | `u64` | Total TCP packets |
| `udp_packets` | `u64` | Total UDP packets |
| `icmp_packets` | `u64` | Total ICMP packets |
| `syn_packets` | `u64` | Total TCP SYN packets |
| `frag_packets` | `u64` | Total IP fragmented packets |
| `last_seen` | `u64` | Monotonic timestamp (`bpf_ktime_get_ns`) |

---

## 2. Missing Telemetry Gaps

While `HostStats` evaluates per-source host behavior, it lacks fine-grained flow-level and destination-aware intelligence required to detect reconnaissance and lateral movement:

- **Destination IP diversity:** Cannot track how many distinct internal target IPs a host contacts.
- **Port scan detection:** Cannot track unique destination ports accessed per time window.
- **Connection failure tracking:** Cannot count TCP RST packets returned by closed ports.
- **Packet size distribution:** Lacks minimum/maximum packet size bounds to identify fixed-size scan/exfiltration streams.
- **Flow cardinality:** Lacks bounded flow tracking per host pair.

To bridge these gaps without breaking `HostStats`, ADG defines `ExtendedHostStats` in `adg-xdp-common`:

```rust
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExtendedHostStats {
    pub packets: u64,
    pub bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub syn_packets: u64,
    pub frag_packets: u64,
    pub last_seen: u64,
    pub rst_packets: u64,
    pub unique_dst_ips: u32,
    pub unique_dst_ports: u32,
    pub flow_count: u32,
    pub _pad: u32,
    pub min_pkt_size: u16,
    pub max_pkt_size: u16,
    pub _pad2: u32,
}
```

---

## 3. Flow Model (`FlowTable`)

Flow tracking is modeled as a 5-tuple key with accumulated statistics:

### `FlowKey`
- `src_ip`: `u32`
- `dst_ip`: `u32`
- `src_port`: `u16`
- `dst_port`: `u16`
- `protocol`: `u8`

### `FlowStats`
- `packets`: `u64`
- `bytes`: `u64`
- `first_seen`: `u64` (nanoseconds)
- `last_seen`: `u64` (nanoseconds)
- `syn_packets`: `u64`
- `rst_packets`: `u64`
- `fin_packets`: `u64`

### `FlowTable` Bounded Memory & Expiration
- Deterministic storage using `BTreeMap<FlowKey, FlowStats>`.
- Bounded capacity (e.g., `max_flows = 10,000`).
- Configurable flow timeout (default: 30 seconds / `30_000_000_000` ns).
- `expire(current_time_ns)` prunes stale flows to prevent memory exhaustion.

---

## 4. SecurityGraph Model

The communication graph represents host connectivity and edge-level interaction risks:

### `GraphNode`
- `host_ip`: `u32`
- `trust_score`: `u8` (from `TrustEngine`)
- `risk_level`: `u8`

### `GraphEdge` (Directed)
- `src_ip`: `u32`
- `dst_ip`: `u32`
- `packet_count`: `u64`
- `byte_count`: `u64`
- `flow_count`: `u32`
- `unique_ports`: `u32`
- `edge_risk`: `f64`
- `last_seen`: `u64`

### Deterministic Representation
Implemented via `SecurityGraph` using `BTreeMap<u32, GraphNode>` and `BTreeMap<(u32, u32), GraphEdge>`.

---

## 5. Graph Algorithms (Classical, Non-ML)

All graph algorithms operate deterministically on `SecurityGraph`:

### 1. Breadth-First Search (BFS)
- **Purpose:** Blast radius estimation — determines all hosts reachable within $k$ hops from a compromised host.
- **Ordering:** Deterministic by sorting neighbor target IPs.

### 2. Depth-First Search (DFS)
- **Purpose:** Attack path exploration — traverses deep into multi-hop lateral movement chains.

### 3. Dijkstra's Minimum-Risk Path
- **Purpose:** Computes the lowest cumulative risk path from a source host to critical target servers.
- **Cost Function:** Custom caller-provided closure `cost_fn(&GraphEdge) -> f64` (default uses `edge_risk`).

### 4. Connected Components
- **Purpose:** Partition analysis — identifies isolated subnets or network clusters.

### 5. Weighted Degree
- **Purpose:** High-volume host identification — computes `(in_degree, out_degree)` weighted by byte volume across directed edges.

---

## 6. NetworkRiskEngine

Calculates a multi-dimensional `NetworkRiskScore` ($0.0$ to $1.0$) separate from `TrustEngine`:

```
network_risk =
    w1 * destination_risk +
    w2 * port_scan_risk +
    w3 * connection_failure_risk +
    w4 * graph_centrality_risk
```

### Component Formulas & Weights

| Component | Weight | Formula | Description |
|---|---|---|---|
| `destination_risk` | `w1 = 0.25` | `unique_dst_ips / flow_count` | Ratio of unique targets to total flows |
| `port_scan_risk` | `w2 = 0.25` | `unique_dst_ports / total_packets` | Ratio of target ports to total packets |
| `connection_failure_risk` | `w3 = 0.25` | `rst_count / flow_count` | Proportion of rejected connection attempts |
| `graph_centrality_risk` | `w4 = 0.25` | `min(1.0, weighted_out_degree / 50000)` | Outbound traffic volume centrality |

---

## 7. Weighted Max-Min Fairness (WMMF)

WMMF is an independent resource allocation module designed to allocate SDN bandwidth deterministically:

1. **Minimum Guarantees:** Ensures each flow receives up to its requested minimum guarantee.
2. **Proportional Share:** Distributes remaining capacity based on flow weight $w_i = \text{TrustScore} / 100$.
3. **Redistribution:** Excess capacity from saturated low-demand flows is redistributed proportionally to active high-demand flows.

---

## 8. Example Graph & Calculations

Consider the following scenario:

```
        h1 (10.0.0.1) [Scanner/Recon]
      /   |   \
     v    v    v
    h2   h3   h4
          |
          v
       Server (10.0.0.254)
```

1. **Host h1 Context:**
   - `unique_dst_ips = 3` (h2, h3, h4)
   - `unique_dst_ports = 5`
   - `rst_count = 12`
   - `out_degree = 8000 bytes`
2. **Risk Calculations:**
   - `destination_risk = 3 / 3 = 1.0`
   - `port_scan_risk = 5 / 15 = 0.33`
   - `connection_failure_risk = 12 / 15 = 0.80`
   - `graph_centrality_risk = 8000 / 50000 = 0.16`
   - `NetworkRisk = (0.25*1.0) + (0.25*0.33) + (0.25*0.80) + (0.25*0.16) = 0.5725` (High Risk)
3. **Graph Traversal:**
   - BFS Blast Radius from h1: `[10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.254]`
   - Dijkstra Shortest Risk Path: `10.0.0.1 -> 10.0.0.3 -> 10.0.0.254`

---

## 9. Future SDN Integration Points

When integrated into live enforcement in future sprints:
1. **eBPF Telemetry Update:** Replace `HOST_STATS` map lookup with `EXTENDED_HOST_STATS` or attach socket/TC filters for TCP port parsing.
2. **SDN Controller Flow Modulator:** Feed `NetworkRiskScore` into Ryu/os-ken `PolicyEngine` to dynamically adjust OpenFlow priority rules.
3. **OVS Queue Management:** Translate WMMF allocations into OpenFlow `OFPActionEnqueue` / Open_vSwitch `QoS` queues for dynamic rate-limiting.

---

## 10. Current Implementation & Validation Status

| Component / Module | Status | Notes |
|---|---|---|
| `ExtendedHostStats` struct | **IMPLEMENTED** | Defined in `adg-xdp-common/src/lib.rs` |
| `FlowKey`, `FlowStats`, `FlowTable` | **IMPLEMENTED & UNIT TESTED** | 4 unit tests covering insert, update, removal, expiry, capacity |
| `HostNetworkContext`, `HostContextBuilder` | **IMPLEMENTED & UNIT TESTED** | Unit test verifying multi-flow context aggregation |
| `SecurityGraph`, `GraphNode`, `GraphEdge` | **IMPLEMENTED & UNIT TESTED** | 2 unit tests covering graph operations & edge expiry |
| BFS, DFS, Dijkstra, CC, Weighted Degree | **IMPLEMENTED & UNIT TESTED** | 5 unit tests covering exact traversal order & shortest risk paths |
| `NetworkRiskEngine` | **IMPLEMENTED & UNIT TESTED** | 2 unit tests covering low-risk vs reconnaissance scoring |
| `WeightedMaxMinFairness` | **IMPLEMENTED & UNIT TESTED** | 6 unit tests covering equal/unequal weights, saturation, min guarantees, 0 capacity |
| Offline Intelligence Demo | **DEMO-ONLY** | Printable report generator in `demo.rs` |
| Live eBPF Map Integration | **NOT YET INTEGRATED** | Preserved existing single-controller pipeline |
| Live Controller OVS WMMF Queues | **NOT YET INTEGRATED** | Preserved existing OpenFlow ALLOW/MIRROR/DROP flows |
