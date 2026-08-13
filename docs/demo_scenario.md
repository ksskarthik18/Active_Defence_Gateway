# ADG Demo Scenario Plan — Guide Review

> Normal → Attack → Trust Degradation → Adaptive Response → Recovery

## Prerequisites

```bash
# Terminal 1: Mininet
sudo mn --topo single,3 --mac --switch ovsk --controller remote

# Terminal 2: eBPF observation plane
cd adg-xdp && sudo RUST_LOG=info cargo run --release -- --iface enp1s0

# Terminal 3: SDN controller
cd controller && ryu-manager adg_controller.py
```

## Phase 1: Normal Host (Trust = 100)

```bash
h1 curl -s -o /dev/null http://10.0.0.2:80
h1 ping -c 5 10.0.0.2
```

**Expected Rust output**: `10.0.0.1 | LOW | TCP | NORMAL | NORMAL | ACTIVE | 100 | 0 | 0 | TRUSTED`

**Expected controller**: `Trust: 100, Decision: ALLOW, Priority: 1`

**Expected flows**: `sudo ovs-ofctl dump-flows s1` → priority=0 (table-miss) + priority=1 (learned)

## Phase 2: Attack — SYN Scan (Trust → 50, MIRROR)

```bash
h1 for i in $(seq 1 50); do nc -z -w 1 10.0.0.2 $((i + 1000)); done
```

**Expected Rust output**: `10.0.0.1 | HIGH | TCP | AGGRESSIVE | NORMAL | ACTIVE | 50 | -50 | 0 | SUSPICIOUS`

**Expected controller**:
```
[TRUST UPDATE]
Host: 10.0.0.1 | Trust: 50 | Policy: ALLOW -> MIRROR
```

**Expected flows**: NEW priority=120 `ipv4_src=10.0.0.1` → `actions=NORMAL,output:CONTROLLER(128)`

## Phase 3: Attack — Fragmentation (Trust → 0, DROP)

```bash
h1 hping3 -S -f -p 80 -c 200 10.0.0.2
```

**Expected Rust output**: `10.0.0.1 | HIGH | TCP | AGGRESSIVE | ANOMALOUS | ACTIVE | 0 | -50 | -85 | UNTRUSTED`

**Expected controller**:
```
[TRUST UPDATE]
Host: 10.0.0.1 | Trust: 0 | Policy: MIRROR -> DROP
```

**Expected flows**: NEW priority=200 `ipv4_src=10.0.0.1` → `actions=drop`

## Phase 4: Verify Isolation

```bash
h1 ping -c 3 10.0.0.2   # Expected: 100% packet loss (h1 is blocked)
h2 ping -c 3 10.0.0.3   # Expected: 0% packet loss (unaffected)
```

## Phase 5: Recovery (Stop attack, wait 2-4s)

**Expected Rust output**: `10.0.0.1 | IDLE | UNKNOWN | UNKNOWN | NORMAL | ACTIVE | 100 | 0 | 0 | TRUSTED`

**Expected controller**:
```
[TRUST UPDATE]
Host: 10.0.0.1 | Trust: 100 | Policy: DROP -> ALLOW
```

**Expected flows**: DROP flow REMOVED. `h1 ping -c 3 10.0.0.2` → 0% loss.

## Timeline Summary

| Time | Trust | Policy | Event |
|------|-------|--------|-------|
| t=0s | 100 | ALLOW | Normal traffic |
| t=10s | 50 | MIRROR | SYN scan detected |
| t=15s | 0 | DROP | Fragmentation attack |
| t=17s | 0 | DROP | h1 isolated, h2/h3 unaffected |
| t=22s | 100 | ALLOW | Windowed delta clean → recovery |

## Verification Commands

```bash
sudo bpftool map dump pinned /sys/fs/bpf/HOST_TRUST
sudo ovs-ofctl dump-flows s1
```
