use std::collections::BTreeMap;

pub const DEFAULT_FLOW_TIMEOUT_NS: u64 = 30_000_000_000; // 30 seconds
pub const DEFAULT_MAX_FLOWS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub syn_packets: u64,
    pub rst_packets: u64,
    pub fin_packets: u64,
}

pub struct FlowTable {
    flows: BTreeMap<FlowKey, FlowStats>,
    max_flows: usize,
    timeout_ns: u64,
}

impl FlowTable {
    pub fn new(max_flows: usize, timeout_ns: u64) -> Self {
        Self {
            flows: BTreeMap::new(),
            max_flows,
            timeout_ns,
        }
    }

    pub fn default_config() -> Self {
        Self::new(DEFAULT_MAX_FLOWS, DEFAULT_FLOW_TIMEOUT_NS)
    }

    pub fn insert_or_update(
        &mut self,
        key: FlowKey,
        pkt_bytes: u64,
        timestamp_ns: u64,
        is_syn: bool,
        is_rst: bool,
        is_fin: bool,
    ) -> bool {
        if self.flows.contains_key(&key) {
            let stats = self.flows.get_mut(&key).unwrap();
            stats.packets += 1;
            stats.bytes += pkt_bytes;
            stats.last_seen = timestamp_ns;
            if is_syn {
                stats.syn_packets += 1;
            }
            if is_rst {
                stats.rst_packets += 1;
            }
            if is_fin {
                stats.fin_packets += 1;
            }
            true
        } else {
            // Check capacity limit
            if self.flows.len() >= self.max_flows {
                // Expire old entries first
                self.expire(timestamp_ns);
                if self.flows.len() >= self.max_flows {
                    return false; // Table full, dropped
                }
            }

            let new_stats = FlowStats {
                packets: 1,
                bytes: pkt_bytes,
                first_seen: timestamp_ns,
                last_seen: timestamp_ns,
                syn_packets: if is_syn { 1 } else { 0 },
                rst_packets: if is_rst { 1 } else { 0 },
                fin_packets: if is_fin { 1 } else { 0 },
            };
            self.flows.insert(key, new_stats);
            true
        }
    }

    pub fn expire(&mut self, current_time_ns: u64) -> usize {
        let timeout = self.timeout_ns;
        let mut to_remove = Vec::new();
        for (key, stats) in &self.flows {
            if current_time_ns.saturating_sub(stats.last_seen) >= timeout {
                to_remove.push(key.clone());
            }
        }
        let count = to_remove.len();
        for key in to_remove {
            self.flows.remove(&key);
        }
        count
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<FlowStats> {
        self.flows.remove(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, FlowKey, FlowStats> {
        self.flows.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insertion_and_update() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let key = FlowKey {
            src_ip: 0x0A000001,
            dst_ip: 0x0A000002,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        // Insert
        assert!(table.insert_or_update(key.clone(), 100, 1_000_000_000, true, false, false));
        assert_eq!(table.len(), 1);

        let stats = table.get(&key).unwrap();
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.bytes, 100);
        assert_eq!(stats.first_seen, 1_000_000_000);
        assert_eq!(stats.last_seen, 1_000_000_000);
        assert_eq!(stats.syn_packets, 1);
        assert_eq!(stats.rst_packets, 0);

        // Update
        assert!(table.insert_or_update(key.clone(), 200, 2_000_000_000, false, false, true));
        assert_eq!(table.len(), 1);

        let updated = table.get(&key).unwrap();
        assert_eq!(updated.packets, 2);
        assert_eq!(updated.bytes, 300);
        assert_eq!(updated.first_seen, 1_000_000_000);
        assert_eq!(updated.last_seen, 2_000_000_000);
        assert_eq!(updated.syn_packets, 1);
        assert_eq!(updated.fin_packets, 1);
    }

    #[test]
    fn test_removal() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let key = FlowKey {
            src_ip: 0x0A000001,
            dst_ip: 0x0A000002,
            src_port: 1000,
            dst_port: 80,
            protocol: 6,
        };
        table.insert_or_update(key.clone(), 64, 1_000_000, false, false, false);
        assert_eq!(table.len(), 1);
        assert!(table.remove(&key).is_some());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_timeout_expiry() {
        let timeout_ns = 10_000_000_000; // 10s
        let mut table = FlowTable::new(100, timeout_ns);

        let k1 = FlowKey {
            src_ip: 1,
            dst_ip: 2,
            src_port: 10,
            dst_port: 20,
            protocol: 6,
        };
        let k2 = FlowKey {
            src_ip: 1,
            dst_ip: 3,
            src_port: 10,
            dst_port: 20,
            protocol: 6,
        };

        table.insert_or_update(k1.clone(), 100, 1_000_000_000, false, false, false); // t = 1s
        table.insert_or_update(k2.clone(), 100, 8_000_000_000, false, false, false); // t = 8s

        // Expire at t = 12s -> k1 (11s idle) expires, k2 (4s idle) stays
        let expired = table.expire(12_000_000_000);
        assert_eq!(expired, 1);
        assert!(table.get(&k1).is_none());
        assert!(table.get(&k2).is_some());
    }

    #[test]
    fn test_bounded_memory_capacity() {
        let mut table = FlowTable::new(2, 5_000_000_000);
        let k1 = FlowKey { src_ip: 1, dst_ip: 1, src_port: 1, dst_port: 1, protocol: 6 };
        let k2 = FlowKey { src_ip: 1, dst_ip: 2, src_port: 1, dst_port: 1, protocol: 6 };
        let k3 = FlowKey { src_ip: 1, dst_ip: 3, src_port: 1, dst_port: 1, protocol: 6 };

        table.insert_or_update(k1, 50, 1_000_000_000, false, false, false);
        table.insert_or_update(k2, 50, 2_000_000_000, false, false, false);
        assert_eq!(table.len(), 2);

        // Third flow at t = 2s without expiry -> table full, insertion rejected
        let inserted = table.insert_or_update(k3, 50, 2_000_000_000, false, false, false);
        assert!(!inserted);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_zero_byte_packets() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let key = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1, dst_port: 80, protocol: 6 };
        assert!(table.insert_or_update(key.clone(), 0, 1_000, false, false, false));
        let s = table.get(&key).unwrap();
        assert_eq!(s.bytes, 0);
        assert_eq!(s.packets, 1);
    }

    #[test]
    fn test_all_tcp_flags_simultaneously() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let key = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1, dst_port: 80, protocol: 6 };
        // SYN + RST + FIN all at once (malformed but must not panic)
        assert!(table.insert_or_update(key.clone(), 64, 1_000, true, true, true));
        let s = table.get(&key).unwrap();
        assert_eq!(s.syn_packets, 1);
        assert_eq!(s.rst_packets, 1);
        assert_eq!(s.fin_packets, 1);
        // Update with all flags again
        assert!(table.insert_or_update(key.clone(), 64, 2_000, true, true, true));
        let s2 = table.get(&key).unwrap();
        assert_eq!(s2.syn_packets, 2);
        assert_eq!(s2.rst_packets, 2);
        assert_eq!(s2.fin_packets, 2);
        assert_eq!(s2.packets, 2);
    }

    #[test]
    fn test_first_seen_preserved_on_update() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let key = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 5000, dst_port: 443, protocol: 6 };
        table.insert_or_update(key.clone(), 100, 1_000_000, false, false, false);
        table.insert_or_update(key.clone(), 200, 5_000_000, false, false, false);
        table.insert_or_update(key.clone(), 300, 9_000_000, false, false, false);
        let s = table.get(&key).unwrap();
        assert_eq!(s.first_seen, 1_000_000, "first_seen must never change after creation");
        assert_eq!(s.last_seen, 9_000_000);
        assert_eq!(s.packets, 3);
        assert_eq!(s.bytes, 600);
    }

    #[test]
    fn test_expiry_then_reinsert() {
        let mut table = FlowTable::new(100, 5_000_000_000);
        let key = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1, dst_port: 22, protocol: 6 };
        table.insert_or_update(key.clone(), 64, 1_000_000_000, true, false, false);
        assert_eq!(table.len(), 1);
        // Expire it
        table.expire(10_000_000_000);
        assert_eq!(table.len(), 0);
        // Reinsert same key — should be brand new
        table.insert_or_update(key.clone(), 128, 11_000_000_000, false, true, false);
        let s = table.get(&key).unwrap();
        assert_eq!(s.packets, 1);
        assert_eq!(s.bytes, 128);
        assert_eq!(s.first_seen, 11_000_000_000);
        assert_eq!(s.syn_packets, 0);
        assert_eq!(s.rst_packets, 1);
    }

    #[test]
    fn test_capacity_reclaimed_by_expiry() {
        let mut table = FlowTable::new(2, 5_000_000_000);
        let k1 = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000001, src_port: 1, dst_port: 1, protocol: 6 };
        let k2 = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1, dst_port: 1, protocol: 6 };
        let k3 = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000003, src_port: 1, dst_port: 1, protocol: 6 };

        table.insert_or_update(k1, 50, 1_000_000_000, false, false, false); // t=1s
        table.insert_or_update(k2, 50, 2_000_000_000, false, false, false); // t=2s
        assert_eq!(table.len(), 2);

        // At t=8s, k1 is 7s idle and k2 is 6s idle — BOTH exceed 5s timeout
        // Expiry triggered by insert_or_update reclaims both slots
        let inserted = table.insert_or_update(k3, 50, 8_000_000_000, false, false, false);
        assert!(inserted, "Insert should succeed after expiry reclaims capacity");
        assert_eq!(table.len(), 1, "Only k3 remains after both k1 and k2 expired");
    }

    #[test]
    fn test_empty_table_operations() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.expire(999_999_999_999), 0);
        let missing_key = FlowKey { src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0, protocol: 0 };
        assert!(table.get(&missing_key).is_none());
        assert!(table.remove(&missing_key).is_none());
    }

    #[test]
    fn test_remove_nonexistent_key() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let k1 = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1, dst_port: 80, protocol: 6 };
        let k2 = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000003, src_port: 1, dst_port: 80, protocol: 6 };
        table.insert_or_update(k1, 64, 1_000, false, false, false);
        assert!(table.remove(&k2).is_none());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_stress_1000_flows() {
        let mut table = FlowTable::new(2000, 30_000_000_000);
        for i in 0u32..1000 {
            let key = FlowKey {
                src_ip: 0x0A000001,
                dst_ip: 0x0A000000 + i,
                src_port: 40000 + (i as u16),
                dst_port: 80,
                protocol: 6,
            };
            assert!(table.insert_or_update(key, 64, (i as u64) * 1_000_000, i % 3 == 0, i % 5 == 0, i % 7 == 0));
        }
        assert_eq!(table.len(), 1000);
        // Expire none (all within 30s window relative to last)
        assert_eq!(table.expire(1_000_000_000), 0);
    }

    #[test]
    fn test_different_protocols_are_distinct_flows() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let tcp = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1000, dst_port: 80, protocol: 6 };
        let udp = FlowKey { src_ip: 0x0A000001, dst_ip: 0x0A000002, src_port: 1000, dst_port: 80, protocol: 17 };
        table.insert_or_update(tcp.clone(), 100, 1_000, false, false, false);
        table.insert_or_update(udp.clone(), 200, 1_000, false, false, false);
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(&tcp).unwrap().bytes, 100);
        assert_eq!(table.get(&udp).unwrap().bytes, 200);
    }

    #[test]
    fn test_default_config_constants() {
        let table = FlowTable::default_config();
        assert_eq!(table.len(), 0);
        // Just verifying it doesn't panic and uses the constants
    }
}
