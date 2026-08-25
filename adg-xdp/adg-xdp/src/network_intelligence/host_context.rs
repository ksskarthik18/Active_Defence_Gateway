use std::collections::BTreeSet;
use super::flow_table::FlowTable;

#[derive(Debug, Clone, PartialEq)]
pub struct HostNetworkContext {
    pub host_ip: u32,
    pub unique_dst_ips: u32,
    pub unique_dst_ports: u32,
    pub flow_count: u32,
    pub rst_count: u64,
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub min_packet_size: u16,
    pub max_packet_size: u16,
}

pub struct HostContextBuilder;

impl HostContextBuilder {
    pub fn build_for_host(host_ip: u32, flow_table: &FlowTable, window_secs: f64) -> HostNetworkContext {
        let mut dst_ips = BTreeSet::new();
        let mut dst_ports = BTreeSet::new();
        let mut flow_count = 0u32;
        let mut rst_count = 0u64;
        let mut total_bytes = 0u64;
        let mut total_packets = 0u64;
        let mut min_pkt_size = u16::MAX;
        let mut max_pkt_size = 0u16;

        for (key, stats) in flow_table.iter() {
            if key.src_ip == host_ip {
                dst_ips.insert(key.dst_ip);
                dst_ports.insert(key.dst_port);
                flow_count += 1;
                rst_count += stats.rst_packets;
                total_bytes += stats.bytes;
                total_packets += stats.packets;

                if stats.packets > 0 {
                    let avg_pkt_size = (stats.bytes / stats.packets) as u16;
                    if avg_pkt_size < min_pkt_size {
                        min_pkt_size = avg_pkt_size;
                    }
                    if avg_pkt_size > max_pkt_size {
                        max_pkt_size = avg_pkt_size;
                    }
                }
            }
        }

        if min_pkt_size == u16::MAX {
            min_pkt_size = 0;
        }

        let bps = if window_secs > 0.0 {
            total_bytes as f64 / window_secs
        } else {
            0.0
        };

        let pps = if window_secs > 0.0 {
            total_packets as f64 / window_secs
        } else {
            0.0
        };

        HostNetworkContext {
            host_ip,
            unique_dst_ips: dst_ips.len() as u32,
            unique_dst_ports: dst_ports.len() as u32,
            flow_count,
            rst_count,
            bytes_per_second: bps,
            packets_per_second: pps,
            min_packet_size: min_pkt_size,
            max_packet_size: max_pkt_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_intelligence::flow_table::{FlowKey, FlowTable};

    #[test]
    fn test_host_context_calculation() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let host = 0x0A000001;

        let k1 = FlowKey { src_ip: host, dst_ip: 0x0A000002, src_port: 1000, dst_port: 80, protocol: 6 };
        let k2 = FlowKey { src_ip: host, dst_ip: 0x0A000003, src_port: 1001, dst_port: 443, protocol: 6 };
        let k3 = FlowKey { src_ip: host, dst_ip: 0x0A000002, src_port: 1002, dst_port: 80, protocol: 6 };

        table.insert_or_update(k1, 200, 1_000_000, true, true, false); // 200 bytes, RST
        table.insert_or_update(k2, 500, 1_000_000, true, false, false); // 500 bytes
        table.insert_or_update(k3, 100, 1_000_000, true, true, false); // 100 bytes, RST

        let ctx = HostContextBuilder::build_for_host(host, &table, 2.0);

        assert_eq!(ctx.host_ip, host);
        assert_eq!(ctx.unique_dst_ips, 2); // .2 and .3
        assert_eq!(ctx.unique_dst_ports, 2); // 80 and 443
        assert_eq!(ctx.flow_count, 3);
        assert_eq!(ctx.rst_count, 2);
        assert_eq!(ctx.bytes_per_second, 800.0 / 2.0); // 400.0 Bps
        assert_eq!(ctx.packets_per_second, 3.0 / 2.0); // 1.5 Pps
        assert_eq!(ctx.min_packet_size, 100);
        assert_eq!(ctx.max_packet_size, 500);
    }

    #[test]
    fn test_empty_flow_table_produces_zero_context() {
        let table = FlowTable::new(100, 30_000_000_000);
        let ctx = HostContextBuilder::build_for_host(0x0A000001, &table, 2.0);
        assert_eq!(ctx.unique_dst_ips, 0);
        assert_eq!(ctx.unique_dst_ports, 0);
        assert_eq!(ctx.flow_count, 0);
        assert_eq!(ctx.rst_count, 0);
        assert_eq!(ctx.bytes_per_second, 0.0);
        assert_eq!(ctx.packets_per_second, 0.0);
        assert_eq!(ctx.min_packet_size, 0);
        assert_eq!(ctx.max_packet_size, 0);
    }

    #[test]
    fn test_flows_from_other_hosts_excluded() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let host_a = 0x0A000001;
        let host_b = 0x0A000099;

        // Flow from host_a
        let ka = FlowKey { src_ip: host_a, dst_ip: 0x0A000002, src_port: 1000, dst_port: 80, protocol: 6 };
        table.insert_or_update(ka, 100, 1_000, false, false, false);

        // Flow from host_b (should not appear in host_a context)
        let kb = FlowKey { src_ip: host_b, dst_ip: 0x0A000003, src_port: 2000, dst_port: 443, protocol: 6 };
        table.insert_or_update(kb, 500, 1_000, false, true, false);

        let ctx = HostContextBuilder::build_for_host(host_a, &table, 1.0);
        assert_eq!(ctx.unique_dst_ips, 1);
        assert_eq!(ctx.flow_count, 1);
        assert_eq!(ctx.rst_count, 0, "host_b RST must not leak into host_a context");
        assert_eq!(ctx.bytes_per_second, 100.0);
    }

    #[test]
    fn test_zero_window_produces_zero_rates() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let host = 0x0A000001;
        let k = FlowKey { src_ip: host, dst_ip: 0x0A000002, src_port: 1000, dst_port: 80, protocol: 6 };
        table.insert_or_update(k, 500, 1_000, false, false, false);

        let ctx = HostContextBuilder::build_for_host(host, &table, 0.0);
        assert_eq!(ctx.bytes_per_second, 0.0);
        assert_eq!(ctx.packets_per_second, 0.0);
    }

    #[test]
    fn test_port_scan_pattern_many_ports_same_dst() {
        let mut table = FlowTable::new(200, 30_000_000_000);
        let host = 0x0A000001;
        let target = 0x0A000002;

        // Scan 50 ports on same target
        for port in 1..=50u16 {
            let k = FlowKey { src_ip: host, dst_ip: target, src_port: 40000 + port, dst_port: port, protocol: 6 };
            table.insert_or_update(k, 64, 1_000, true, true, false); // SYN+RST
        }

        let ctx = HostContextBuilder::build_for_host(host, &table, 1.0);
        assert_eq!(ctx.unique_dst_ips, 1, "All flows target same IP");
        assert_eq!(ctx.unique_dst_ports, 50, "50 different destination ports");
        assert_eq!(ctx.flow_count, 50);
        assert_eq!(ctx.rst_count, 50, "Every scan got RST");
    }

    #[test]
    fn test_single_large_flow() {
        let mut table = FlowTable::new(100, 30_000_000_000);
        let host = 0x0A000001;
        let k = FlowKey { src_ip: host, dst_ip: 0x0A000002, src_port: 50000, dst_port: 443, protocol: 6 };
        // Simulate 100 packets in one flow
        for i in 0..100u64 {
            table.insert_or_update(k.clone(), 1500, i * 1_000_000, i == 0, false, i == 99);
        }

        let ctx = HostContextBuilder::build_for_host(host, &table, 0.1);
        assert_eq!(ctx.unique_dst_ips, 1);
        assert_eq!(ctx.unique_dst_ports, 1);
        assert_eq!(ctx.flow_count, 1);
        assert_eq!(ctx.packets_per_second, 100.0 / 0.1); // 1000 PPS
        assert_eq!(ctx.min_packet_size, ctx.max_packet_size, "Uniform packet size");
    }
}
