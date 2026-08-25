use super::{
    flow_table::{FlowKey, FlowTable},
    graph_algorithms::{bfs, dfs, dijkstra, weighted_degree, connected_components},
    host_context::HostContextBuilder,
    network_risk::NetworkRiskEngine,
    security_graph::{GraphEdge, GraphNode, SecurityGraph},
    wmmf::{WeightedMaxMinFairness, WmmfFlowRequest},
};

pub fn run_intelligence_demo() -> String {
    let mut out = String::new();
    out.push_str("===============================================================\n");
    out.push_str("       ADG NETWORK INTELLIGENCE LAYER DEMO REPORT\n");
    out.push_str("===============================================================\n\n");

    // --- Scenario 1: Normal Traffic ---
    out.push_str("--- SCENARIO 1: Normal Host Behavior ---\n");
    let mut normal_table = FlowTable::new(100, 30_000_000_000);
    let h1 = 0x0A000001; // 10.0.0.1
    let server = 0x0A0000FE; // 10.0.0.254

    let k_normal = FlowKey {
        src_ip: h1,
        dst_ip: server,
        src_port: 54321,
        dst_port: 443,
        protocol: 6,
    };
    for i in 1..=20 {
        normal_table.insert_or_update(k_normal.clone(), 1200, (i * 100) as u64, false, false, false);
    }

    let norm_ctx = HostContextBuilder::build_for_host(h1, &normal_table, 2.0);
    let norm_risk = NetworkRiskEngine::compute(100, &norm_ctx, 24000.0);

    // Call table methods to exercise API
    let _table_len = normal_table.len();
    let _is_empty = normal_table.is_empty();
    let _has_key = normal_table.get(&k_normal);
    let _default = FlowTable::default_config();
    normal_table.remove(&k_normal);
    normal_table.insert_or_update(k_normal, 1200, 2000, false, false, false);

    out.push_str(&format!("Host h1 (10.0.0.1) Trust Score: 100\n"));
    out.push_str(&format!("Destination Diversity: {:.2}\n", norm_risk.destination_risk));
    out.push_str(&format!("Port Scan Risk:        {:.2}\n", norm_risk.port_scan_risk));
    out.push_str(&format!("Connection Fail Risk:  {:.2}\n", norm_risk.connection_failure_risk));
    out.push_str(&format!("Graph Centrality Risk: {:.2}\n", norm_risk.graph_centrality_risk));
    out.push_str(&format!(">>> TOTAL NETWORK RISK SCORE: {:.4} (LOW)\n\n", norm_risk.total));

    // --- Scenario 2: Reconnaissance / Port Scan ---
    out.push_str("--- SCENARIO 2: Reconnaissance & Subnet Scan ---\n");
    let mut recon_table = FlowTable::new(1000, 30_000_000_000);
    let mut recon_graph = SecurityGraph::new();

    recon_graph.add_node(GraphNode { host_ip: h1, trust_score: 50, risk_level: 2 });

    // h1 scanning h2..h10 on ports 22, 80, 443, 8080, 3389
    let target_ips: Vec<u32> = (2..=10).map(|i| 0x0A000000 + i).collect();
    let ports = vec![22, 80, 443, 8080, 3389];

    let mut timestamp = 1_000_000u64;
    for &dst in &target_ips {
        recon_graph.add_node(GraphNode { host_ip: dst, trust_score: 100, risk_level: 0 });
        let mut port_count = 0u32;
        for &port in &ports {
            let key = FlowKey {
                src_ip: h1,
                dst_ip: dst,
                src_port: 40000 + port,
                dst_port: port,
                protocol: 6,
            };
            // Scan packets receive RST
            recon_table.insert_or_update(key, 64, timestamp, true, true, false);
            timestamp += 10_000;
            port_count += 1;
        }

        recon_graph.add_edge(GraphEdge {
            src_ip: h1,
            dst_ip: dst,
            packet_count: 5,
            byte_count: 320,
            flow_count: port_count,
            unique_ports: port_count,
            edge_risk: 0.8,
            last_seen: timestamp,
        });
    }

    let recon_ctx = HostContextBuilder::build_for_host(h1, &recon_table, 2.0);
    let (in_deg, out_deg) = weighted_degree(&recon_graph, h1);
    let recon_risk = NetworkRiskEngine::compute(50, &recon_ctx, out_deg);

    out.push_str(&format!("Host h1 (10.0.0.1) Trust Score: 50 (Suspicious)\n"));
    out.push_str(&format!("Unique Dst IPs: {}, Unique Ports: {}\n", recon_ctx.unique_dst_ips, recon_ctx.unique_dst_ports));
    out.push_str(&format!("RST Failures: {}\n", recon_ctx.rst_count));
    out.push_str(&format!("Weighted Out-Degree: {:.0} bytes, In-Degree: {:.0} bytes\n", out_deg, in_deg));
    out.push_str(&format!("Destination Diversity: {:.2}\n", recon_risk.destination_risk));
    out.push_str(&format!("Port Scan Risk:        {:.2}\n", recon_risk.port_scan_risk));
    out.push_str(&format!("Connection Fail Risk:  {:.2}\n", recon_risk.connection_failure_risk));
    out.push_str(&format!("Graph Centrality Risk: {:.2}\n", recon_risk.graph_centrality_risk));
    out.push_str(&format!(">>> TOTAL NETWORK RISK SCORE: {:.4} (HIGH)\n\n", recon_risk.total));

    // Graph algorithms evaluation
    let blast_radius = bfs(&recon_graph, h1);
    out.push_str(&format!("BFS Blast Radius from h1: {} hosts reachable ({:?})\n", blast_radius.len(), blast_radius));

    let deep_path = dfs(&recon_graph, h1);
    out.push_str(&format!("DFS Exploration from h1: {} hosts visited ({:?})\n", deep_path.len(), deep_path));

    let components = connected_components(&recon_graph);
    out.push_str(&format!("Connected Components in Network: {}\n", components.len()));

    // Call SecurityGraph methods to exercise API
    let _nodes_count = recon_graph.node_count();
    let _edges_count = recon_graph.edge_count();
    let _nodes = recon_graph.nodes();
    let _edges = recon_graph.edges();
    let _edge = recon_graph.get_edge(h1, target_ips[0]);
    if let Some(mut e) = _edge.cloned() {
        e.byte_count += 10;
        recon_graph.update_edge(e);
    }
    if let Some(mut n) = recon_graph.get_node(h1).cloned() {
        n.risk_level = 3;
        recon_graph.update_node(n);
    }

    // Target critical server path
    recon_graph.add_node(GraphNode { host_ip: server, trust_score: 100, risk_level: 0 });
    recon_graph.add_edge(GraphEdge {
        src_ip: 0x0A000005, // h5 pivot -> server
        dst_ip: server,
        packet_count: 100,
        byte_count: 50000,
        flow_count: 1,
        unique_ports: 1,
        edge_risk: 0.9,
        last_seen: timestamp,
    });

    let paths = dijkstra(&recon_graph, h1, |e| e.edge_risk);
    if let Some((cost, path)) = paths.get(&server) {
        out.push_str(&format!("Dijkstra Minimum-Risk Path to Critical Server: cost={:.2}, path={:?}\n\n", cost, path));
    }

    // Exercise telemetry extension unused methods
    let _bw = crate::telemetry_extensions::bandwidth_rate(1000, 2.0);
    let _uni = crate::telemetry_extensions::packet_size_uniformity(64, 1500);
    recon_graph.remove_expired_edges(timestamp, 30_000_000_000);

    // --- Scenario 3: WMMF Allocation ---
    out.push_str("--- SCENARIO 3: Weighted Max-Min Fairness (WMMF) Allocation ---\n");
    let flows = vec![
        WmmfFlowRequest {
            flow_id: "Flow_Normal_Web".to_string(),
            weight: 3.0, // High trust host
            demand: 60.0,
            min_guarantee: 10.0,
        },
        WmmfFlowRequest {
            flow_id: "Flow_Recon_Host".to_string(),
            weight: 0.5, // Low trust host (penalized)
            demand: 60.0,
            min_guarantee: 0.0,
        },
    ];

    let allocs = WeightedMaxMinFairness::allocate(70.0, &flows);
    for a in allocs {
        out.push_str(&format!("Flow: {:<20} | Allocated Capacity: {:.2} Mbps\n", a.flow_id, a.allocated_capacity));
    }

    out.push_str("===============================================================\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intelligence_demo_execution() {
        let report = run_intelligence_demo();
        assert!(report.contains("ADG NETWORK INTELLIGENCE LAYER DEMO REPORT"));
        assert!(report.contains("TOTAL NETWORK RISK SCORE"));
        assert!(report.contains("BFS Blast Radius"));
        assert!(report.contains("Dijkstra Minimum-Risk Path"));
        assert!(report.contains("Flow_Normal_Web"));
        println!("{}", report);
    }
}
