use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use super::security_graph::{GraphEdge, SecurityGraph};

/// 1. Breadth-First Search (BFS)
/// Traverses reachable nodes level by level starting from `start_ip`.
/// Deterministic traversal ordering is guaranteed by sorting outgoing edges by target IP.
pub fn bfs(graph: &SecurityGraph, start_ip: u32) -> Vec<u32> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut order = Vec::new();

    if graph.get_node(start_ip).is_none() {
        return order;
    }

    visited.insert(start_ip);
    queue.push_back(start_ip);

    while let Some(current) = queue.pop_front() {
        order.push(current);

        let mut outgoing: Vec<u32> = graph
            .outgoing_edges(current)
            .iter()
            .map(|e| e.dst_ip)
            .collect();
        outgoing.sort(); // Ensure deterministic traversal

        for next in outgoing {
            if !visited.contains(&next) {
                visited.insert(next);
                queue.push_back(next);
            }
        }
    }

    order
}

/// 2. Depth-First Search (DFS)
/// Explores deep along each path starting from `start_ip`.
/// Deterministic traversal ordering is guaranteed by sorting outgoing target IPs.
pub fn dfs(graph: &SecurityGraph, start_ip: u32) -> Vec<u32> {
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();

    if graph.get_node(start_ip).is_none() {
        return order;
    }

    fn dfs_inner(
        graph: &SecurityGraph,
        current: u32,
        visited: &mut BTreeSet<u32>,
        order: &mut Vec<u32>,
    ) {
        visited.insert(current);
        order.push(current);

        let mut outgoing: Vec<u32> = graph
            .outgoing_edges(current)
            .iter()
            .map(|e| e.dst_ip)
            .collect();
        outgoing.sort();

        for next in outgoing {
            if !visited.contains(&next) {
                dfs_inner(graph, next, visited, order);
            }
        }
    }

    dfs_inner(graph, start_ip, &mut visited, &mut order);
    order
}

#[derive(Copy, Clone, Debug)]
struct State {
    cost: f64,
    position: u32,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.position == other.position
    }
}

impl Eq for State {}

impl Ord for State {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.position.cmp(&other.position))
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// 3. Dijkstra's Shortest Path / Minimum Risk Path
/// Computes min-cost path from `start_ip` to all reachable nodes using custom `cost_fn`.
///
/// `cost_fn` extracts numeric cost for a `GraphEdge` (e.g. edge_risk, latency, or inverse trust).
pub fn dijkstra<F>(
    graph: &SecurityGraph,
    start_ip: u32,
    cost_fn: F,
) -> BTreeMap<u32, (f64, Vec<u32>)>
where
    F: Fn(&GraphEdge) -> f64,
{
    let mut dist: BTreeMap<u32, f64> = BTreeMap::new();
    let mut prev: BTreeMap<u32, u32> = BTreeMap::new();
    let mut heap = BinaryHeap::new();

    if graph.get_node(start_ip).is_none() {
        return BTreeMap::new();
    }

    dist.insert(start_ip, 0.0);
    heap.push(State {
        cost: 0.0,
        position: start_ip,
    });

    while let Some(State { cost, position }) = heap.pop() {
        if let Some(&d) = dist.get(&position) {
            if cost > d {
                continue;
            }
        }

        for edge in graph.outgoing_edges(position) {
            let next = edge.dst_ip;
            let edge_cost = cost_fn(edge);
            let next_cost = cost + edge_cost;

            let current_best = dist.get(&next).copied().unwrap_or(f64::INFINITY);
            if next_cost < current_best {
                dist.insert(next, next_cost);
                prev.insert(next, position);
                heap.push(State {
                    cost: next_cost,
                    position: next,
                });
            }
        }
    }

    let mut result = BTreeMap::new();
    for (&node, &total_cost) in &dist {
        let mut path = Vec::new();
        let mut curr = node;
        path.push(curr);
        while let Some(&p) = prev.get(&curr) {
            path.push(p);
            curr = p;
        }
        path.reverse();
        result.insert(node, (total_cost, path));
    }

    result
}

/// 4. Connected Components
/// Identifies isolated network regions by treating directed edges as undirected links.
pub fn connected_components(graph: &SecurityGraph) -> Vec<Vec<u32>> {
    let mut visited = BTreeSet::new();
    let mut components = Vec::new();

    for &ip in graph.nodes().keys() {
        if !visited.contains(&ip) {
            let mut component = Vec::new();
            let mut queue = VecDeque::new();

            visited.insert(ip);
            queue.push_back(ip);

            while let Some(curr) = queue.pop_front() {
                component.push(curr);
                for nbr in graph.neighbors(curr) {
                    if !visited.contains(&nbr) {
                        visited.insert(nbr);
                        queue.push_back(nbr);
                    }
                }
            }
            component.sort();
            components.push(component);
        }
    }

    components.sort();
    components
}

/// 5. Weighted Degree
/// Returns `(weighted_in_degree, weighted_out_degree)` for a host IP.
/// Weighted out-degree = sum of outgoing edge byte_count
/// Weighted in-degree = sum of incoming edge byte_count
pub fn weighted_degree(graph: &SecurityGraph, ip: u32) -> (f64, f64) {
    let in_degree: f64 = graph
        .incoming_edges(ip)
        .iter()
        .map(|e| e.byte_count as f64)
        .sum();

    let out_degree: f64 = graph
        .outgoing_edges(ip)
        .iter()
        .map(|e| e.byte_count as f64)
        .sum();

    (in_degree, out_degree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_intelligence::security_graph::{GraphEdge, GraphNode, SecurityGraph};

    // 10.0.0.x addresses as u32 (host byte order)
    const H1: u32 = 0x0A000001; // 10.0.0.1
    const H2: u32 = 0x0A000002; // 10.0.0.2
    const H3: u32 = 0x0A000003; // 10.0.0.3
    const H4: u32 = 0x0A000004; // 10.0.0.4
    const H5: u32 = 0x0A000005; // 10.0.0.5
    const H6: u32 = 0x0A000006; // 10.0.0.6

    fn setup_test_graph() -> SecurityGraph {
        // Test Graph:
        // h1 -> h2
        //  | \
        //  |  -> h3
        //  |
        //  -> h4
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3, H4] {
            graph.add_node(GraphNode {
                host_ip: id,
                trust_score: 100,
                risk_level: 0,
            });
        }

        graph.add_edge(GraphEdge {
            src_ip: H1,
            dst_ip: H2,
            packet_count: 10,
            byte_count: 1000,
            flow_count: 1,
            unique_ports: 1,
            edge_risk: 0.1,
            last_seen: 1,
        });

        graph.add_edge(GraphEdge {
            src_ip: H1,
            dst_ip: H3,
            packet_count: 20,
            byte_count: 2000,
            flow_count: 1,
            unique_ports: 2,
            edge_risk: 0.3,
            last_seen: 1,
        });

        graph.add_edge(GraphEdge {
            src_ip: H1,
            dst_ip: H4,
            packet_count: 50,
            byte_count: 5000,
            flow_count: 1,
            unique_ports: 5,
            edge_risk: 0.5,
            last_seen: 1,
        });

        graph
    }

    #[test]
    fn test_bfs_traversal() {
        let graph = setup_test_graph();
        let order = bfs(&graph, H1);
        assert_eq!(order, vec![H1, H2, H3, H4]);
    }

    #[test]
    fn test_dfs_traversal() {
        let graph = setup_test_graph();
        let order = dfs(&graph, H1);
        assert_eq!(order, vec![H1, H2, H3, H4]);
    }

    #[test]
    fn test_dijkstra_shortest_risk_path() {
        let graph = setup_test_graph();
        let paths = dijkstra(&graph, H1, |e| e.edge_risk);

        assert_eq!(paths.get(&H1).unwrap().0, 0.0);
        assert_eq!(paths.get(&H2).unwrap().0, 0.1);
        assert_eq!(paths.get(&H2).unwrap().1, vec![H1, H2]);

        assert_eq!(paths.get(&H3).unwrap().0, 0.3);
        assert_eq!(paths.get(&H3).unwrap().1, vec![H1, H3]);

        assert_eq!(paths.get(&H4).unwrap().0, 0.5);
        assert_eq!(paths.get(&H4).unwrap().1, vec![H1, H4]);
    }

    #[test]
    fn test_connected_components() {
        let mut graph = setup_test_graph();
        // Add an isolated pair: h5 <-> h6
        graph.add_node(GraphNode { host_ip: H5, trust_score: 100, risk_level: 0 });
        graph.add_node(GraphNode { host_ip: H6, trust_score: 100, risk_level: 0 });
        graph.add_edge(GraphEdge {
            src_ip: H5,
            dst_ip: H6,
            packet_count: 1,
            byte_count: 64,
            flow_count: 1,
            unique_ports: 1,
            edge_risk: 0.0,
            last_seen: 1,
        });

        let components = connected_components(&graph);
        assert_eq!(components.len(), 2);
        assert_eq!(components[0], vec![H1, H2, H3, H4]);
        assert_eq!(components[1], vec![H5, H6]);
    }

    #[test]
    fn test_weighted_degree() {
        let graph = setup_test_graph();
        let (in_deg, out_deg) = weighted_degree(&graph, H1);
        assert_eq!(in_deg, 0.0);
        assert_eq!(out_deg, 8000.0); // 1000 + 2000 + 5000

        let (h4_in, h4_out) = weighted_degree(&graph, H4);
        assert_eq!(h4_in, 5000.0);
        assert_eq!(h4_out, 0.0);
    }

    // ===== BRUTAL EDGE CASES =====

    #[test]
    fn test_bfs_empty_graph() {
        let graph = SecurityGraph::new();
        let order = bfs(&graph, H1);
        assert!(order.is_empty());
    }

    #[test]
    fn test_dfs_empty_graph() {
        let graph = SecurityGraph::new();
        let order = dfs(&graph, H1);
        assert!(order.is_empty());
    }

    #[test]
    fn test_dijkstra_empty_graph() {
        let graph = SecurityGraph::new();
        let paths = dijkstra(&graph, H1, |e| e.edge_risk);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_connected_components_empty_graph() {
        let graph = SecurityGraph::new();
        let cc = connected_components(&graph);
        assert!(cc.is_empty());
    }

    #[test]
    fn test_weighted_degree_nonexistent_node() {
        let graph = SecurityGraph::new();
        let (in_d, out_d) = weighted_degree(&graph, H1);
        assert_eq!(in_d, 0.0);
        assert_eq!(out_d, 0.0);
    }

    #[test]
    fn test_single_isolated_node() {
        let mut graph = SecurityGraph::new();
        graph.add_node(GraphNode { host_ip: H1, trust_score: 100, risk_level: 0 });
        let bfs_order = bfs(&graph, H1);
        assert_eq!(bfs_order, vec![H1]);
        let dfs_order = dfs(&graph, H1);
        assert_eq!(dfs_order, vec![H1]);
        let cc = connected_components(&graph);
        assert_eq!(cc, vec![vec![H1]]);
    }

    #[test]
    fn test_all_isolated_nodes() {
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3, H4] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        let cc = connected_components(&graph);
        assert_eq!(cc.len(), 4, "Each isolated node is its own component");
        for c in &cc {
            assert_eq!(c.len(), 1);
        }
    }

    #[test]
    fn test_cycle_graph() {
        // H1 -> H2 -> H3 -> H1 (cycle)
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        graph.add_edge(GraphEdge { src_ip: H1, dst_ip: H2, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.1, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H2, dst_ip: H3, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.2, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H3, dst_ip: H1, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.3, last_seen: 1 });

        // BFS/DFS must not infinite loop
        let bfs_order = bfs(&graph, H1);
        assert_eq!(bfs_order.len(), 3);
        assert_eq!(bfs_order[0], H1);
        let dfs_order = dfs(&graph, H1);
        assert_eq!(dfs_order.len(), 3);
        assert_eq!(dfs_order[0], H1);

        // Connected components: single component
        let cc = connected_components(&graph);
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].len(), 3);
    }

    #[test]
    fn test_linear_chain_traversal_order() {
        // H1 -> H2 -> H3 -> H4 (linear chain)
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3, H4] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        graph.add_edge(GraphEdge { src_ip: H1, dst_ip: H2, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.1, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H2, dst_ip: H3, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.2, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H3, dst_ip: H4, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.3, last_seen: 1 });

        let bfs_order = bfs(&graph, H1);
        assert_eq!(bfs_order, vec![H1, H2, H3, H4]);
        let dfs_order = dfs(&graph, H1);
        assert_eq!(dfs_order, vec![H1, H2, H3, H4]);
    }

    #[test]
    fn test_dijkstra_multi_hop_path() {
        // H1 -> H2 -> H3 -> H4 with cumulative cost
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3, H4] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        graph.add_edge(GraphEdge { src_ip: H1, dst_ip: H2, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.1, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H2, dst_ip: H3, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.2, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H3, dst_ip: H4, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.3, last_seen: 1 });

        let paths = dijkstra(&graph, H1, |e| e.edge_risk);
        let (cost_h4, path_h4) = paths.get(&H4).unwrap();
        assert!((cost_h4 - 0.6).abs() < 1e-9, "Cumulative cost H1->H2->H3->H4 = 0.1+0.2+0.3");
        assert_eq!(*path_h4, vec![H1, H2, H3, H4]);
    }

    #[test]
    fn test_dijkstra_prefers_cheaper_indirect_path() {
        // Direct H1->H3 costs 1.0, but H1->H2->H3 costs 0.1+0.2 = 0.3
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        graph.add_edge(GraphEdge { src_ip: H1, dst_ip: H3, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 1.0, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H1, dst_ip: H2, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.1, last_seen: 1 });
        graph.add_edge(GraphEdge { src_ip: H2, dst_ip: H3, packet_count: 1, byte_count: 100, flow_count: 1, unique_ports: 1, edge_risk: 0.2, last_seen: 1 });

        let paths = dijkstra(&graph, H1, |e| e.edge_risk);
        let (cost, path) = paths.get(&H3).unwrap();
        assert!((cost - 0.3).abs() < 1e-9, "Indirect path should be cheaper");
        assert_eq!(*path, vec![H1, H2, H3]);
    }

    #[test]
    fn test_dijkstra_unreachable_node() {
        let mut graph = SecurityGraph::new();
        graph.add_node(GraphNode { host_ip: H1, trust_score: 100, risk_level: 0 });
        graph.add_node(GraphNode { host_ip: H2, trust_score: 100, risk_level: 0 }); // no edge
        let paths = dijkstra(&graph, H1, |e| e.edge_risk);
        assert!(paths.contains_key(&H1));
        assert!(!paths.contains_key(&H2), "H2 is unreachable from H1");
    }

    #[test]
    fn test_dijkstra_custom_cost_fn_bytes() {
        let graph = setup_test_graph();
        // Use byte_count as cost instead of edge_risk
        let paths = dijkstra(&graph, H1, |e| e.byte_count as f64);
        assert_eq!(paths.get(&H2).unwrap().0, 1000.0);
        assert_eq!(paths.get(&H3).unwrap().0, 2000.0);
        assert_eq!(paths.get(&H4).unwrap().0, 5000.0);
    }

    #[test]
    fn test_bfs_from_leaf_node() {
        let graph = setup_test_graph();
        // H4 has no outgoing edges, so BFS from H4 returns only H4
        let order = bfs(&graph, H4);
        assert_eq!(order, vec![H4]);
    }

    #[test]
    fn test_star_topology_weighted_degree() {
        // H1 is hub, H2..H6 are spokes
        let mut graph = SecurityGraph::new();
        for id in [H1, H2, H3, H4, H5, H6] {
            graph.add_node(GraphNode { host_ip: id, trust_score: 100, risk_level: 0 });
        }
        for &spoke in &[H2, H3, H4, H5, H6] {
            graph.add_edge(GraphEdge {
                src_ip: H1, dst_ip: spoke,
                packet_count: 10, byte_count: 1000, flow_count: 1,
                unique_ports: 1, edge_risk: 0.1, last_seen: 1,
            });
        }
        let (in_d, out_d) = weighted_degree(&graph, H1);
        assert_eq!(out_d, 5000.0); // 5 spokes * 1000 bytes
        assert_eq!(in_d, 0.0);

        // Each spoke has in=1000, out=0
        let (s_in, s_out) = weighted_degree(&graph, H5);
        assert_eq!(s_in, 1000.0);
        assert_eq!(s_out, 0.0);
    }
}
