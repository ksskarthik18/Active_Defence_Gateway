use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub host_ip: u32,
    pub trust_score: u8,
    pub risk_level: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub packet_count: u64,
    pub byte_count: u64,
    pub flow_count: u32,
    pub unique_ports: u32,
    pub edge_risk: f64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityGraph {
    nodes: BTreeMap<u32, GraphNode>,
    edges: BTreeMap<(u32, u32), GraphEdge>,
}

impl SecurityGraph {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.insert(node.host_ip, node);
    }

    pub fn update_node(&mut self, node: GraphNode) {
        self.add_node(node);
    }

    pub fn get_node(&self, ip: u32) -> Option<&GraphNode> {
        self.nodes.get(&ip)
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        // Automatically ensure nodes exist if not present
        if !self.nodes.contains_key(&edge.src_ip) {
            self.nodes.insert(
                edge.src_ip,
                GraphNode {
                    host_ip: edge.src_ip,
                    trust_score: 100,
                    risk_level: 0,
                },
            );
        }
        if !self.nodes.contains_key(&edge.dst_ip) {
            self.nodes.insert(
                edge.dst_ip,
                GraphNode {
                    host_ip: edge.dst_ip,
                    trust_score: 100,
                    risk_level: 0,
                },
            );
        }
        self.edges.insert((edge.src_ip, edge.dst_ip), edge);
    }

    pub fn update_edge(&mut self, edge: GraphEdge) {
        self.add_edge(edge);
    }

    pub fn get_edge(&self, src_ip: u32, dst_ip: u32) -> Option<&GraphEdge> {
        self.edges.get(&(src_ip, dst_ip))
    }

    pub fn remove_expired_edges(&mut self, current_time_ns: u64, timeout_ns: u64) -> usize {
        let mut to_remove = Vec::new();
        for (key, edge) in &self.edges {
            if current_time_ns.saturating_sub(edge.last_seen) >= timeout_ns {
                to_remove.push(*key);
            }
        }
        let count = to_remove.len();
        for key in to_remove {
            self.edges.remove(&key);
        }
        count
    }

    pub fn neighbors(&self, ip: u32) -> Vec<u32> {
        let mut set = BTreeSet::new();
        for (src, dst) in self.edges.keys() {
            if *src == ip {
                set.insert(*dst);
            } else if *dst == ip {
                set.insert(*src);
            }
        }
        set.into_iter().collect()
    }

    pub fn outgoing_edges(&self, ip: u32) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|((src, _), _)| *src == ip)
            .map(|(_, edge)| edge)
            .collect()
    }

    pub fn incoming_edges(&self, ip: u32) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|((_, dst), _)| *dst == ip)
            .map(|(_, edge)| edge)
            .collect()
    }

    pub fn nodes(&self) -> &BTreeMap<u32, GraphNode> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeMap<(u32, u32), GraphEdge> {
        &self.edges
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 10.0.0.x addresses as u32 (host byte order)
    const H1: u32 = 0x0A000001; // 10.0.0.1
    const H2: u32 = 0x0A000002; // 10.0.0.2

    #[test]
    fn test_node_and_edge_management() {
        let mut graph = SecurityGraph::new();

        graph.add_node(GraphNode { host_ip: H1, trust_score: 90, risk_level: 1 });
        graph.add_node(GraphNode { host_ip: H2, trust_score: 50, risk_level: 2 });

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.get_node(H1).unwrap().trust_score, 90);

        let edge = GraphEdge {
            src_ip: H1,
            dst_ip: H2,
            packet_count: 10,
            byte_count: 1000,
            flow_count: 1,
            unique_ports: 1,
            edge_risk: 0.1,
            last_seen: 1_000_000,
        };
        graph.add_edge(edge.clone());

        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.outgoing_edges(H1).len(), 1);
        assert_eq!(graph.incoming_edges(H2).len(), 1);
        assert_eq!(graph.neighbors(H1), vec![H2]);
        assert_eq!(graph.neighbors(H2), vec![H1]);
    }

    #[test]
    fn test_expired_edges() {
        let mut graph = SecurityGraph::new();
        graph.add_edge(GraphEdge {
            src_ip: H1,
            dst_ip: H2,
            packet_count: 5,
            byte_count: 500,
            flow_count: 1,
            unique_ports: 1,
            edge_risk: 0.2,
            last_seen: 1_000_000,
        });

        assert_eq!(graph.remove_expired_edges(10_000_000_000, 5_000_000_000), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    // ===== BRUTAL EDGE CASES =====

    #[test]
    fn test_duplicate_edge_overwrites() {
        let mut graph = SecurityGraph::new();
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H2, packet_count: 10, byte_count: 100,
            flow_count: 1, unique_ports: 1, edge_risk: 0.1, last_seen: 1,
        });
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H2, packet_count: 99, byte_count: 9999,
            flow_count: 5, unique_ports: 3, edge_risk: 0.9, last_seen: 2,
        });
        assert_eq!(graph.edge_count(), 1, "Second add_edge should overwrite, not duplicate");
        assert_eq!(graph.get_edge(H1, H2).unwrap().packet_count, 99);
    }

    #[test]
    fn test_directed_edge_asymmetry() {
        let mut graph = SecurityGraph::new();
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H2, packet_count: 10, byte_count: 100,
            flow_count: 1, unique_ports: 1, edge_risk: 0.5, last_seen: 1,
        });
        assert!(graph.get_edge(H1, H2).is_some());
        assert!(graph.get_edge(H2, H1).is_none(), "Directed: H2->H1 must not exist");
        assert_eq!(graph.outgoing_edges(H1).len(), 1);
        assert_eq!(graph.outgoing_edges(H2).len(), 0);
        assert_eq!(graph.incoming_edges(H1).len(), 0);
        assert_eq!(graph.incoming_edges(H2).len(), 1);
    }

    #[test]
    fn test_self_loop_edge() {
        let mut graph = SecurityGraph::new();
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H1, packet_count: 1, byte_count: 64,
            flow_count: 1, unique_ports: 1, edge_risk: 0.0, last_seen: 1,
        });
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.outgoing_edges(H1).len(), 1);
        assert_eq!(graph.incoming_edges(H1).len(), 1);
        // Self-loop: H1 is its own neighbor
        assert_eq!(graph.neighbors(H1), vec![H1]);
    }

    #[test]
    fn test_node_update_preserves_edges() {
        let mut graph = SecurityGraph::new();
        graph.add_node(GraphNode { host_ip: H1, trust_score: 100, risk_level: 0 });
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H2, packet_count: 5, byte_count: 500,
            flow_count: 1, unique_ports: 1, edge_risk: 0.2, last_seen: 1,
        });
        // Update H1 trust score
        graph.update_node(GraphNode { host_ip: H1, trust_score: 30, risk_level: 3 });
        assert_eq!(graph.get_node(H1).unwrap().trust_score, 30);
        assert_eq!(graph.edge_count(), 1, "Edges must survive node update");
    }

    #[test]
    fn test_add_edge_auto_creates_nodes() {
        let mut graph = SecurityGraph::new();
        assert_eq!(graph.node_count(), 0);
        graph.add_edge(GraphEdge {
            src_ip: H1, dst_ip: H2, packet_count: 1, byte_count: 64,
            flow_count: 1, unique_ports: 1, edge_risk: 0.0, last_seen: 1,
        });
        assert_eq!(graph.node_count(), 2, "add_edge should auto-create missing nodes");
        assert!(graph.get_node(H1).is_some());
        assert!(graph.get_node(H2).is_some());
    }

    #[test]
    fn test_empty_graph_queries() {
        let mut graph = SecurityGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert!(graph.get_node(H1).is_none());
        assert!(graph.get_edge(H1, H2).is_none());
        assert!(graph.outgoing_edges(H1).is_empty());
        assert!(graph.incoming_edges(H1).is_empty());
        assert!(graph.neighbors(H1).is_empty());
        assert_eq!(graph.remove_expired_edges(999, 1), 0);
    }

    #[test]
    fn test_large_graph_50_nodes() {
        let mut graph = SecurityGraph::new();
        // Create 50 nodes in a chain: 0x0A000001 -> 0x0A000002 -> ... -> 0x0A000032
        for i in 1..=50u32 {
            let ip = 0x0A000000 + i;
            graph.add_node(GraphNode { host_ip: ip, trust_score: 100, risk_level: 0 });
        }
        for i in 1..50u32 {
            let src = 0x0A000000 + i;
            let dst = 0x0A000000 + i + 1;
            graph.add_edge(GraphEdge {
                src_ip: src, dst_ip: dst, packet_count: 1, byte_count: 100,
                flow_count: 1, unique_ports: 1, edge_risk: 0.01, last_seen: 1,
            });
        }
        assert_eq!(graph.node_count(), 50);
        assert_eq!(graph.edge_count(), 49);
        assert_eq!(graph.neighbors(0x0A000019).len(), 2); // mid-chain has 2 neighbors
    }
}
