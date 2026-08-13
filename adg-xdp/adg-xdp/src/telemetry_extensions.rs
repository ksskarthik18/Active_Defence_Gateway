/// Sprint 7/8 Preparation: Telemetry Extension Functions
///
/// These functions provide scoring logic for future security signals
/// that will be integrated once HOST_STATS is extended with destination
/// tracking fields. They are fully tested but NOT wired into the
/// active TrustEngine pipeline.

/// Destination diversity score.
///
/// Measures the ratio of unique destination IPs to total flows.
/// High values (>0.8) indicate scanning or lateral movement —
/// the host is contacting many different targets with few repeated flows.
///
/// Returns 0.0 if total_flows is 0.
pub fn destination_diversity(unique_dsts: u32, total_flows: u32) -> f64 {
    if total_flows == 0 {
        return 0.0;
    }
    unique_dsts as f64 / total_flows as f64
}

/// Port scan heuristic score.
///
/// Measures the ratio of unique destination ports to total TCP packets.
/// Legitimate hosts typically contact 1-5 ports. A host contacting
/// 20+ unique ports with few data packets is likely scanning.
///
/// Returns 0.0 if tcp_packets is 0.
pub fn port_scan_score(unique_ports: u32, tcp_packets: u64) -> f64 {
    if tcp_packets == 0 {
        return 0.0;
    }
    unique_ports as f64 / tcp_packets as f64
}

/// RST ratio — failed connection indicator.
///
/// A high RST:SYN ratio indicates that most connection attempts
/// are being rejected, which is a strong port scan signature.
/// Normal clients have RST:SYN < 0.1. Scanners typically > 0.5.
///
/// Returns 0.0 if syn is 0.
pub fn rst_ratio(rst: u64, syn: u64) -> f64 {
    if syn == 0 {
        return 0.0;
    }
    rst as f64 / syn as f64
}

/// Bandwidth rate in bytes per second.
///
/// Computed from bytes transferred over a time window.
/// Sudden spikes (>10x baseline) may indicate volumetric attacks
/// or data exfiltration.
pub fn bandwidth_rate(bytes: u64, window_secs: f64) -> f64 {
    if window_secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 / window_secs
}

/// Packet size uniformity score.
///
/// Returns the coefficient of variation (std_dev / mean).
/// Low values (<0.1) indicate uniform packet sizes:
/// - Uniform small packets → scan traffic
/// - Uniform large packets → bulk exfiltration
///
/// Returns 0.0 if mean is 0.
pub fn packet_size_uniformity(min_size: u16, max_size: u16) -> f64 {
    if min_size == 0 && max_size == 0 {
        return 0.0;
    }
    let range = (max_size - min_size) as f64;
    let midpoint = (max_size as f64 + min_size as f64) / 2.0;
    if midpoint == 0.0 {
        return 0.0;
    }
    range / midpoint
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- destination_diversity tests ---

    #[test]
    fn test_diversity_zero_flows() {
        assert_eq!(destination_diversity(0, 0), 0.0);
    }

    #[test]
    fn test_diversity_single_destination() {
        let score = destination_diversity(1, 100);
        assert!(score < 0.05, "Single destination should have very low diversity");
    }

    #[test]
    fn test_diversity_scanning_pattern() {
        let score = destination_diversity(50, 55);
        assert!(score > 0.8, "50 unique destinations in 55 flows = scanning");
    }

    #[test]
    fn test_diversity_normal_traffic() {
        let score = destination_diversity(3, 200);
        assert!(score < 0.05, "3 destinations in 200 flows = normal");
    }

    // --- port_scan_score tests ---

    #[test]
    fn test_port_scan_zero_tcp() {
        assert_eq!(port_scan_score(0, 0), 0.0);
    }

    #[test]
    fn test_port_scan_normal_browsing() {
        let score = port_scan_score(2, 500);
        assert!(score < 0.01, "2 ports in 500 packets = normal browsing");
    }

    #[test]
    fn test_port_scan_aggressive() {
        let score = port_scan_score(100, 120);
        assert!(score > 0.5, "100 ports in 120 packets = aggressive scan");
    }

    // --- rst_ratio tests ---

    #[test]
    fn test_rst_ratio_zero_syn() {
        assert_eq!(rst_ratio(0, 0), 0.0);
    }

    #[test]
    fn test_rst_ratio_normal() {
        let ratio = rst_ratio(2, 100);
        assert!(ratio < 0.1, "2 RSTs in 100 SYNs = normal");
    }

    #[test]
    fn test_rst_ratio_scan_signature() {
        let ratio = rst_ratio(80, 100);
        assert!(ratio > 0.5, "80 RSTs in 100 SYNs = scan");
    }

    // --- bandwidth_rate tests ---

    #[test]
    fn test_bandwidth_zero_window() {
        assert_eq!(bandwidth_rate(1000, 0.0), 0.0);
    }

    #[test]
    fn test_bandwidth_normal() {
        let rate = bandwidth_rate(1_000_000, 2.0);
        assert_eq!(rate, 500_000.0);
    }

    // --- packet_size_uniformity tests ---

    #[test]
    fn test_uniformity_zero() {
        assert_eq!(packet_size_uniformity(0, 0), 0.0);
    }

    #[test]
    fn test_uniformity_scan_traffic() {
        // Scan packets are typically 40-60 bytes (very uniform)
        let score = packet_size_uniformity(40, 60);
        assert!(score < 0.5, "40-60 byte range = uniform scan traffic");
    }

    #[test]
    fn test_uniformity_mixed_traffic() {
        // Normal traffic has wide range
        let score = packet_size_uniformity(64, 1500);
        assert!(score > 1.0, "64-1500 byte range = diverse traffic");
    }
}
