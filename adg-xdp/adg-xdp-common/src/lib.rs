#![no_std]

pub const MAX_ENTRIES: u32 = 10240;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HostStats {
    pub packets: u64,
    pub bytes: u64,

    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,

    pub syn_packets: u64,
    pub frag_packets: u64,

    pub last_seen: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HostStats {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TrustEntry {
    pub score: u8,
    pub level: u8,
    pub version: u8,
    pub flags: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrustEntry {}

// ===== Sprint 7/8 Preparation =====
// Extended telemetry struct for future destination tracking,
// port scan detection, and flow analysis.
// NOT used by the active pipeline — preparation only.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExtendedHostStats {
    // --- Existing fields (mirror of HostStats) ---
    pub packets: u64,
    pub bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub syn_packets: u64,
    pub frag_packets: u64,
    pub last_seen: u64,
    // --- HIGH priority: destination intelligence ---
    pub rst_packets: u64,
    pub unique_dst_ips: u32,
    pub unique_dst_ports: u32,
    pub flow_count: u32,
    pub _pad: u32,
    // --- MEDIUM priority: packet statistics ---
    pub min_pkt_size: u16,
    pub max_pkt_size: u16,
    pub _pad2: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExtendedHostStats {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub data_offset_reserved_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urg_ptr: u16,
}