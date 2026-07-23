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

    pub last_seen: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HostStats {}

