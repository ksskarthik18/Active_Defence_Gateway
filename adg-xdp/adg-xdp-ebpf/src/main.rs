#![no_std]
#![no_main]

use adg_xdp_common::{
    EthHdr,
    HostStats,
    ExtendedHostStats,
    Ipv4Hdr,
    TcpHdr,
    TrustEntry,
    FlowEvent,
    MAX_ENTRIES,
};

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;

const TCP_FIN: u16 = 0x0001;
const TCP_SYN: u16 = 0x0002;
const TCP_RST: u16 = 0x0004;

#[map]
static HOST_STATS: HashMap<u32, HostStats> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static EXTENDED_HOST_STATS: HashMap<u32, ExtendedHostStats> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static HOST_TRUST: HashMap<u32, TrustEntry> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static HOST_RISK: HashMap<u32, u32> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static FLOW_EVENTS: PerfEventArray<FlowEvent> = PerfEventArray::new(0);

#[xdp]
pub fn adg_xdp(ctx: XdpContext) -> u32 {
    match try_adg_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_adg_xdp(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet Header
    let eth_ptr = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &*eth_ptr };

    // 0x0800 in network byte order (big-endian u16).
    // On x86_64 (little-endian), u16::from_be(eth.ether_type) checks for 0x0800.
    if u16::from_be(eth.ether_type) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. Parse IPv4 Header
    let eth_len = core::mem::size_of::<EthHdr>();
    let ipv4_ptr = ptr_at::<Ipv4Hdr>(&ctx, eth_len)?;
    let ipv4 = unsafe { &*ipv4_ptr };

    // Extract source IP. Converting from network byte order (big endian) to host byte order
    // so it matches std::net::Ipv4Addr::from(u32) in userspace.
    let src_addr = u32::from_be(ipv4.src_addr);
    let pkt_len = u16::from_be(ipv4.tot_len) as u64;

    // Detect fragmentation: lower 13 bits are offset, bit 13 is MF flag
    let frag_val = u16::from_be(ipv4.frag_off);
    let is_frag = if (frag_val & 0x3FFF) != 0 { 1 } else { 0 };

    let mut is_syn = 0;
    let mut is_rst = 0;
    if ipv4.protocol == 6 {
        let ip_header_len = ((ipv4.version_ihl & 0x0F) * 4) as usize;
        let tcp_offset = eth_len + ip_header_len;

        if let Ok(tcp_ptr) = ptr_at::<TcpHdr>(&ctx, tcp_offset) {
            let tcp = unsafe { core::ptr::read_unaligned(tcp_ptr) };
            let flags = u16::from_be(tcp.data_offset_reserved_flags) & 0x01FF;
            if flags & TCP_SYN != 0 {
                is_syn = 1;
            }
            if flags & TCP_RST != 0 {
                is_rst = 1;
            }

            // Stream only TCP control events (Constraint 2)
            if (flags & (TCP_SYN | TCP_FIN | TCP_RST)) != 0 {
                let event = FlowEvent {
                    src_ip: src_addr,
                    dst_ip: u32::from_be(ipv4.dst_addr),
                    src_port: u16::from_be(tcp.src_port),
                    dst_port: u16::from_be(tcp.dst_port),
                    protocol: 6,
                    flags: flags as u8,
                    pkt_size: pkt_len as u16,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                };
                
                // Constraint 5: Event delivery failure must never affect packet forwarding.
                // We ignore the Result of output.
                let _ = FLOW_EVENTS.output(&ctx, &event, 0);
            }
        }
    }

    // Update per-host telemetry in the BPF map
    let stats = HOST_STATS.get_ptr_mut(&src_addr);
    if let Some(stats_ptr) = stats {
        unsafe {
            (*stats_ptr).packets += 1;
            (*stats_ptr).bytes += pkt_len;
            match ipv4.protocol {
                1 => (*stats_ptr).icmp_packets += 1,
                6 => {
                    (*stats_ptr).tcp_packets += 1;
                    (*stats_ptr).syn_packets += is_syn;
                }
                17 => (*stats_ptr).udp_packets += 1,
                _ => {}
            }
            (*stats_ptr).frag_packets += is_frag;
            (*stats_ptr).last_seen = bpf_ktime_get_ns();
        }
    } else {
        let initial = HostStats {
            packets: 1,
            bytes: pkt_len,
            tcp_packets: if ipv4.protocol == 6 { 1 } else { 0 },
            udp_packets: if ipv4.protocol == 17 { 1 } else { 0 },
            icmp_packets: if ipv4.protocol == 1 { 1 } else { 0 },
            syn_packets: is_syn,
            frag_packets: is_frag,
            last_seen: unsafe { bpf_ktime_get_ns() },
        };
        let _ = HOST_STATS.insert(&src_addr, &initial, 0);
    }

    // Update extended telemetry in the new BPF map
    let ext_stats = EXTENDED_HOST_STATS.get_ptr_mut(&src_addr);
    if let Some(ext_ptr) = ext_stats {
        unsafe {
            (*ext_ptr).packets += 1;
            (*ext_ptr).bytes += pkt_len;
            match ipv4.protocol {
                1 => (*ext_ptr).icmp_packets += 1,
                6 => {
                    (*ext_ptr).tcp_packets += 1;
                    (*ext_ptr).syn_packets += is_syn;
                    (*ext_ptr).rst_packets += is_rst;
                }
                17 => (*ext_ptr).udp_packets += 1,
                _ => {}
            }
            (*ext_ptr).frag_packets += is_frag;
            
            let pkt_len_u16 = pkt_len as u16;
            if pkt_len_u16 < (*ext_ptr).min_pkt_size {
                (*ext_ptr).min_pkt_size = pkt_len_u16;
            }
            if pkt_len_u16 > (*ext_ptr).max_pkt_size {
                (*ext_ptr).max_pkt_size = pkt_len_u16;
            }
            
            (*ext_ptr).last_seen = bpf_ktime_get_ns();
        }
    } else {
        let pkt_len_u16 = pkt_len as u16;
        let initial_ext = ExtendedHostStats {
            packets: 1,
            bytes: pkt_len,
            tcp_packets: if ipv4.protocol == 6 { 1 } else { 0 },
            udp_packets: if ipv4.protocol == 17 { 1 } else { 0 },
            icmp_packets: if ipv4.protocol == 1 { 1 } else { 0 },
            syn_packets: is_syn,
            frag_packets: is_frag,
            last_seen: unsafe { bpf_ktime_get_ns() },
            rst_packets: is_rst,
            unique_dst_ips: 0,
            unique_dst_ports: 0,
            flow_count: 0,
            _pad: 0,
            min_pkt_size: pkt_len_u16,
            max_pkt_size: pkt_len_u16,
            _pad2: 0,
        };
        let _ = EXTENDED_HOST_STATS.insert(&src_addr, &initial_ext, 0);
    }

    info!(&ctx, "packet seen from src: {:i}, action: PASS", ipv4.src_addr);

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
