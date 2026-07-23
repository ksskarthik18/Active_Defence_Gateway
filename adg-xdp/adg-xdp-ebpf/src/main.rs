#![no_std]
#![no_main]

use adg_xdp_common::{
    EthHdr,
    Ipv4Hdr,
    TcpHdr,
    HostStats,
    MAX_ENTRIES,
};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

const TCP_SYN: u16 = 0x0002;

#[map]
static HOST_STATS: HashMap<u32, HostStats> =
    HashMap::with_max_entries(MAX_ENTRIES, 0);

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

    let mut is_syn = 0;
    if ipv4.protocol == 6 {
        let ip_header_len = ((ipv4.version_ihl & 0x0F) * 4) as usize;
        let tcp_offset = eth_len + ip_header_len;

        if let Ok(tcp_ptr) = ptr_at::<TcpHdr>(&ctx, tcp_offset) {
            // Using read_unaligned to prevent Rust UB on unaligned packet data
            let tcp = unsafe { core::ptr::read_unaligned(tcp_ptr) };
            let flags = u16::from_be(tcp.data_offset_reserved_flags) & 0x01FF;
            if flags & TCP_SYN != 0 {
                is_syn = 1;
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
        }
    } else {
        let initial = HostStats {
            packets: 1,
            bytes: pkt_len,
            tcp_packets: if ipv4.protocol == 6 { 1 } else { 0 },
            udp_packets: if ipv4.protocol == 17 { 1 } else { 0 },
            icmp_packets: if ipv4.protocol == 1 { 1 } else { 0 },
            syn_packets: is_syn,
            last_seen: 0,
        };
        let _ = HOST_STATS.insert(&src_addr, &initial, 0);
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
