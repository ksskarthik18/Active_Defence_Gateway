#![no_std]
#![no_main]

use adg_xdp_common::{EthHdr, Ipv4Hdr, MAX_ENTRIES};
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[map]
static PACKET_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_ENTRIES, 0);

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

    // 3. Increment Counter in BPF HashMap
    let count = PACKET_COUNTS.get_ptr_mut(&src_addr);
    if let Some(count_ptr) = count {
        unsafe {
            *count_ptr += 1;
        }
    } else {
        let _ = PACKET_COUNTS.insert(&src_addr, &1, 0);
    }

    info!(&ctx, "packet seen from src: {:i}, action: PASS", ipv4.src_addr);

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
