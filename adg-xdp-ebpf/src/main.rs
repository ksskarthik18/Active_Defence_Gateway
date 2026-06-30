#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp] // an attribute macro that marks this function as an XDP program
// converts your Rust function into a kernel-recognized XDP entry point.

// ctx is the context of the XDP program, which contains information about the packet and the environment
pub fn adg_xdp(ctx: XdpContext) -> u32 {
    match try_adg_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_adg_xdp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
// specifies the license of the eBPF program, which is required for loading the program into the kernel. 
// The license must be compatible with the GPL to allow certain kernel functions to be used.
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
