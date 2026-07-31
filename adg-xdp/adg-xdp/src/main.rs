use adg_xdp_common::{HostStats, TrustEntry};
use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::{net::Ipv4Addr, time::Duration};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp1s0")]
    iface: String,
}

mod profiler;
mod trust;

use profiler::HostProfiler;
use trust::TrustEngine;

fn get_ktime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/adg-xdp"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("adg_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let host_stats: HashMap<_, u32, HostStats> =
        HashMap::try_from(ebpf.take_map("HOST_STATS").ok_or_else(|| anyhow::anyhow!("HOST_STATS map not found"))?)?;

    let mut host_trust: HashMap<_, u32, TrustEntry> =
        HashMap::try_from(ebpf.take_map("HOST_TRUST").ok_or_else(|| anyhow::anyhow!("HOST_TRUST map not found"))?)?;

    println!("Attached XDP program to {iface}. Monitoring HOST_STATS and populating HOST_TRUST map...");
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("\nReceived Ctrl-C, exiting...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                let mut entries = Vec::new();
                for item in host_stats.iter() {
                    if let Ok((ip, stats)) = item {
                        entries.push((Ipv4Addr::from(ip), stats));
                    }
                }
                if !entries.is_empty() {
                    entries.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.packets));
                    println!("\n----------------------------------------------------------------------------------------------------------------------------------------------");
                    println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<12} | {:<8} | {:<10} | {:<12}", "Host", "Activity", "Protocol", "SYN", "Recent", "Trust", "SYN Pen.", "Level");
                    println!("----------------------------------------------------------------------------------------------------------------------------------------------");
                    let current_time = get_ktime_ns();
                    for (ip, stats) in entries {
                        // Create HostProfile
                        let profile = HostProfiler::build(ip.into(), &stats, current_time);
                        // Compute TrustScore
                        let trust = TrustEngine::compute(&profile);
                        
                        // Populate HOST_TRUST eBPF map
                        let trust_entry = TrustEntry {
                            score: trust.score,
                            level: trust.level() as u8,
                            version: 1,
                            flags: 0,
                        };
                        let ip_u32: u32 = ip.into();
                        if let Err(e) = host_trust.insert(ip_u32, trust_entry, 0) {
                            warn!("Failed to update HOST_TRUST for IP {}: {}", ip, e);
                        }
                        
                        println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<12} | {:<8} | {:<10} | {:<12}",
                            ip.to_string(),
                            profile.activity.to_string(),
                            profile.protocol.to_string(),
                            profile.syn_behavior.to_string(),
                            profile.recent_activity.to_string(),
                            trust.score,
                            trust.syn_contribution,
                            trust.level().to_string()
                        );
                    }
                    println!("----------------------------------------------------------------------------------------------------------------------------------------------");
                } else {
                    debug!("HOST_STATS map currently empty.");
                }
            }
        }
    }

    Ok(())
}
