use adg_xdp_common::HostStats;
use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::{net::Ipv4Addr, time::Duration, sync::{Arc, RwLock}, collections::HashMap as StdHashMap, fs};
use tokio::signal;
use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
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
    
    // Set up shared state for the Trust Engine Socket API
    let trust_store = Arc::new(RwLock::new(StdHashMap::<String, u8>::new()));
    
    // Start Unix Domain Socket Server for OS-Ken Python controller
    let socket_path = "/tmp/adg_trust.sock";
    let _ = fs::remove_file(socket_path); // ignore error if it doesn't exist
    
    let listener = UnixListener::bind(socket_path).context("Failed to bind Unix Domain Socket")?;
    let store_clone = trust_store.clone();
    
    tokio::spawn(async move {
        println!("API Server listening at {}", socket_path);
        loop {
            match listener.accept().await {
                Ok((mut socket, _addr)) => {
                    let store = store_clone.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0; 1024];
                        if let Ok(n) = socket.read(&mut buf).await {
                            if n == 0 { return; }
                            let request = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                            
                            let response = if request.to_uppercase() == "ALL" {
                                let map = store.read().unwrap();
                                // simple json manually
                                let items: Vec<String> = map.iter()
                                    .map(|(ip, score)| format!("\"{}\": {}", ip, score))
                                    .collect();
                                format!("{{{}}}\n", items.join(", "))
                            } else {
                                // Request is an IP address
                                let map = store.read().unwrap();
                                let score = map.get(&request).copied().unwrap_or(100);
                                format!("{}\n", score)
                            };
                            
                            let _ = socket.write_all(response.as_bytes()).await;
                        }
                    });
                }
                Err(e) => {
                    warn!("Unix socket accept failed: {}", e);
                }
            }
        }
    });

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("adg_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let host_stats: HashMap<_, u32, HostStats> =
        HashMap::try_from(ebpf.map("HOST_STATS").ok_or_else(|| anyhow::anyhow!("HOST_STATS map not found"))?)?;

    println!("Attached XDP program to {iface}. Monitoring HOST_STATS map...");
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("\nReceived Ctrl-C, exiting...");
                let _ = fs::remove_file(socket_path); // Cleanup socket
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
                    println!("\n-----------------------------------------------------------------------------------------------------------------------------------------");
                    println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<12} | {:<8} | {:<12}", "Host", "Activity", "Protocol", "SYN", "Recent", "Trust", "Level");
                    println!("-----------------------------------------------------------------------------------------------------------------------------------------");
                    let current_time = get_ktime_ns();
                    for (ip, stats) in entries {
                        // Create HostProfile
                        let profile = HostProfiler::build(ip.into(), &stats, current_time);
                        // Compute TrustScore
                        let trust = TrustEngine::compute(&profile);
                        
                        // Push to trust store
                        {
                            let mut store = trust_store.write().unwrap();
                            store.insert(ip.to_string(), trust.score);
                        }
                        
                        println!("{:<16} | {:<12} | {:<12} | {:<12} | {:<12} | {:<8} | {:<12}",
                            ip.to_string(),
                            profile.activity.to_string(),
                            profile.protocol.to_string(),
                            profile.syn_behavior.to_string(),
                            profile.recent_activity.to_string(),
                            trust.score,
                            trust.level().to_string()
                        );
                    }
                    println!("-----------------------------------------------------------------------------------------------------------------------------------------");
                } else {
                    debug!("HOST_STATS map currently empty.");
                }
            }
        }
    }

    Ok(())
}
