use adg_xdp_common::HostStats;
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

#[derive(Debug)]
pub enum ActivityLevel {
    Idle,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ActivityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ActivityLevel::Idle => "IDLE",
            ActivityLevel::Low => "LOW",
            ActivityLevel::Medium => "MEDIUM",
            ActivityLevel::High => "HIGH",
        };
        write!(f, "{}", s)
    }
}

fn activity_level(stats: &HostStats) -> ActivityLevel {
    if stats.packets == 0 {
        ActivityLevel::Idle
    } else if stats.packets < 50 {
        ActivityLevel::Low
    } else if stats.packets < 500 {
        ActivityLevel::Medium
    } else {
        ActivityLevel::High
    }
}

#[derive(Debug)]
pub enum ProtocolProfile {
    TcpDominant,
    UdpDominant,
    IcmpDominant,
    Mixed,
    Unknown,
}

impl std::fmt::Display for ProtocolProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProtocolProfile::TcpDominant => "TCP",
            ProtocolProfile::UdpDominant => "UDP",
            ProtocolProfile::IcmpDominant => "ICMP",
            ProtocolProfile::Mixed => "MIXED",
            ProtocolProfile::Unknown => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

fn protocol_profile(stats: &HostStats) -> ProtocolProfile {
    let tcp = stats.tcp_packets;
    let udp = stats.udp_packets;
    let icmp = stats.icmp_packets;

    if tcp == 0 && udp == 0 && icmp == 0 {
        return ProtocolProfile::Unknown;
    }

    if tcp > udp && tcp > icmp {
        ProtocolProfile::TcpDominant
    } else if udp > tcp && udp > icmp {
        ProtocolProfile::UdpDominant
    } else if icmp > tcp && icmp > udp {
        ProtocolProfile::IcmpDominant
    } else {
        ProtocolProfile::Mixed
    }
}

#[derive(Debug)]
pub enum SynBehavior {
    Normal,
    Moderate,
    Aggressive,
    Unknown,
}

impl std::fmt::Display for SynBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SynBehavior::Normal => "NORMAL",
            SynBehavior::Moderate => "MODERATE",
            SynBehavior::Aggressive => "AGGRESSIVE",
            SynBehavior::Unknown => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

fn syn_rate(stats: &HostStats) -> f64 {
    if stats.tcp_packets == 0 {
        return 0.0;
    }
    stats.syn_packets as f64 / stats.tcp_packets as f64
}

fn syn_behavior(stats: &HostStats) -> SynBehavior {
    if stats.tcp_packets == 0 {
        return SynBehavior::Unknown;
    }

    let rate = syn_rate(stats);

    if rate < 0.05 {
        SynBehavior::Normal
    } else if rate < 0.20 {
        SynBehavior::Moderate
    } else {
        SynBehavior::Aggressive
    }
}




#[derive(Debug)]
pub enum RecentActivity {
    Active,
    Recent,
    Idle,
}

impl std::fmt::Display for RecentActivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecentActivity::Active => "ACTIVE",
            RecentActivity::Recent => "RECENT",
            RecentActivity::Idle => "IDLE",
        };
        write!(f, "{}", s)
    }
}

fn activity_state(idle_ns: u64) -> RecentActivity {
    const SECOND: u64 = 1_000_000_000;

    if idle_ns < 5 * SECOND {
        RecentActivity::Active
    } else if idle_ns < 30 * SECOND {
        RecentActivity::Recent
    } else {
        RecentActivity::Idle
    }
}

fn get_ktime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[derive(Debug)]
pub struct HostProfile {
    pub ip: u32,
    pub packets: u64,
    pub bytes: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub syn: u64,
    pub last_seen: u64,
    pub activity: ActivityLevel,
    pub protocol: ProtocolProfile,
    pub syn_behavior: SynBehavior,
    pub recent_activity: RecentActivity,
}

pub struct TrustScore {
    pub score: u8,
}

#[derive(Debug)]
pub enum TrustLevel {
    Trusted,
    Normal,
    Suspicious,
    Untrusted,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TrustLevel::Trusted => "TRUSTED",
            TrustLevel::Normal => "NORMAL",
            TrustLevel::Suspicious => "SUSPICIOUS",
            TrustLevel::Untrusted => "UNTRUSTED",
        };
        write!(f, "{}", s)
    }
}

impl TrustScore {
    pub fn level(&self) -> TrustLevel {
        match self.score {
            90..=100 => TrustLevel::Trusted,
            70..=89 => TrustLevel::Normal,
            40..=69 => TrustLevel::Suspicious,
            _ => TrustLevel::Untrusted,
        }
    }
}

pub struct HostProfiler;

impl HostProfiler {
    pub fn build(ip: u32, stats: &HostStats, current_time: u64) -> HostProfile {
        let idle_ns = current_time.saturating_sub(stats.last_seen);
        HostProfile {
            ip,
            packets: stats.packets,
            bytes: stats.bytes,
            tcp: stats.tcp_packets,
            udp: stats.udp_packets,
            icmp: stats.icmp_packets,
            syn: stats.syn_packets,
            last_seen: stats.last_seen,
            activity: activity_level(stats),
            protocol: protocol_profile(stats),
            syn_behavior: syn_behavior(stats),
            recent_activity: activity_state(idle_ns),
        }
    }
}

pub struct TrustEngine;

impl TrustEngine {
    pub fn compute(profile: &HostProfile) -> TrustScore {
        let mut trust: i32 = 100;

        match profile.activity {
            ActivityLevel::High => {}
            ActivityLevel::Medium => trust -= 5,
            ActivityLevel::Low => trust -= 10,
            ActivityLevel::Idle => trust -= 15,
        }

        match profile.protocol {
            ProtocolProfile::TcpDominant => {}
            ProtocolProfile::UdpDominant => {}
            ProtocolProfile::IcmpDominant => {}
            ProtocolProfile::Mixed => trust -= 5,
            ProtocolProfile::Unknown => trust -= 10,
        }

        match profile.syn_behavior {
            SynBehavior::Normal => {}
            SynBehavior::Moderate => trust -= 20,
            SynBehavior::Aggressive => trust -= 50,
            SynBehavior::Unknown => {}
        }

        match profile.recent_activity {
            RecentActivity::Active => {}
            RecentActivity::Recent => trust -= 5,
            RecentActivity::Idle => trust -= 15,
        }

        trust = trust.clamp(0, 100);

        TrustScore {
            score: trust as u8,
        }
    }
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
