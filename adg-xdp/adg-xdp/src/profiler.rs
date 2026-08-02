use adg_xdp_common::HostStats;

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
pub enum FragBehavior {
    Normal,
    Anomalous,
}

impl std::fmt::Display for FragBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FragBehavior::Normal => "NORMAL",
            FragBehavior::Anomalous => "ANOMALOUS",
        };
        write!(f, "{}", s)
    }
}

fn frag_behavior(stats: &HostStats) -> FragBehavior {
    if stats.packets == 0 {
        return FragBehavior::Normal;
    }
    let rate = stats.frag_packets as f64 / stats.packets as f64;
    // Over 5% fragmented packets is highly suspicious on modern networks
    if rate > 0.05 {
        FragBehavior::Anomalous
    } else {
        FragBehavior::Normal
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

#[derive(Debug)]
pub struct HostProfile {
    pub ip: u32,
    pub packets: u64,
    pub bytes: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub syn: u64,
    pub frag: u64,
    pub last_seen: u64,
    pub activity: ActivityLevel,
    pub protocol: ProtocolProfile,
    pub syn_behavior: SynBehavior,
    pub frag_behavior: FragBehavior,
    pub recent_activity: RecentActivity,
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
            frag: stats.frag_packets,
            last_seen: stats.last_seen,
            activity: activity_level(stats),
            protocol: protocol_profile(stats),
            syn_behavior: syn_behavior(stats),
            frag_behavior: frag_behavior(stats),
            recent_activity: activity_state(idle_ns),
        }
    }
}
