use crate::profiler::{ActivityLevel, HostProfile, ProtocolProfile, RecentActivity, SynBehavior};

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
