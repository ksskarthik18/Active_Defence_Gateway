use crate::profiler::{HostProfile, SynBehavior};

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

pub trait TrustSignal {
    fn evaluate(&self, profile: &HostProfile) -> i32;
}

const MODERATE_SYN_PENALTY: i32 = 20;
const AGGRESSIVE_SYN_PENALTY: i32 = 50;

pub struct SynSignal;

impl TrustSignal for SynSignal {
    fn evaluate(&self, profile: &HostProfile) -> i32 {
        match profile.syn_behavior {
            SynBehavior::Normal => 0,
            SynBehavior::Moderate => -MODERATE_SYN_PENALTY,
            SynBehavior::Aggressive => -AGGRESSIVE_SYN_PENALTY,
            SynBehavior::Unknown => 0,
        }
    }
}

pub struct TrustEngine {
    signals: Vec<Box<dyn TrustSignal>>,
}

impl TrustEngine {
    pub fn new() -> Self {
        Self {
            signals: vec![
                Box::new(SynSignal),
                // Future signals like PortDiversitySignal, ThreatIntelSignal go here
            ],
        }
    }

    pub fn compute(&self, profile: &HostProfile) -> TrustScore {
        let mut trust: i32 = 100;
        
        for signal in &self.signals {
            trust += signal.evaluate(profile);
        }

        trust = trust.clamp(0, 100);

        TrustScore {
            score: trust as u8,
        }
    }
}
