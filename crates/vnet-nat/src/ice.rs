//! ICE agent implementation (RFC 8445)

use crate::{NatError, NatResult};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ICE candidate types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CandidateType {
    Host = 0x01,
    ServerReflexive = 0x02,
    PeerReflexive = 0x03,
    Relay = 0x04,
}

/// ICE candidate
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    pub foundation: String,
    pub component_id: u8,
    pub transport: String,
    pub priority: u32,
    pub address: IpAddr,
    pub port: u16,
    pub candidate_type: CandidateType,
    pub related_address: Option<IpAddr>,
    pub related_port: Option<u16>,
    pub tcp_type: Option<String>,
}

impl IceCandidate {
    pub fn to_sdp(&self) -> String {
        let addr_str = match self.address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{}]", ip),
        };
        
        let mut s = format!(
            "a=candidate:{} {} {} {} {} {} typ {}",
            self.foundation, self.component_id, self.transport, self.priority,
            addr_str, self.port, match self.candidate_type {
                CandidateType::Host => "host",
                CandidateType::ServerReflexive => "srflx",
                CandidateType::PeerReflexive => "prflx",
                CandidateType::Relay => "relay",
            }
        );

        if let (Some(raddr), Some(rport)) = (self.related_address, self.related_port) {
            s.push_str(&format!(" raddr {} rport {}", raddr, rport));
        }

        if let Some(tcp_type) = &self.tcp_type {
            s.push_str(&format!(" tcptype {}", tcp_type));
        }

        s
    }

    pub fn from_sdp(_line: &str) -> Result<Self, String> {
        // Simplified SDP parsing
        Err("Not implemented".into())
    }
}

/// ICE connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IceState {
    New = 0x01,
    Checking = 0x02,
    Connected = 0x03,
    Completed = 0x04,
    Failed = 0x05,
    Disconnected = 0x06,
    Closed = 0x07,
}

impl TryFrom<u8> for CandidateType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Host),
            0x02 => Ok(Self::ServerReflexive),
            0x03 => Ok(Self::PeerReflexive),
            0x04 => Ok(Self::Relay),
            _ => Err(()),
        }
    }
}

/// ICE agent for managing connectivity
pub struct IceAgent {
    local_candidates: Vec<IceCandidate>,
    remote_candidates: Vec<IceCandidate>,
    state: IceState,
    controlling: bool,
    tie_breaker: u64,
}

impl IceAgent {
    pub fn new(controlling: bool) -> Self {
        Self {
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            state: IceState::New,
            controlling,
            tie_breaker: rand::random(),
        }
    }

    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        self.local_candidates.push(candidate);
    }

    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        self.remote_candidates.push(candidate);
    }

    pub fn set_remote_candidates(&mut self, candidates: Vec<IceCandidate>) {
        self.remote_candidates = candidates;
    }

    pub fn state(&self) -> IceState {
        self.state
    }

    pub fn local_candidates(&self) -> &[IceCandidate] {
        &self.local_candidates
    }

    /// Start connectivity checks
    pub async fn start_connectivity_checks(&mut self) -> Result<(), String> {
        self.state = IceState::Checking;
        // Simplified - in real implementation, this would do connectivity checks
        // against all candidate pairs
        self.state = IceState::Connected;
        Ok(())
    }

    /// Get the selected candidate pair
    pub fn selected_pair(&self) -> Option<(IceCandidate, IceCandidate)> {
        if self.state == IceState::Connected || self.state == IceState::Completed {
            if let (Some(local), Some(remote)) = (self.local_candidates.first(), self.remote_candidates.first()) {
                return Some((local.clone(), remote.clone()));
            }
        }
        None
    }
}