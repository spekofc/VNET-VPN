//! Endpoint abstraction for NAT traversal

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Transport {
    Udp = 0x01,
    Tcp = 0x02,
}

/// Network endpoint representation
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub transport: Transport,
    pub public: bool, // Whether this is a public (internet-routable) address
}

impl Endpoint {
    pub fn new(addr: SocketAddr, transport: Transport) -> Self {
        let public = is_public_ip(addr.ip());
        Self { addr, transport, public }
    }

    pub fn udp(addr: SocketAddr) -> Self {
        Self::new(addr, Transport::Udp)
    }

    pub fn tcp(addr: SocketAddr) -> Self {
        Self::new(addr, Transport::Tcp)
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    pub fn is_public(&self) -> bool {
        self.public
    }
}

/// Check if an IP address is publicly routable
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    // Loopback: 127.0.0.0/8
    // Link-local: 169.254.0.0/16
    // Reserved: 0.0.0.0/8, 240.0.0.0/4
    !(octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || octets[0] == 0
        || octets[0] >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // Unique local addresses: fc00::/7
    // Link-local: fe80::/10
    // Loopback: ::1
    // Unspecified: ::
    // Multicast: ff00::/8
    let segments = ip.segments();
    !(segments[0] & 0xfe00 == 0xfc00 // fc00::/7
        || segments[0] & 0xffc0 == 0xfe80 // fe80::/10
        || (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 && segments[6] == 0 && segments[7] == 1) // ::1
        || (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 && segments[6] == 0 && segments[7] == 0) // ::
        || segments[0] & 0xff00 == 0xff00) // ff00::/8
}

/// Endpoint pair for connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPair {
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl EndpointPair {
    pub fn new(local: Endpoint, remote: Endpoint) -> Self {
        Self { local, remote }
    }

    /// Check if both endpoints are public
    pub fn both_public(&self) -> bool {
        self.local.is_public() && self.remote.is_public()
    }

    /// Check if direct connection is possible
    pub fn direct_possible(&self) -> bool {
        self.local.is_public() || self.remote.is_public()
    }
}