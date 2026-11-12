//! STUN client implementation (RFC 5389)

use crate::{NatError, NatResult};
use bytes::{Bytes, BytesMut, BufMut};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunMessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
}

/// STUN attribute types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunAttributeType {
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,
    ChangeRequest = 0x0003,
    SourceAddress = 0x0004,
    ChangedAddress = 0x0005,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028,
}

/// STUN error
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("Response too short")]
    ResponseTooShort,
    #[error("Not a Binding Response")]
    NotBindingResponse,
    #[error("Invalid magic cookie")]
    InvalidMagicCookie,
    #[error("No XOR-MAPPED-ADDRESS found")]
    NoXorMappedAddress,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
}

/// STUN message (simplified)
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: u16,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<(u16, Vec<u8>)>,
}

/// STUN client for NAT traversal
pub struct StunClient {
    socket: UdpSocket,
    server_addr: SocketAddr,
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client
    pub async fn new(server_addr: SocketAddr, bind_addr: Option<SocketAddr>) -> NatResult<Self> {
        let socket = match bind_addr {
            Some(addr) => UdpSocket::bind(addr).await?,
            None => {
                let addr = match server_addr {
                    SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                    SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                };
                UdpSocket::bind(addr).await?
            }
        };

        socket.connect(server_addr).await?;
        Ok(Self {
            socket,
            server_addr,
            timeout: Duration::from_secs(5),
        })
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform a STUN Binding request to discover public IP/port
    pub async fn binding_request(&self) -> NatResult<SocketAddr> {
        let request = self.build_binding_request();
        let mut buf = [0u8; 1500];

        self.socket.send(&request).await?;
        
        let len = timeout(self.timeout, self.socket.recv(&mut buf)).await??;
        let response = &buf[..len];

        self.parse_binding_response(response)
    }

    /// Build a STUN Binding Request
    fn build_binding_request(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(100);
        
        // STUN header: Message Type (0x0001), Length (0), Magic Cookie, Transaction ID
        buf.put_u16(0x0001); // Binding Request
        buf.put_u16(0); // Length (will be updated)
        buf.put_u32(0x2112A442); // Magic Cookie
        
        // Transaction ID (96 bits = 12 bytes)
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill(&mut transaction_id);
        buf.put_slice(&transaction_id);

        // Add FINGERPRINT attribute (optional but recommended)
        // For simplicity, we'll skip it for now

        // Update length
        let len = buf.len() - 20; // Subtract header size
        buf[2] = ((len >> 8) & 0xFF) as u8;
        buf[3] = (len & 0xFF) as u8;

        buf.to_vec()
    }

    /// Parse STUN Binding Response
    fn parse_binding_response(&self, data: &[u8]) -> NatResult<SocketAddr> {
        if data.len() < 20 {
            return Err(NatError::Stun(StunError::ResponseTooShort));
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != 0x0101 && msg_type != 0x0111 {
            return Err(NatError::Stun(StunError::NotBindingResponse));
        }

        // Check magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != 0x2112A442 {
            return Err(NatError::Stun(StunError::InvalidMagicCookie));
        }

        // Parse attributes
        let mut offset = 20;
        while offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            let attr_data = &data[offset..offset + attr_len];
            
            match attr_type {
                0x0001 => { /* MAPPED-ADDRESS */ }
                0x0020 => { // XOR-MAPPED-ADDRESS
                    if attr_len >= 8 {
                        let port = u16::from_be_bytes([attr_data[0], attr_data[1]]) ^ 0x2112;
                        let addr_bytes = [
                            attr_data[4] ^ 0x21,
                            attr_data[5] ^ 0x12,
                            attr_data[6] ^ 0xA4,
                            attr_data[7] ^ 0x42,
                        ];
                        let ip = Ipv4Addr::from(addr_bytes);
                        let port = port ^ 0x2112;
                        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                    }
                }
                _ => {}
            }
            offset += 4 + attr_len;
            // Align to 4-byte boundary
            offset = (offset + 3) & !3;
        }

        Err(NatError::Stun(StunError::NoXorMappedAddress))
    }
}

/// STUN message builder
pub struct StunMessageBuilder {
    msg_type: u16,
    transaction_id: [u8; 12],
    attributes: Vec<(u16, Vec<u8>)>,
}

impl StunMessageBuilder {
    pub fn new(msg_type: u16) -> Self {
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill(&mut transaction_id);
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(mut self, attr_type: u16, value: Vec<u8>) -> Self {
        self.attributes.push((attr_type, value));
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        
        // Header
        buf.put_u16(self.msg_type);
        buf.put_u16(0); // Length placeholder
        buf.put_u32(0x2112A442); // Magic cookie
        buf.put_slice(&self.transaction_id);

        // Attributes
        for (attr_type, value) in self.attributes {
            buf.put_u16(attr_type);
            buf.put_u16(value.len() as u16);
            buf.put_slice(&value);
            // Padding to 4-byte boundary
            let padding = (4 - (value.len() % 4)) % 4;
            buf.put_bytes(0, padding);
        }

        // Update length
        let len = buf.len() - 20;
        buf[2] = ((len >> 8) & 0xFF) as u8;
        buf[3] = (len & 0xFF) as u8;

        buf.to_vec()
    }
}