//! Message types for data and control plane

use super::frame::{Frame, FrameHeader, FrameType, FrameFlags, AeadAlgorithm};
use super::constants::*;
use crate::codec::{CodecError, Decode, Encode};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Message type for control plane
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlMessageType {
    Ping = 0x01,
    Pong = 0x02,
    Ack = 0x03,
    Nack = 0x04,
    PeerListRequest = 0x10,
    PeerListResponse = 0x11,
    PeerJoined = 0x12,
    PeerLeft = 0x13,
    RouteUpdate = 0x14,
    MtuProbe = 0x20,
    MtuProbeResponse = 0x21,
    RekeyRequest = 0x30,
    RekeyResponse = 0x31,
    Close = 0xFF,
}

impl ControlMessageType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Pong),
            0x03 => Some(Self::Ack),
            0x04 => Some(Self::Nack),
            0x10 => Some(Self::PeerListRequest),
            0x11 => Some(Self::PeerListResponse),
            0x12 => Some(Self::PeerJoined),
            0x13 => Some(Self::PeerLeft),
            0x14 => Some(Self::RouteUpdate),
            0x20 => Some(Self::MtuProbe),
            0x21 => Some(Self::MtuProbeResponse),
            0x30 => Some(Self::RekeyRequest),
            0x31 => Some(Self::RekeyResponse),
            0xFF => Some(Self::Close),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
    Ack { sequence: u64 },
    Nack { sequence: u64, reason: String },
    PeerListRequest,
    PeerListResponse { peers: Vec<PeerInfo> },
    PeerJoined { peer: PeerInfo },
    PeerLeft { peer_id: [u8; SESSION_ID_SIZE] },
    RouteUpdate { routes: Vec<RouteEntry> },
    MtuProbe { probe_size: u16, sequence: u32 },
    MtuProbeResponse { probe_size: u16, sequence: u32, success: bool },
    RekeyRequest { new_ecdh_public: Vec<u8> },
    RekeyResponse { new_ecdh_public: Vec<u8> },
    Close { reason: String },
}

impl ControlMessage {
    pub fn message_type(&self) -> ControlMessageType {
        match self {
            Self::Ping { .. } => ControlMessageType::Ping,
            Self::Pong { .. } => ControlMessageType::Pong,
            Self::Ack { .. } => ControlMessageType::Ack,
            Self::Nack { .. } => ControlMessageType::Nack,
            Self::PeerListRequest => ControlMessageType::PeerListRequest,
            Self::PeerListResponse { .. } => ControlMessageType::PeerListResponse,
            Self::PeerJoined { .. } => ControlMessageType::PeerJoined,
            Self::PeerLeft { .. } => ControlMessageType::PeerLeft,
            Self::RouteUpdate { .. } => ControlMessageType::RouteUpdate,
            Self::MtuProbe { .. } => ControlMessageType::MtuProbe,
            Self::MtuProbeResponse { .. } => ControlMessageType::MtuProbeResponse,
            Self::RekeyRequest { .. } => ControlMessageType::RekeyRequest,
            Self::RekeyResponse { .. } => ControlMessageType::RekeyResponse,
            Self::Close { .. } => ControlMessageType::Close,
        }
    }

    pub fn encode(&self) -> Result<Bytes, CodecError> {
        let mut buf = BytesMut::new();
        Encode::encode(self, &mut buf)?;
        Ok(buf.freeze())
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        Decode::decode(buf)
    }
}

impl Encode for ControlMessage {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        match self {
            Self::Ping { timestamp } => {
                buf.put_u8(ControlMessageType::Ping as u8);
                buf.put_u64(*timestamp);
            }
            Self::Pong { timestamp } => {
                buf.put_u8(ControlMessageType::Pong as u8);
                buf.put_u64(*timestamp);
            }
            Self::Ack { sequence } => {
                buf.put_u8(ControlMessageType::Ack as u8);
                buf.put_u64(*sequence);
            }
            Self::Nack { sequence, reason } => {
                buf.put_u8(ControlMessageType::Nack as u8);
                buf.put_u64(*sequence);
                let reason_bytes = reason.as_bytes();
                buf.put_u16(reason_bytes.len() as u16);
                buf.put_slice(reason_bytes);
            }
            Self::PeerListRequest => {
                buf.put_u8(ControlMessageType::PeerListRequest as u8);
            }
            Self::PeerListResponse { peers } => {
                buf.put_u8(ControlMessageType::PeerListResponse as u8);
                buf.put_u16(peers.len() as u16);
                for peer in peers {
                    peer.encode(buf)?;
                }
            }
            Self::PeerJoined { peer } => {
                buf.put_u8(ControlMessageType::PeerJoined as u8);
                peer.encode(buf)?;
            }
            Self::PeerLeft { peer_id } => {
                buf.put_u8(ControlMessageType::PeerLeft as u8);
                buf.put_slice(peer_id);
            }
            Self::RouteUpdate { routes } => {
                buf.put_u8(ControlMessageType::RouteUpdate as u8);
                buf.put_u16(routes.len() as u16);
                for route in routes {
                    route.encode(buf)?;
                }
            }
            Self::MtuProbe { probe_size, sequence } => {
                buf.put_u8(ControlMessageType::MtuProbe as u8);
                buf.put_u16(*probe_size);
                buf.put_u32(*sequence);
            }
            Self::MtuProbeResponse { probe_size, sequence, success } => {
                buf.put_u8(ControlMessageType::MtuProbeResponse as u8);
                buf.put_u16(*probe_size);
                buf.put_u32(*sequence);
                buf.put_u8(if *success { 1 } else { 0 });
            }
            Self::RekeyRequest { new_ecdh_public } => {
                buf.put_u8(ControlMessageType::RekeyRequest as u8);
                buf.put_slice(new_ecdh_public);
            }
            Self::RekeyResponse { new_ecdh_public } => {
                buf.put_u8(ControlMessageType::RekeyResponse as u8);
                buf.put_slice(new_ecdh_public);
            }
            Self::Close { reason } => {
                buf.put_u8(ControlMessageType::Close as u8);
                let reason_bytes = reason.as_bytes();
                buf.put_u16(reason_bytes.len() as u16);
                buf.put_slice(reason_bytes);
            }
        }
        Ok(())
    }
}

impl Decode for ControlMessage {
    fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        if buf.is_empty() {
            return Err(CodecError::BufferTooSmall { need: 1, have: 0 });
        }

        let msg_type = ControlMessageType::from_byte(buf.get_u8())
            .ok_or(CodecError::InvalidControlType { msg_type: buf[0] })?;

        match msg_type {
            ControlMessageType::Ping => {
                if buf.remaining() < 8 {
                    return Err(CodecError::BufferTooSmall { need: 8, have: buf.remaining() });
                }
                Ok(Self::Ping { timestamp: buf.get_u64() })
            }
            ControlMessageType::Pong => {
                if buf.remaining() < 8 {
                    return Err(CodecError::BufferTooSmall { need: 8, have: buf.remaining() });
                }
                Ok(Self::Pong { timestamp: buf.get_u64() })
            }
            ControlMessageType::Ack => {
                if buf.remaining() < 8 {
                    return Err(CodecError::BufferTooSmall { need: 8, have: buf.remaining() });
                }
                Ok(Self::Ack { sequence: buf.get_u64() })
            }
            ControlMessageType::Nack => {
                if buf.remaining() < 10 {
                    return Err(CodecError::BufferTooSmall { need: 10, have: buf.remaining() });
                }
                let sequence = buf.get_u64();
                let reason_len = buf.get_u16() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::BufferTooSmall { need: reason_len, have: buf.remaining() });
                }
                let mut reason_bytes = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_bytes);
                let reason = String::from_utf8(reason_bytes)
                    .map_err(|_| CodecError::InvalidUtf8)?;
                Ok(Self::Nack { sequence, reason })
            }
            ControlMessageType::PeerListRequest => Ok(Self::PeerListRequest),
            ControlMessageType::PeerListResponse => {
                if buf.remaining() < 2 {
                    return Err(CodecError::BufferTooSmall { need: 2, have: buf.remaining() });
                }
                let count = buf.get_u16() as usize;
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    peers.push(PeerInfo::decode(buf)?);
                }
                Ok(Self::PeerListResponse { peers })
            }
            ControlMessageType::PeerJoined => {
                Ok(Self::PeerJoined { peer: PeerInfo::decode(buf)? })
            }
            ControlMessageType::PeerLeft => {
                if buf.remaining() < SESSION_ID_SIZE {
                    return Err(CodecError::BufferTooSmall { need: SESSION_ID_SIZE, have: buf.remaining() });
                }
                let mut peer_id = [0u8; SESSION_ID_SIZE];
                buf.copy_to_slice(&mut peer_id);
                Ok(Self::PeerLeft { peer_id })
            }
            ControlMessageType::RouteUpdate => {
                if buf.remaining() < 2 {
                    return Err(CodecError::BufferTooSmall { need: 2, have: buf.remaining() });
                }
                let count = buf.get_u16() as usize;
                let mut routes = Vec::with_capacity(count);
                for _ in 0..count {
                    routes.push(RouteEntry::decode(buf)?);
                }
                Ok(Self::RouteUpdate { routes })
            }
            ControlMessageType::MtuProbe => {
                if buf.remaining() < 6 {
                    return Err(CodecError::BufferTooSmall { need: 6, have: buf.remaining() });
                }
                Ok(Self::MtuProbe {
                    probe_size: buf.get_u16(),
                    sequence: buf.get_u32(),
                })
            }
            ControlMessageType::MtuProbeResponse => {
                if buf.remaining() < 7 {
                    return Err(CodecError::BufferTooSmall { need: 7, have: buf.remaining() });
                }
                Ok(Self::MtuProbeResponse {
                    probe_size: buf.get_u16(),
                    sequence: buf.get_u32(),
                    success: buf.get_u8() != 0,
                })
            }
            ControlMessageType::RekeyRequest => {
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED,
                        have: buf.remaining(),
                    });
                }
                let mut new_ecdh_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut new_ecdh_public);
                Ok(Self::RekeyRequest { new_ecdh_public })
            }
            ControlMessageType::RekeyResponse => {
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED,
                        have: buf.remaining(),
                    });
                }
                let mut new_ecdh_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut new_ecdh_public);
                Ok(Self::RekeyResponse { new_ecdh_public })
            }
            ControlMessageType::Close => {
                if buf.remaining() < 2 {
                    return Err(CodecError::BufferTooSmall { need: 2, have: buf.remaining() });
                }
                let reason_len = buf.get_u16() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::BufferTooSmall { need: reason_len, have: buf.remaining() });
                }
                let mut reason_bytes = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_bytes);
                let reason = String::from_utf8(reason_bytes)
                    .map_err(|_| CodecError::InvalidUtf8)?;
                Ok(Self::Close { reason })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub session_id: [u8; SESSION_ID_SIZE],
    pub static_public: Vec<u8>,
    pub virtual_ip: IpAddr,
    pub endpoint: Option<(IpAddr, u16)>,
    pub aead_algorithms: u8,
    pub last_seen: u64,
    pub state: PeerState,
    pub mtu: u16,
}

impl PeerInfo {
    pub fn new(
        session_id: [u8; SESSION_ID_SIZE],
        static_public: [u8; ECDH_PUBLIC_KEY_COMPRESSED],
        virtual_ip: IpAddr,
    ) -> Self {
        Self {
            session_id,
            static_public: static_public.to_vec(),
            virtual_ip,
            endpoint: None,
            aead_algorithms: 0x03,
            last_seen: 0,
            state: PeerState::Connected,
            mtu: DEFAULT_MTU,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        buf.put_slice(&self.session_id);
        buf.put_slice(&self.static_public);
        match self.virtual_ip {
            IpAddr::V4(ip) => {
                buf.put_u8(0x04);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(0x06);
                buf.put_slice(&ip.octets());
            }
        }
        if let Some((ip, port)) = self.endpoint {
            buf.put_u8(0x01);
            match ip {
                IpAddr::V4(ip) => {
                    buf.put_u8(0x04);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(0x06);
                    buf.put_slice(&ip.octets());
                }
            }
            buf.put_u16(port);
        } else {
            buf.put_u8(0x00);
        }
        buf.put_u8(self.aead_algorithms);
        buf.put_u64(self.last_seen);
        buf.put_u8(self.state as u8);
        buf.put_u16(self.mtu);
        Ok(())
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        if buf.remaining() < SESSION_ID_SIZE + ECDH_PUBLIC_KEY_COMPRESSED + 1 {
            return Err(CodecError::BufferTooSmall {
                need: SESSION_ID_SIZE + ECDH_PUBLIC_KEY_COMPRESSED + 1,
                have: buf.remaining(),
            });
        }

        let mut session_id = [0u8; SESSION_ID_SIZE];
        buf.copy_to_slice(&mut session_id);

        let mut static_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
        buf.copy_to_slice(&mut static_public);

        let ip_version = buf.get_u8();
        let virtual_ip = match ip_version {
            0x04 => {
                if buf.remaining() < 4 {
                    return Err(CodecError::BufferTooSmall { need: 4, have: buf.remaining() });
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            0x06 => {
                if buf.remaining() < 16 {
                    return Err(CodecError::BufferTooSmall { need: 16, have: buf.remaining() });
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(CodecError::InvalidIpVersion { version: ip_version }),
        };

        let has_endpoint = buf.get_u8();
        let endpoint = if has_endpoint != 0 {
            let ep_ip_version = buf.get_u8();
            let ep_ip = match ep_ip_version {
                0x04 => {
                    if buf.remaining() < 4 {
                        return Err(CodecError::BufferTooSmall { need: 4, have: buf.remaining() });
                    }
                    let mut octets = [0u8; 4];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                0x06 => {
                    if buf.remaining() < 16 {
                        return Err(CodecError::BufferTooSmall { need: 16, have: buf.remaining() });
                    }
                    let mut octets = [0u8; 16];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(CodecError::InvalidIpVersion { version: ep_ip_version }),
            };
            let port = buf.get_u16();
            Some((ep_ip, port))
        } else {
            None
        };

        let aead_algorithms = buf.get_u8();
        let last_seen = buf.get_u64();
        let state = PeerState::from_byte(buf.get_u8())
            .ok_or(CodecError::InvalidPeerState)?;
        let mtu = buf.get_u16();

        Ok(Self {
            session_id,
            static_public,
            virtual_ip,
            endpoint,
            aead_algorithms,
            last_seen,
            state,
            mtu,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PeerState {
    Handshaking = 0x01,
    Connected = 0x02,
    Disconnected = 0x03,
    Reconnecting = 0x04,
    Blocked = 0xFF,
}

impl PeerState {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Handshaking),
            0x02 => Some(Self::Connected),
            0x03 => Some(Self::Disconnected),
            0x04 => Some(Self::Reconnecting),
            0xFF => Some(Self::Blocked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub next_hop: [u8; SESSION_ID_SIZE],
    pub metric: u16,
    pub flags: RouteFlags,
}

impl RouteEntry {
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        match self.destination {
            IpAddr::V4(ip) => {
                buf.put_u8(0x04);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(0x06);
                buf.put_slice(&ip.octets());
            }
        }
        buf.put_u8(self.prefix_len);
        buf.put_slice(&self.next_hop);
        buf.put_u16(self.metric);
        buf.put_u8(self.flags.bits());
        Ok(())
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        if buf.remaining() < 1 {
            return Err(CodecError::BufferTooSmall { need: 1, have: buf.remaining() });
        }

        let ip_version = buf.get_u8();
        let destination = match ip_version {
            0x04 => {
                if buf.remaining() < 4 {
                    return Err(CodecError::BufferTooSmall { need: 4, have: buf.remaining() });
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            0x06 => {
                if buf.remaining() < 16 {
                    return Err(CodecError::BufferTooSmall { need: 16, have: buf.remaining() });
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(CodecError::InvalidIpVersion { version: ip_version }),
        };

        if buf.remaining() < 1 + SESSION_ID_SIZE + 2 + 1 {
            return Err(CodecError::BufferTooSmall {
                need: 1 + SESSION_ID_SIZE + 2 + 1,
                have: buf.remaining(),
            });
        }

        let prefix_len = buf.get_u8();
        let mut next_hop = [0u8; SESSION_ID_SIZE];
        buf.copy_to_slice(&mut next_hop);
        let metric = buf.get_u16();
        let flags = RouteFlags::from_bits(buf.get_u8());

        Ok(Self {
            destination,
            prefix_len,
            next_hop,
            metric,
            flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteFlags(u8);

impl RouteFlags {
    pub const NONE: Self = Self(0x00);
    pub const DIRECT: Self = Self(0x01);
    pub const LEARNED: Self = Self(0x02);
    pub const STATIC: Self = Self(0x04);
    pub const DEFAULT: Self = Self(0x08);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMessage {
    pub packet: Bytes,
    pub original_len: usize,
}

impl DataMessage {
    pub fn new(packet: Bytes) -> Self {
        let original_len = packet.len();
        Self { packet, original_len }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.packet
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Handshake(crate::handshake::HandshakeMessage),
    Control(ControlMessage),
    Data(DataMessage),
}

impl Message {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Handshake(h) => h.frame_type(),
            Self::Control(_) => FrameType::Control,
            Self::Data(_) => FrameType::Data,
        }
    }

    pub fn message_type(&self) -> u8 {
        match self {
            Self::Handshake(h) => h.frame_type() as u8,
            Self::Control(c) => c.message_type() as u8,
            Self::Data(_) => FrameType::Data as u8,
        }
    }
}