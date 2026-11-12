//! vnet-proto — Protocol frames, handshake, and message types
//!
//! Implements the VNET wire protocol as specified in SPEC.md.

#![warn(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod frame;
pub mod handshake;
pub mod message;
pub mod codec;
pub mod constants;

pub use frame::{Frame, FrameHeader, FrameType, FrameFlags};
pub use handshake::{HandshakeState, HandshakeMessage, HandshakeError};
pub use message::{Message, ControlMessageType, ControlMessage, DataMessage};
pub use codec::{FrameCodec, CodecError};
pub use constants::*;