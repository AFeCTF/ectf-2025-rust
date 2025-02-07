use alloc::{string::String, vec::Vec};
use bincode::{enc::write::Writer, Decode, Encode};
use libectf::{frame::Frame, subscription::{ChannelInfo, SubscriptionData}, BINCODE_CONFIG};

pub const MAGIC: u8 = b'%';

#[derive(Encode, Decode, PartialEq, Eq)]
pub struct Opcode(u8);

impl Opcode {
    pub(super) const DECODE: Opcode = Opcode(b'D');
    pub(super) const SUBSCRIBE: Opcode = Opcode(b'S');
    pub(super) const LIST: Opcode = Opcode(b'L');
    pub(super) const ACK: Opcode = Opcode(b'A');
    pub(super) const ERROR: Opcode = Opcode(b'E');
    pub(super) const DEBUG: Opcode = Opcode(b'G');

    pub(super) fn should_ack(&self) -> bool {
        !matches!(self.0, b'G' | b'A')
    }
}

#[derive(Encode)]
pub struct MessageHeader {
    pub magic: u8,  // b'%'
    pub opcode: Opcode,
    pub length: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Packet {
    ListCommand,
    ListResponse(Vec<ChannelInfo>),
    SubscriptionCommand(SubscriptionData),
    SubscriptionResponse,
    DecodeResponse(Frame),
    Ack,
    Debug(String),
    Error(String)
}

struct SizeFinder(u16);

impl Writer for SizeFinder {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        // TODO error on overflow (both in casting and addassign)
        self.0 += bytes.len() as u16;
        Ok(())
    }
}

impl Packet {
    pub(super) fn encoded_size(&self) -> u16 {
        match self {
            Packet::ListCommand | Packet::SubscriptionResponse | Packet::Ack => { 0 }
            Packet::ListResponse(vec) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(0u32, &mut size_finder, BINCODE_CONFIG).unwrap();
                for entry in vec {
                    bincode::encode_into_writer(entry, &mut size_finder, BINCODE_CONFIG).unwrap();
                }
                size_finder.0
            }
            Packet::SubscriptionCommand(subscription_data) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(&subscription_data.header, &mut size_finder, BINCODE_CONFIG).unwrap();
                for entry in &subscription_data.keys {
                    bincode::encode_into_writer(entry, &mut size_finder, BINCODE_CONFIG).unwrap();
                }
                size_finder.0
            }
            Packet::DecodeResponse(frame) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(frame, &mut size_finder, BINCODE_CONFIG).unwrap();
                size_finder.0
            }
            Packet::Debug(s) => { s.len() as u16 }
            Packet::Error(s) => { s.len() as u16 }
        }
    }

    pub(super) fn opcode(&self) -> Opcode {
        match self {
            Packet::ListCommand | Packet::ListResponse(_) => { Opcode::LIST }
            Packet::SubscriptionCommand(_) | Packet::SubscriptionResponse => { Opcode::SUBSCRIBE }
            Packet::DecodeResponse(_) => { Opcode::DECODE }
            Packet::Ack => { Opcode::ACK }
            Packet::Debug(_) => { Opcode::DEBUG }
            Packet::Error(_) => { Opcode::ERROR }
        }
    }
}

