use core::{fmt::Debug, str};

use alloc::{string::String, vec::Vec};
use bincode::{Decode, Encode};

use crate::crypto::{Key, MASKS};

pub const FRAME_SIZE: usize = 64;
pub const NUM_ENCODED_FRAMES: usize = MASKS.len();

#[derive(Encode, Decode, Clone, PartialEq, Eq)]
pub struct Frame(pub [u8; FRAME_SIZE]);

impl Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match str::from_utf8(&self.0) {
            Ok(s) => {
                write!(f, "Frame(b\"{}\")", s)
            },
            Err(_) => {
                write!(f, "Frame(ENCRYPTED)")
            },
        }
    }
}

#[derive(Debug, Encode, Decode)]
pub struct EncodedFramePacketHeader {
    pub channel: u32,
    pub timestamp: u64,
    pub mac_hash: [u8; 16]
}

#[derive(Debug, Encode, Decode)]
pub struct EncodedFramePacket {
    pub header: EncodedFramePacketHeader,
    pub data: [Frame; NUM_ENCODED_FRAMES],
}

#[derive(Debug, Encode, Decode)]
pub struct ChannelInfo {
    pub channel: u32,
    pub start: u64,
    pub end: u64
}

#[derive(Debug)]
pub struct SubscriptionData {
    pub header: SubscriptionDataHeader,
    pub keys: Vec<EncodedSubscriptionKey>
}

#[derive(Debug, Encode, Decode)]
pub struct SubscriptionDataHeader {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32,
    pub mac_hash: [u8; 32]
}

#[derive(Debug, Encode, Decode)]
pub struct EncodedSubscriptionKey {
    pub mask_idx: u8,
    pub key: Key
}

#[derive(Debug)]
pub enum Packet {
    ListCommand,
    ListResponse(Vec<ChannelInfo>),
    SubscriptionCommand(SubscriptionData),
    SubscriptionResponse,
    DecodeCommand(EncodedFramePacket),
    DecodeResponse(Frame),
    Ack,
    Debug(String),
    Error(String)
}

pub struct DecodedFrame {
    pub header: EncodedFramePacketHeader,
    pub frame: Frame
}


impl SubscriptionData {
    pub fn contains_frame(&self, frame: &EncodedFramePacketHeader) -> bool {
        self.header.channel == frame.channel && self.header.start_timestamp <= frame.timestamp && self.header.end_timestamp >= frame.timestamp
    }

    pub fn key_for_frame(&self, header: &EncodedFramePacketHeader) -> Option<&EncodedSubscriptionKey> {
        if !self.contains_frame(header) {
            return None;
        }

        let mut start_timestamp = self.header.start_timestamp;
        for key in &self.keys {
            let mask = MASKS[key.mask_idx as usize];
            if (start_timestamp ^ header.timestamp) >> mask == 0 {
                return Some(key);
            }
            start_timestamp += 1 << mask;
        }

        None
    }
}
