use core::{fmt::Debug, str};

use alloc::{string::String, vec::Vec};
use bincode::{Decode, Encode};

use crate::crypto::{Key, MAX_POSSIBLE_MASK};

pub const FRAME_SIZE: usize = 64;
pub const NUM_ENCODED_FRAMES: usize = (MAX_POSSIBLE_MASK + 1) as usize;

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
pub struct EncodedFramePacket {
    pub channel: u32,
    pub timestamp: u64,
    pub data: [Frame; NUM_ENCODED_FRAMES]
}

#[derive(Encode, Decode)]
pub struct SubscriptionUpdatePacket {
    pub decoder_id: u32,
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32
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
    pub keys: Vec<SubscriptionKey>
}

#[derive(Debug, Encode, Decode)]
pub struct SubscriptionDataHeader {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32
}

#[derive(Debug, Encode, Decode)]
pub struct SubscriptionKey {
    pub start_timestamp: u64,
    pub mask_width: u8,
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

