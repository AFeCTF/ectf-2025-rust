use alloc::{string::String, vec::Vec};
use bincode::{Decode, Encode};

pub const FRAME_SIZE: usize = 64;

pub type Frame = [u8; FRAME_SIZE];

#[derive(Debug, Encode, Decode)]
pub struct EncodedFramePacket {
    pub channel: u32,
    pub timestamp: u64,
    pub data: [Frame; 64]
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

#[derive(Debug, Encode, Decode)]
pub struct SubscriptionData {

}

#[derive(Debug, Encode, Decode)]
pub struct SubscriptionKey {
    pub start_timestamp: u64,
    pub mask_width: u8,
    pub key: [u8; 32]
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

