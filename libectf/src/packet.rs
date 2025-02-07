use core::{fmt::Debug, str};

use alloc::vec::Vec;
use bincode::{config::{Configuration, Fixint, LittleEndian, NoLimit}, Decode, Encode};
use sha2::{Digest, Sha256};

use crate::crypto::{Key, MASKS};

pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = bincode::config::legacy();

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


pub struct DecodedFrame {
    pub header: EncodedFramePacketHeader,
    pub frame: Frame
}

pub trait EncodeToVec: Encode {
    fn encode_to_vec(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }
}

impl<T: Encode> EncodeToVec for T {}

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

    pub fn decrypt_and_authenticate(&mut self, device_key: &Key) -> bool {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(self.header.start_timestamp.to_le_bytes());
        hasher.update(self.header.end_timestamp.to_le_bytes());
        hasher.update(self.header.channel.to_le_bytes());

        let mut cipher = device_key.cipher();

        for k in &mut self.keys {
            cipher.decrypt(&mut k.key.0);
            hasher.update(k.mask_idx.to_le_bytes());
            hasher.update(k.key.0);
        }

        <[u8; 32]>::from(hasher.finalize()) == self.header.mac_hash
    }
}
