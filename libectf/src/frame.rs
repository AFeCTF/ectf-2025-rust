use core::{fmt::Debug, mem::MaybeUninit, str};

use bincode::{Decode, Encode};
use sha2::{Digest, Sha256};

use crate::{key::Key, masks::MASKS};

pub const FRAME_SIZE: usize = 64;
pub const NUM_ENCODED_FRAMES: usize = MASKS.len();

#[derive(Encode, Decode, Clone, PartialEq, Eq)]
pub struct Frame(pub [u8; FRAME_SIZE]);

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

impl Frame {
    pub fn encode(&self, timestamp: u64, channel: u32, secrets: &[u8]) -> EncodedFramePacket {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(&self.0);

        // Stupidity because I don't want frame to implement copy
        let mut data: [MaybeUninit<Frame>; NUM_ENCODED_FRAMES] = unsafe { MaybeUninit::uninit().assume_init() };
        for elem in &mut data {
            *elem = MaybeUninit::new(self.clone());
        }
        let mut data: [Frame; NUM_ENCODED_FRAMES] = unsafe { core::mem::transmute(data) };

        for (mask_idx, mask) in MASKS.iter().enumerate() {
            let key = Key::for_frame(timestamp & !((1 << mask) - 1), mask_idx as u8, channel, secrets);
            key.cipher().encode_frame(&mut data[mask_idx]);
        }

        EncodedFramePacket {
            header: EncodedFramePacketHeader {
                channel,
                timestamp,
                mac_hash: <[u8; 32]>::from(hasher.finalize())[..16].try_into().unwrap()
            },
            data,
        }
    }
}

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

