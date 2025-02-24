use core::{fmt::Debug, mem::MaybeUninit};

use rkyv::{Archive, Deserialize, Serialize};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey, signature::SignerMut};

use alloc::boxed::Box;
use sha2::Sha256;

use crate::{key::Key, masks::MASKS};

/// Size of each frame in bytes.
pub const FRAME_SIZE: usize = 64;

/// The number of encrypted frames in an encoded frame packet.
pub const NUM_ENCRYPTED_FRAMES: usize = MASKS.len();

#[derive(Archive, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Frame(pub [u8; FRAME_SIZE]);

#[derive(Debug, Archive, Serialize, Deserialize)]
pub struct EncodedFramePacketHeader {
    pub timestamp: u64,
    pub channel: u32,
    pub signature: [u8; 64]
}

/// Encoded frame packet that is sent to the decoder.
#[derive(Debug, Archive, Serialize, Deserialize)]
pub struct EncodedFramePacket {
    pub header: EncodedFramePacketHeader,
    pub data: [Frame; NUM_ENCRYPTED_FRAMES],
}

impl Frame {
    pub fn encode(&self, timestamp: u64, channel: u32, secrets: &[u8]) -> EncodedFramePacket {
        let mut signing_key = SigningKey::<Sha256>::from_pkcs1_der(secrets).unwrap();
        let signature: Box<[u8]> = signing_key.sign(&self.0).try_into().unwrap();

        // I wish there was an easier way to do this without making Frame implement copy, but all
        // this code does is copy our frame into an array with size NUM_ENCRYPTED_FRAMES.
        let mut data: [MaybeUninit<Frame>; NUM_ENCRYPTED_FRAMES] = unsafe { MaybeUninit::uninit().assume_init() };
        for elem in &mut data {
            *elem = MaybeUninit::new(self.clone());
        }
        let mut data: [Frame; NUM_ENCRYPTED_FRAMES] = unsafe { core::mem::transmute(data) };

        // Loop through every possible mask and encrypt the frame with the key for the bitrange
        // that contains this frame.
        for (mask_idx, mask) in MASKS.iter().enumerate() {
            let key = Key::for_bitrange(timestamp & !((1 << mask) - 1), mask_idx as u8, channel, secrets);
            key.cipher().encrypt_frame(&mut data[mask_idx]);
        }

        EncodedFramePacket {
            header: EncodedFramePacketHeader {
                channel,
                timestamp,
                signature: signature.to_vec().try_into().unwrap()
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

