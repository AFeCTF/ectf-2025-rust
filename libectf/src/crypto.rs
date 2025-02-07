use alloc::vec::Vec;

use aes::Aes128;
use bincode::{Decode, Encode};
use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyInit, KeySizeUser};
use sha2::{Digest, Sha256};
use core::{convert::Into, fmt::Debug, mem::MaybeUninit};

use crate::packet::{EncodedFramePacket, EncodedFramePacketHeader, EncodedSubscriptionKey, Frame, SubscriptionData, SubscriptionDataHeader, NUM_ENCODED_FRAMES};

pub const MASKS: &[u8] = &[0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 45, 50, 55, 60];

#[derive(Encode, Decode)]
pub struct Key(pub [u8; 8]);

impl Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key(b\"")?;

        for c in self.0 {
            write!(f, "{:02x}", c)?;
        }

        write!(f, "\")")
    }
}

pub struct Cipher(Aes128);

impl Key {
    pub fn cipher(&self) -> Cipher {
        Cipher(Aes128::new(&self.to_aes_key()))
    }

    fn to_aes_key(&self) -> GenericArray<u8, <Aes128 as KeySizeUser>::KeySize> {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&self.0);
        data.into()
    }

    fn for_device(device_id: u32, secrets: &[u8]) -> Key {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(secrets);
        hasher.update(device_id.to_le_bytes());
        let _hash: [u8; 32] = hasher.finalize().into();
        // Key(hash[..8].try_into().unwrap())
        Key([0; 8])
    }

    fn for_frame(start_timestamp: u64, mask_idx: u8, channel: u32, secrets: &[u8]) -> Key {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(secrets);
        hasher.update(start_timestamp.to_le_bytes());
        hasher.update(mask_idx.to_le_bytes());
        hasher.update(channel.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        Key(hash[..8].try_into().unwrap())
    }
}

impl Cipher {
    pub fn encrypt<const N: usize>(&mut self, data: &mut [u8; N]) {
        for chunk in data.chunks_exact_mut(16) {
            self.0.encrypt_block_mut(chunk.into());
        }
    }

    pub fn decrypt<const N: usize>(&mut self, data: &mut [u8; N]) {
        for chunk in data.chunks_exact_mut(16) {
            self.0.decrypt_block_mut(chunk.into());
        }
    }

    pub fn encode_frame(&mut self, frame: &mut Frame) {
        self.encrypt(&mut frame.0);
    }

    pub fn decode_frame(&mut self, frame: &mut Frame) {
        self.decrypt(&mut frame.0);
    }
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

impl EncodedSubscriptionKey {
    pub fn decode_frame_packet(&self, frame: &EncodedFramePacket) -> Frame {
        let mut data = frame.data[self.mask_idx as usize].clone();
        self.key.cipher().decode_frame(&mut data);
        data
    }
}

fn characterize_range(mut a: u64, b: u64) -> Vec<(u64, u8)> {
    let mut res = Vec::new();

    let mut mask_idx = 0;

    while a <= b {
        if mask_idx < MASKS.len() - 1 {
            let next_block_span = (1 << MASKS[mask_idx + 1]) - 1;
            if a & next_block_span == 0 && a | next_block_span <= b {
                mask_idx += 1;
                continue;
            } 
        }
        let block_span = (1 << MASKS[mask_idx]) - 1;
        res.push((a, mask_idx as u8));
        a = (a | block_span) + 1;
        if a == 0 {  // Overflow
            return res;
        }
        mask_idx = 0;
    }

    res
}

impl SubscriptionData {
    pub fn generate(secrets: &[u8], start: u64, end: u64, channel: u32, device_id: u32) -> SubscriptionData {
        let device_key = Key::for_device(device_id, secrets);

        let mut hasher: Sha256 = Digest::new();
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        hasher.update(channel.to_le_bytes());

        let mut device_key_cipher = device_key.cipher();

        let keys = characterize_range(start, end).into_iter().map(|(t, mask_idx)| {
            let mut key = Key::for_frame(t, mask_idx, channel, secrets);

            hasher.update(mask_idx.to_le_bytes());
            hasher.update(key.0);

            device_key_cipher.encrypt(&mut key.0);

            EncodedSubscriptionKey {
                mask_idx,
                key 
            }
        }).collect();

        let header = SubscriptionDataHeader {
            channel,
            start_timestamp: start,
            end_timestamp: end,
            mac_hash: hasher.finalize().into()
        };

        SubscriptionData { header, keys }
    }
}

