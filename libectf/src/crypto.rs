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

pub fn into_aes_key(key: &Key) -> GenericArray<u8, <Aes128 as KeySizeUser>::KeySize> {
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&key.0);
    data.into()
}

#[inline]
pub fn init_cipher(key: &Key) -> Aes128 {
    Aes128::new(&into_aes_key(&key))
}

// TODO research security of this
pub fn aes_encrypt<const N: usize>(data: &mut [u8; N], key: &Key) {
    let mut cipher = init_cipher(key);

    for chunk in data.chunks_exact_mut(16) {
        cipher.encrypt_block_mut(chunk.into());
    }
}

pub fn aes_decrypt_with_cipher<const N: usize>(cipher: &mut Aes128, data: &mut [u8; N]) {
    for chunk in data.chunks_exact_mut(16) {
        cipher.decrypt_block_mut(chunk.into());
    }
}

pub fn aes_decrypt<const N: usize>(data: &mut [u8; N], key: &Key) {
    let mut cipher = init_cipher(key);

    for chunk in data.chunks_exact_mut(16) {
        cipher.decrypt_block_mut(chunk.into());
    }
}

fn gen_device_key(device_id: u32, secrets: &[u8]) -> Key {
    let mut hasher: Sha256 = Digest::new();
    hasher.update(secrets);
    hasher.update(device_id.to_le_bytes());
    let _hash: [u8; 32] = hasher.finalize().into();
    // Key(hash[..8].try_into().unwrap())
    Key([0; 8])
}

fn gen_key(start_timestamp: u64, mask_idx: u8, channel: u32, secrets: &[u8]) -> Key {
    let mut hasher: Sha256 = Digest::new();
    hasher.update(secrets);
    hasher.update(start_timestamp.to_le_bytes());
    hasher.update(mask_idx.to_le_bytes());
    hasher.update(channel.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    Key(hash[..8].try_into().unwrap())
}

pub fn encode(frame: &Frame, timestamp: u64, channel: u32, secrets: &[u8]) -> EncodedFramePacket {
    let mut hasher: Sha256 = Digest::new();
    hasher.update(&frame.0);

    // Stupidity because I don't want frame to implement copy
    let mut data: [MaybeUninit<Frame>; NUM_ENCODED_FRAMES] = unsafe { MaybeUninit::uninit().assume_init() };
    for elem in &mut data {
        *elem = MaybeUninit::new(frame.clone());
    }
    let mut data: [Frame; NUM_ENCODED_FRAMES] = unsafe { core::mem::transmute(data) };

    for (mask_idx, mask) in MASKS.iter().enumerate() {
        let key = gen_key(timestamp & !((1 << mask) - 1), mask_idx as u8, channel, secrets);
        aes_encrypt(&mut data[mask_idx].0, &key);
    }

    EncodedFramePacket {
        header: EncodedFramePacketHeader {
            channel,
            timestamp,
            mac_hash: <[u8;32]>::from(hasher.finalize())[..16].try_into().unwrap()
        },
        data,
    }
}

pub fn decode_frame_in_place_with_key(frame: &mut Frame, key: &Key) {
    aes_decrypt(&mut frame.0, &key);
}

pub fn decode_with_key(frame: &EncodedFramePacket, key: &EncodedSubscriptionKey) -> Frame {
    let mut data = frame.data[key.mask_idx as usize].clone();
    decode_frame_in_place_with_key(&mut data, &key.key);
    data
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

pub fn gen_subscription(secrets: &[u8], start: u64, end: u64, channel: u32, device_id: u32) -> SubscriptionData {
    // TODO encrypt with device id somehow
    let device_key = gen_device_key(device_id, secrets);

    let mut hasher: Sha256 = Digest::new();
    hasher.update(start.to_le_bytes());
    hasher.update(end.to_le_bytes());
    hasher.update(channel.to_le_bytes());

    let keys = characterize_range(start, end).into_iter().map(|(t, mask_idx)| {
        let mut key = gen_key(t, mask_idx, channel, secrets);

        hasher.update(mask_idx.to_le_bytes());
        hasher.update(key.0);

        aes_encrypt(&mut key.0, &device_key);

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

pub fn decode_with_subscription(frame: &EncodedFramePacket, subscription: &SubscriptionData) -> Option<Frame> {
    subscription.key_for_frame(&frame.header).map(|k| decode_with_key(frame, k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_characterize() {
        let r = characterize_range(1, u64::MAX - 1);

        for (t, mask_idx) in r {
            println!("{:064b} mask width {}", t, MASKS[mask_idx as usize]);
        }
    }

    #[test]
    fn test_range_build() {
        let secrets = b"super secret secrets";

        let start = 1234;
        let end = 5678;
        let channel = 1;
        let device_id = 1;

        let s = gen_subscription(secrets, start, end, channel, device_id);

        let test_frame: Frame = Frame(*b"This is a test frame. It's size is 64 bytes. SUPER SECRET!!!!!!!");

        let valid = encode(&test_frame, (start + end) / 2, channel, secrets);
        let decoded = decode_with_subscription(&valid, &s);
        assert!(matches!(decoded, Some(f) if f == test_frame));

        let valid = encode(&test_frame, start, channel, secrets);
        let decoded = decode_with_subscription(&valid, &s);
        assert!(matches!(decoded, Some(f) if f == test_frame));

        let valid = encode(&test_frame, end, channel, secrets);
        let decoded = decode_with_subscription(&valid, &s);
        assert!(matches!(decoded, Some(f) if f == test_frame));

        let invalid = encode(&test_frame, start - 1, channel, secrets);
        let decoded = decode_with_subscription(&invalid, &s);
        assert!(matches!(decoded, None));

        let invalid = encode(&test_frame, end + 1, channel, secrets);
        let decoded = decode_with_subscription(&invalid, &s);
        assert!(matches!(decoded, None));

        let invalid = encode(&test_frame, start, channel + 1, secrets);
        let decoded = decode_with_subscription(&invalid, &s);
        assert!(matches!(decoded, None));
    }
}
