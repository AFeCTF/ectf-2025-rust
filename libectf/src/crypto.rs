use alloc::vec::Vec;

use aes::Aes256;
use bincode::{Decode, Encode};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use sha2::{Sha256, Digest};
use core::{convert::Into, fmt::Debug, mem::MaybeUninit};

use crate::packet::{EncodedFramePacket, Frame, SubscriptionData, SubscriptionDataHeader, SubscriptionKey, NUM_ENCODED_FRAMES};

pub const MAX_POSSIBLE_MASK: u8 = 60;

#[derive(Encode, Decode)]
pub struct Key(pub [u8; 32]);

impl Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key(b\"")?;

        for c in self.0 {
            write!(f, "{:02x}", c)?;
        }

        write!(f, "\")")
    }
}


// TODO research security of this
pub fn aes_encrypt_in_place(data: &mut [u8; 64], key: &Key) {
    let mut cipher = Aes256::new(key.0.as_ref().into());

    for chunk in data.chunks_exact_mut(16) {
        cipher.encrypt_block_mut(chunk.into());
    }
}

pub fn aes_decrypt_in_place(data: &mut [u8; 64], key: &Key) {
    let mut cipher = Aes256::new(key.0.as_ref().into());

    for chunk in data.chunks_exact_mut(16) {
        cipher.decrypt_block_mut(chunk.into());
    }
}

fn gen_key(start_timestamp: u64, mask_width: u8, channel: u32, secrets: &[u8]) -> Key {
    let mut hasher: Sha256 = Digest::new();
    hasher.update(secrets);
    hasher.update(start_timestamp.to_le_bytes());
    hasher.update(mask_width.to_le_bytes());
    hasher.update(channel.to_le_bytes());
    Key(hasher.finalize().into())
}

pub fn encode(frame: &Frame, timestamp: u64, channel: u32, secrets: &[u8]) -> EncodedFramePacket {
    // Stupidity because I don't want frame to implement copy
    let mut data: [MaybeUninit<Frame>; NUM_ENCODED_FRAMES] = unsafe { MaybeUninit::uninit().assume_init() };
    for elem in &mut data {
        *elem = MaybeUninit::new(frame.clone());
    }
    let mut data: [Frame; NUM_ENCODED_FRAMES] = unsafe { core::mem::transmute(data) };

    let mut t = timestamp;

    for mask_width in 0..MAX_POSSIBLE_MASK+1 {
        let key = gen_key(t << mask_width, mask_width, channel,  secrets);
        aes_encrypt_in_place(&mut data[mask_width as usize].0, &key);
        t >>= 1;
    }

    EncodedFramePacket {
        channel,
        timestamp,
        data
    }
}

pub fn decode_with_key(frame: &EncodedFramePacket, key: &SubscriptionKey) -> Frame {
    let mut data = frame.data[key.mask_width as usize].clone();
    aes_decrypt_in_place(&mut data.0, &key.key);
    data
}

fn characterize_range(mut a: u64, b: u64) -> Vec<(u64, u8)> {
    let mut res = Vec::new();

    let mut block_level = 0;

    while a <= b {
        let next_block_span = (1 << block_level + 1) - 1;
        if block_level < MAX_POSSIBLE_MASK && a & next_block_span == 0 && a | next_block_span <= b {
            block_level += 1;
        } else {
            let block_span = (1 << block_level) - 1;
            res.push((a, block_level));
            a = (a | block_span) + 1;
            block_level = 0;
        }
    }

    res
}

pub fn gen_subscription(secrets: &[u8], start: u64, end: u64, channel: u32, _device_id: u32) -> SubscriptionData {
    // TODO encrypt with device id somehow

    let header = SubscriptionDataHeader {
        channel,
        start_timestamp: start,
        end_timestamp: end
    };

    let keys = characterize_range(start, end).into_iter().map(|(t, mask)| SubscriptionKey {
        start_timestamp: t,
        mask_width: mask,
        key: gen_key(t, mask, channel, secrets)
    }).collect();

    SubscriptionData { header, keys }
}

pub fn decode_with_subscription(frame: &EncodedFramePacket, subscription: &SubscriptionData) -> Option<Frame> {
    if frame.channel != subscription.header.channel || frame.timestamp < subscription.header.start_timestamp || frame.timestamp > subscription.header.end_timestamp {
        return None;
    }

    for key in &subscription.keys {
        if (key.start_timestamp ^ frame.timestamp) >> key.mask_width == 0 {
            return Some(decode_with_key(frame, key));
        }
    }

    // Shouldn't happen
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
