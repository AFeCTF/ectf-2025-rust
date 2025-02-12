use alloc::vec::Vec;
use bincode::{Decode, Encode};
use sha2::{Digest, Sha256};

use crate::{frame::EncodedFramePacketHeader, key::Key, masks::{characterize_range, MASKS}};

/// Channel information that is sent in response to a list subscription command.
#[derive(Debug, Encode, Decode)]
pub struct ChannelInfo {
    pub channel: u32,
    pub start: u64,
    pub end: u64
}

/// Subscription data as it is sent, recieved, and stored
#[derive(Debug)]
pub struct SubscriptionData {
    pub header: SubscriptionDataHeader,
    /// Encoded subscription keys. In transport the key data is encrypted using the device key.
    pub keys: Vec<EncodedSubscriptionKey>
}

/// Subscription channel, time range, and a mac_hash for data authentication.
#[derive(Debug, Encode, Decode)]
pub struct SubscriptionDataHeader {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32,
    /// SHA256 of the entire contents of the subscription data packet. Calculated like this:
    /// `SHA256(start_timestamp, end_timestamp, channel, {mask_idx, UNENCRYPTED_KEY} for each key)`
    pub mac_hash: [u8; 32]
}

#[derive(Debug, Encode, Decode)]
/// An encoded subscription key valid for a bitrange. The start_timestamp isn't encoded with the
/// key because they are all adjacent.
pub struct EncodedSubscriptionKey {
    pub mask_idx: u8,
    pub key: Key
}

impl SubscriptionData {
    /// Checks if we can use this subscription to decode a frame.
    pub fn contains_frame(&self, frame: &EncodedFramePacketHeader) -> bool {
        self.header.channel == frame.channel && self.header.start_timestamp <= frame.timestamp && self.header.end_timestamp >= frame.timestamp
    }

    /// Finds a key we can use to decode a frame.
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

    /// Decrypt the subscription keys using the device_key and validate that the mac_hash matches
    /// the hash of our decrypted data.
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

    /// Generate a subscription key.
    pub fn generate(secrets: &[u8], start: u64, end: u64, channel: u32, device_id: u32) -> SubscriptionData {
        let device_key = Key::for_device(device_id, secrets);

        let mut hasher: Sha256 = Digest::new();
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        hasher.update(channel.to_le_bytes());

        let mut device_key_cipher = device_key.cipher();

        let keys = characterize_range(start, end).into_iter().map(|(t, mask_idx)| {
            let mut key = Key::for_bitrange(t, mask_idx, channel, secrets);

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

