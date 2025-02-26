use alloc::vec::Vec;
use rkyv::{Archive, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{frame::ArchivedEncodedFramePacketHeader, key::Key, masks::{characterize_range, MASKS}};

/// Channel information that is sent in response to a list subscription command.
#[derive(Debug, Archive, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub channel: u32,
    pub start: u64,
    pub end: u64
}

/// Subscription data as it is sent, recieved, and stored
#[derive(Debug, Archive, Serialize, Deserialize)]
pub struct SubscriptionData {
    pub header: SubscriptionDataHeader,
    /// Encoded subscription keys. In transport the key data is encrypted using the device key.
    pub keys: Vec<EncodedSubscriptionKey>
}

/// Subscription channel, time range, and a mac_hash for data authentication.
#[derive(Debug, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
pub struct SubscriptionDataHeader {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32,
    /// SHA256 of the entire contents of the subscription data packet. Calculated like this:
    /// `SHA256(start_timestamp, end_timestamp, channel, UNENCRYPTED_KEY for each key)`
    pub mac_hash: [u8; 32]
}

/// An encoded subscription key valid for a bitrange. The start_timestamp isn't encoded with the
/// key because they are all adjacent.
#[derive(Debug, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
pub struct EncodedSubscriptionKey {
    pub key: Key
}

impl ArchivedSubscriptionDataHeader {
    /// Checks if we can use this subscription to decode a frame.
    pub fn contains_frame(&self, frame: &ArchivedEncodedFramePacketHeader) -> bool {
        self.channel == frame.channel && self.start_timestamp <= frame.timestamp && self.end_timestamp >= frame.timestamp
    }

    /// Finds a key we can use to decode a frame.
    pub fn key_for_frame<'k>(&self, header: &ArchivedEncodedFramePacketHeader, keys: &'k [ArchivedEncodedSubscriptionKey]) -> Option<(&'k ArchivedEncodedSubscriptionKey, u8)> {
        if !self.contains_frame(header) {
            return None;
        }

        for (key, (start_timestamp, mask_idx)) in keys.iter().zip(characterize_range(self.start_timestamp.to_native(), self.end_timestamp.to_native()).into_iter()) {
            let mask = MASKS[mask_idx as usize];
            if (start_timestamp ^ header.timestamp) >> mask == 0 {
                return Some((key, mask_idx));
            }
        }

        None
    }
}

impl ArchivedSubscriptionData {
    /// Decrypt the subscription keys using the device_key and validate that the mac_hash matches
    /// the hash of our decrypted data.
    pub fn authenticate(&self, device_key: &Key) -> bool {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(self.header.start_timestamp.to_native().to_le_bytes());
        hasher.update(self.header.end_timestamp.to_native().to_le_bytes());
        hasher.update(self.header.channel.to_native().to_le_bytes());

        let mut cipher = device_key.cipher();

        let mut buf = [0u8; 8];
        
        for (k, _) in self.keys.iter().zip(characterize_range(self.header.start_timestamp.to_native(), self.header.end_timestamp.to_native()).into_iter()) {
            buf.copy_from_slice(&k.key.0);
            cipher.decrypt(&mut buf);
            hasher.update(k.key.0);
        }

        <[u8; 32]>::from(hasher.finalize()) == self.header.mac_hash
    }
}

impl SubscriptionData {
    /// Generate a subscription key.
    pub fn generate(secrets: &[u8], start: u64, end: u64, channel: u32, device_id: Option<u32>) -> SubscriptionData {
        let mut device_key = device_id.map(|d| Key::for_device(d, secrets).cipher());

        let mut hasher: Sha256 = Digest::new();
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        hasher.update(channel.to_le_bytes());

        let keys = characterize_range(start, end).into_iter().map(|(t, mask_idx)| {
            let mut key = Key::for_bitrange(t, mask_idx, channel, secrets);

            hasher.update(key.0);

            if let Some(device_key_cipher) = &mut device_key {
                device_key_cipher.encrypt(&mut key.0);
            }

            EncodedSubscriptionKey {
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

