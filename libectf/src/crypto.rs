use sha2::{Digest, Sha256};

use aes::Aes256;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};

use crate::packet::{EncodedFramePacket, Frame, SubscriptionKey};

pub type Key = [u8; 32];

// TODO research security of this
pub fn aes_encrypt_in_place(data: &mut [u8; 64], key: &Key) {
    let mut cipher = Aes256::new(key.into());

    for chunk in data.chunks_exact_mut(16) {
        cipher.encrypt_block_mut(chunk.into());
    }
}

pub fn aes_decrypt_in_place(data: &mut [u8; 64], key: &Key) {
    let mut cipher = Aes256::new(key.into());

    for chunk in data.chunks_exact_mut(16) {
        cipher.decrypt_block_mut(chunk.into());
    }
}

pub fn gen_key(start_timestamp: u64, mask_width: u8, channel: u32, decoder_id: u32, secrets: &[u8]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(secrets);
    hasher.update(start_timestamp.to_le_bytes());
    hasher.update(mask_width.to_le_bytes());
    hasher.update(channel.to_le_bytes());
    hasher.update(decoder_id.to_le_bytes());
    hasher.finalize().into()
}

pub fn encode(frame: Frame, mut timestamp: u64, channel: u32, decoder_id: u32, secrets: &[u8]) -> EncodedFramePacket {
    let mut data = [frame; 64];

    for mask_width in 0..64 {
        let key = gen_key(timestamp << mask_width, mask_width, channel, decoder_id, secrets);
        aes_encrypt_in_place(&mut data[mask_width as usize], &key);
        timestamp >>= 1;
    }

    EncodedFramePacket {
        channel,
        timestamp,
        data
    }
}

pub fn decode(frame: EncodedFramePacket, key: SubscriptionKey) -> Frame {
    let mut data = frame.data[key.mask_width as usize];
    aes_decrypt_in_place(&mut data, &key.key);
    data
}
