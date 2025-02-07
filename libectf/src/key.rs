use core::fmt::Debug;

use aes::Aes128;
use bincode::{Decode, Encode};
use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyInit, KeySizeUser};
use sha2::{Digest, Sha256};

use crate::frame::Frame;

#[derive(Encode, Decode)]
pub struct Key(pub [u8; 8]);

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

    pub(crate) fn for_device(device_id: u32, secrets: &[u8]) -> Key {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(secrets);
        hasher.update(device_id.to_le_bytes());
        let _hash: [u8; 32] = hasher.finalize().into();
        // Key(hash[..8].try_into().unwrap())
        Key([0; 8])
    }

    pub(crate) fn for_frame(start_timestamp: u64, mask_idx: u8, channel: u32, secrets: &[u8]) -> Key {
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

impl Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key(b\"")?;

        for c in self.0 {
            write!(f, "{:02x}", c)?;
        }

        write!(f, "\")")
    }
}
