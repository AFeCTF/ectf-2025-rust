use core::fmt::Debug;

use aes::Aes128;
use bincode::{Decode, Encode};
use cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyInit, KeySizeUser};
use sha2::{Digest, Sha256};

use crate::frame::Frame;

/// 64-bit key that is extended with zeros to form an AES128 key
#[derive(Encode, Decode)]
pub struct Key(pub [u8; 8]);

/// Used to encrypt and decrypt data. Generated from a [`Key`].
pub struct Cipher(Aes128);

impl Key {
    /// Create a [`Cipher`] from a key. The [`Cipher`] should be reused as much as possible.
    pub fn cipher(&self) -> Cipher {
        Cipher(Aes128::new(&self.to_aes_key()))
    }

    /// Create an AES128 key from this key.
    fn to_aes_key(&self) -> GenericArray<u8, <Aes128 as KeySizeUser>::KeySize> {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&self.0);
        data.into()
    }

    /// Generate a device key using the device id and the global secrets.
    pub(crate) fn for_device(device_id: u32, secrets: &[u8]) -> Key {
        let mut hasher: Sha256 = Digest::new();
        hasher.update(secrets);
        hasher.update(device_id.to_le_bytes());
        let _hash: [u8; 32] = hasher.finalize().into();
        // Key(hash[..8].try_into().unwrap())
        Key([0; 8])
    }

    /// Generate a subscripton key for a bitrange.
    pub(crate) fn for_bitrange(start_timestamp: u64, mask_idx: u8, channel: u32, secrets: &[u8]) -> Key {
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
    /// Encrypt an array with AES.
    pub fn encrypt<const N: usize>(&mut self, data: &mut [u8; N]) {
        for chunk in data.chunks_exact_mut(16) {
            self.0.encrypt_block_mut(chunk.into());
        }
    }

    /// Decrypt an array with AES.
    pub fn decrypt<const N: usize>(&mut self, data: &mut [u8; N]) {
        for chunk in data.chunks_exact_mut(16) {
            self.0.decrypt_block_mut(chunk.into());
        }
    }

    /// Encrypt a single frame with AES. Not to be confused with frame encoding.
    pub fn encrypt_frame(&mut self, frame: &mut Frame) {
        self.encrypt(&mut frame.0);
    }

    /// Decrypt a single frame with AES. Not to be confused with frame decoding.
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
