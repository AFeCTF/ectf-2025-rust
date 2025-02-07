#![cfg_attr(not(test), no_std)]

#[cfg(test)] extern crate std;
#[cfg(test)] #[allow(unused_imports)] use std::prelude::*;

extern crate alloc;

use bincode::{config::{Configuration, Fixint, LittleEndian, NoLimit}, Encode};
use alloc::vec::Vec;

pub mod masks;
pub mod key;
pub mod frame;
pub mod subscription;

pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = bincode::config::legacy();

pub trait EncodeToVec: Encode {
    fn encode_to_vec(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }
}

impl<T: Encode> EncodeToVec for T {}

