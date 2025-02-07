use alloc::{string::String, vec::Vec};
use bincode::{de::read::Reader, enc::write::Writer, Decode, Encode};
use libectf::{frame::{EncodedFramePacketHeader, Frame, NUM_ENCODED_FRAMES}, subscription::EncodedSubscriptionKey, BINCODE_CONFIG};

use super::raw_rw::RawRW;

pub const CHUNK_SIZE: usize = 256;

pub struct BodyRW<'l, RW: RawRW> {
    cursor: usize,
    rw: &'l mut RW,
    should_ack: bool
}

impl<'l, RW: RawRW> BodyRW<'l, RW> {
    pub fn new(should_ack: bool, rw: &'l mut RW) -> Self {
        Self { cursor: 0, rw, should_ack }
    }

    pub fn write_body<T: Encode>(&mut self, body: &T) {
        bincode::encode_into_writer(body, self, BINCODE_CONFIG).unwrap();
    }

    pub fn write_vector_body<T: Encode>(&mut self, body: &Vec<T>) {
        for entry in body {
            bincode::encode_into_writer(entry, &mut *self, BINCODE_CONFIG).unwrap();
        }
    }

    pub fn write_string_body(&mut self, body: &String) {
        self.write(body.as_bytes()).unwrap();
    }

    pub fn read_vector_body<T: Decode>(&mut self, length: usize) -> Vec<T> {
        let mut res = Vec::new();

        while self.cursor < length {
            res.push(bincode::decode_from_reader(&mut *self, BINCODE_CONFIG).unwrap());
        }
        
        res
    }

    // pub fn read_string_body(&mut self, length: usize) -> String {
    //     let mut res: Vec<u8> = Vec::with_capacity(length);
    //     self.read(res.as_mut_slice()).unwrap();
    //     String::from_utf8_lossy(res.as_slice()).to_string()
    // }

    pub fn read_body<T: Decode>(&mut self) -> T {
        bincode::decode_from_reader(self, BINCODE_CONFIG).unwrap()
    }

    pub(super) fn decode_off_wire(&mut self, _header: &EncodedFramePacketHeader, key: Option<&EncodedSubscriptionKey>) -> Option<Frame> {
        let mut res: Option<Frame> = None;

        if let Some(key) = key {
            for idx in 0..NUM_ENCODED_FRAMES {
                let f: Frame = self.read_body();
                if idx == key.mask_idx as usize {
                    res = Some(f);
                }
            }
            
            if let Some(f) = res.as_mut() {
                key.key.cipher().decode_frame(f);
            }
        } else {
            // Throw all frames away
            for _ in 0..NUM_ENCODED_FRAMES {
                let _: Frame = self.read_body();
            }
        }
        
        res
    }
    
    pub(super) fn finish_read(&mut self) {
        if self.should_ack && self.cursor % CHUNK_SIZE != 0 {
            self.rw.write_ack();
        }
    }

    pub(super) fn finish_write(&mut self) {
        if self.should_ack && self.cursor % CHUNK_SIZE != 0 {
            self.rw.wait_for_ack();
        }
    }
}

impl<'l, RW: RawRW> Writer for BodyRW<'l, RW> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.write(bytes)
        }

        let first_chunk_size = CHUNK_SIZE - (self.cursor % CHUNK_SIZE);

        if first_chunk_size >= bytes.len() {
            self.rw.write(bytes)?;
            self.cursor += bytes.len();
            if self.cursor % CHUNK_SIZE == 0 {
                self.rw.wait_for_ack();
            }
        } else {
            let first_slice = &bytes[0..first_chunk_size];
            self.rw.write(first_slice)?;
            self.rw.wait_for_ack();
            self.cursor += first_slice.len();
            for chunk in bytes[first_chunk_size..].chunks(256) {
                if self.cursor % CHUNK_SIZE != 0 {
                    panic!("This should never happen!");
                }
                self.rw.write(chunk)?;
                self.cursor += chunk.len();
                if self.cursor % CHUNK_SIZE == 0 {
                    self.rw.wait_for_ack();
                }
            }
        }

        Ok(())
    }
}

impl<'l, RW: RawRW> Reader for BodyRW<'l, RW> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), bincode::error::DecodeError> {
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.read(bytes)
        }

        let first_chunk_size = CHUNK_SIZE - (self.cursor % CHUNK_SIZE);

        if first_chunk_size >= bytes.len() {
            self.rw.read(bytes)?;
            self.cursor += bytes.len();
            if self.cursor % CHUNK_SIZE == 0 {
                self.rw.write_ack();
            }
        } else {
            let first_slice = &mut bytes[0..first_chunk_size];
            self.rw.read(first_slice)?;
            self.cursor += first_slice.len();
            self.rw.write_ack();
            for chunk in bytes[first_chunk_size..].chunks_mut(256) {
                if self.cursor % CHUNK_SIZE != 0 {
                    panic!("This should never happen!");
                }
                self.rw.read(chunk)?;
                self.cursor += chunk.len();
                if self.cursor % CHUNK_SIZE == 0 {
                    self.rw.write_ack();
                }
            }
        }

        Ok(())
    }
}

