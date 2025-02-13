use alloc::{string::String, vec::Vec};
use bincode::{de::read::Reader, enc::write::Writer, Decode, Encode};
use libectf::{frame::{Frame, NUM_ENCRYPTED_FRAMES}, subscription::EncodedSubscriptionKey, BINCODE_CONFIG};

use super::raw_rw::RawRW;

/// A wrapper around a raw reader/writer that handles reading/writing the body of 
/// packets. This is needed because the encoder expects ACKs every 256 bytes.
pub struct BodyRW<'l, RW: RawRW> {
    cursor: usize,
    rw: &'l mut RW,
    should_ack: bool
}

impl<'l, RW: RawRW> BodyRW<'l, RW> {
    const CHUNK_SIZE: usize = 256;
    
    /// Creates a new BodyRW object.
    pub fn new(should_ack: bool, rw: &'l mut RW) -> Self {
        Self { cursor: 0, rw, should_ack }
    }

    /// Writes encodable data, waiting for ACKs when required.
    pub fn write_body<T: Encode>(&mut self, body: &T) {
        bincode::encode_into_writer(body, self, BINCODE_CONFIG).unwrap();
    }

    /// Writes a vector of encodable data, this is equivalent to writing each element
    /// sequentially. NOTE: The length of the vector is stored nowhere, it is the 
    /// responsibility of the programmer to store it some other way and pass it to the
    /// [`read_vector_body`] function on the receiving end.
    pub fn write_vector_body<T: Encode>(&mut self, body: &Vec<T>) {
        for entry in body {
            bincode::encode_into_writer(entry, &mut *self, BINCODE_CONFIG).unwrap();
        }
    }

    /// Writes a string. NOTE: The length of the string is stored nowhere, it is the 
    /// responsibility of the programmer to store it some other way and pass it to the
    /// [`read_string_body`] function on the receiving end.
    pub fn write_string_body(&mut self, body: &String) {
        self.write(body.as_bytes()).unwrap();
    }

    /// Reads encodable data, waiting for ACKs when required.
    pub fn read_body<T: Decode>(&mut self) -> T {
        bincode::decode_from_reader(self, BINCODE_CONFIG).unwrap()
    }

    /// Reads a vector of decodable data. Until [`length`] bytes have been read.
    pub fn read_vector_body<T: Decode>(&mut self, length: usize) -> Vec<T> {
        let mut res = Vec::new();

        while self.cursor < length {
            res.push(bincode::decode_from_reader(&mut *self, BINCODE_CONFIG).unwrap());
        }
        
        res
    }

    /// Reads a string. This is not used on the decoder so it is commented out.
    // pub fn read_string_body(&mut self, length: usize) -> String {
    //     let mut res: Vec<u8> = Vec::with_capacity(length);
    //     self.read(res.as_mut_slice()).unwrap();
    //     String::from_utf8_lossy(res.as_slice()).to_string()
    // }

    /// Decodes a frame off the wire. This function is intended to be called once 
    /// the header of the encoded frame has already been read, and will read frames
    /// one at a time and decode the proper frame with [`key`] (if one is provided).
    pub(super) fn decode_off_wire(&mut self, key: Option<&EncodedSubscriptionKey>) -> Option<Frame> {
        let mut res: Option<Frame> = None;

        if let Some(key) = key {
            for idx in 0..NUM_ENCRYPTED_FRAMES {
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
            for _ in 0..NUM_ENCRYPTED_FRAMES {
                let _: Frame = self.read_body();
            }
        }
        
        res
    }

    /// Write the final ACK once an entire packet has been recieved.
    pub(super) fn finish_read(&mut self) {
        if self.should_ack && self.cursor % Self::CHUNK_SIZE != 0 {
            self.rw.write_ack();
        }
    }

    /// Recieve the final ACK once an entire packet has been transmitted.
    pub(super) fn finish_write(&mut self) {
        if self.should_ack && self.cursor % Self::CHUNK_SIZE != 0 {
            self.rw.wait_for_ack();
        }
    }
}

impl<'l, RW: RawRW> Writer for BodyRW<'l, RW> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.write(bytes);
        }

        let mut remaining = bytes;
        while !remaining.is_empty() {
            let chunk_size = (Self::CHUNK_SIZE - (self.cursor % Self::CHUNK_SIZE)).min(remaining.len());
            let (chunk, rest) = remaining.split_at(chunk_size);

            self.rw.write(chunk)?;
            self.cursor += chunk.len();
            remaining = rest;

            if self.cursor % Self::CHUNK_SIZE == 0 {
                self.rw.wait_for_ack();
            }
        }

        Ok(())
    }
}

impl<'l, RW: RawRW> Reader for BodyRW<'l, RW> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), bincode::error::DecodeError> {
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.read(bytes);
        }

        let mut remaining = bytes;
        while !remaining.is_empty() {
            let chunk_size = (Self::CHUNK_SIZE - (self.cursor % Self::CHUNK_SIZE)).min(remaining.len());
            let (chunk, rest) = remaining.split_at_mut(chunk_size);

            self.rw.read(chunk)?;
            self.cursor += chunk.len();
            remaining = rest;

            if self.cursor % Self::CHUNK_SIZE == 0 {
                self.rw.write_ack();
            }
        }

        Ok(())
    }
}
