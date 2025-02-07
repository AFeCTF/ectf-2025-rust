use core::ops::Deref;

use alloc::{string::String, vec::Vec};
use bincode::{de::read::Reader, enc::write::Writer, Decode, Encode};
use embedded_io::Read;
use libectf::{frame::{EncodedFramePacketHeader, Frame, NUM_ENCODED_FRAMES}, subscription::{EncodedSubscriptionKey, SubscriptionData}};
use max7800x_hal::{pac, uart::BuiltUartPeripheral};
use sha2::{Digest, Sha256};

use super::{MessageHeader, Opcode, Packet, ReadResult, BINCODE_CONFIG, CHUNK_SIZE, MAGIC};

#[allow(dead_code)]
pub struct DecodedFrame {
    pub header: EncodedFramePacketHeader,
    pub frame: Frame
}

pub struct UartRW<'a, UART: Deref<Target = pac::uart0::RegisterBlock>, RX, TX, CTS, RTS>(pub &'a mut BuiltUartPeripheral<UART, RX, TX, CTS, RTS>);

impl<'a, UART, RX, TX, CTS, RTS> Reader for UartRW<'a, UART, RX, TX, CTS, RTS>
where
    UART: Deref<Target = pac::uart0::RegisterBlock>
{
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), bincode::error::DecodeError> {
        // TODO error handling and we want read_exact instead of read right?
        self.0.read_exact(bytes).unwrap();
        Ok(())
    }
}

impl<'a, UART, RX, TX, CTS, RTS> Writer for UartRW<'a, UART, RX, TX, CTS, RTS>
where
    UART: Deref<Target = pac::uart0::RegisterBlock>
{
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        self.0.write_bytes(bytes);
        Ok(())
    }
}

impl<'a, UART, RX, TX, CTS, RTS> RawRW for UartRW<'a, UART, RX, TX, CTS, RTS>
where
    UART: Deref<Target = pac::uart0::RegisterBlock>
{ }

pub trait RawRW: Reader + Writer + Sized {
    fn wait_for_ack(&mut self) {
        let header = self.read_header();
        
        if header.opcode != Opcode::ACK {
            // TODO better error handling
            panic!("Non-ack recieved");
        }

        if header.length != 0 {
            // TODO warn because packet size should be zero
            for _ in 0..header.length {
                self.read(&mut [0u8]).unwrap();
            }
        }
    }

    fn read_header(&mut self) -> MessageHeader {
        // Block until we get the magic character
        let mut buf = [0u8];
        while buf[0] != MAGIC {
            self.read(&mut buf).unwrap();
        }

        let opcode: Opcode = bincode::decode_from_reader(&mut *self, BINCODE_CONFIG).unwrap();
        let length: u16 = bincode::decode_from_reader(&mut *self, BINCODE_CONFIG).unwrap();

        MessageHeader {
            magic: MAGIC,
            opcode,
            length
        }
    }

    fn write_ack(&mut self) {
        self.write_header(Opcode::ACK, 0);
    }

    fn write_header(&mut self, opcode: Opcode, length: u16) {
        let header = MessageHeader {
            magic: MAGIC,
            opcode,
            length,
        };
        
        // TODO error handling!
        bincode::encode_into_writer(header, self, BINCODE_CONFIG).unwrap();
    }

    fn write_to_wire(&mut self, msg: &Packet) {
        self.write_header(msg.opcode(), msg.encoded_size());
        if msg.opcode().should_ack() {
            self.wait_for_ack();
        }

        let mut rw = BodyRW::new(msg.opcode().should_ack(), self);

        match msg {
            Packet::ListResponse(vec) => { 
                rw.write_body(&(vec.len() as u32));
                rw.write_vector_body(vec);
            }
            Packet::SubscriptionCommand(subscription_data) => { 
                rw.write_body(&subscription_data.header); 
                rw.write_vector_body(&subscription_data.keys); 
            }
            Packet::DecodeResponse(frame) => { rw.write_body(frame); }
            Packet::Error(s) => { rw.write_string_body(s); }
            Packet::Debug(s) => { rw.write_string_body(s); }
            _ => { return; }
        }
        
        rw.finish_write();
    }

    fn read_from_wire<'l, F: FnOnce(&EncodedFramePacketHeader) -> Option<&'l EncodedSubscriptionKey>>(&mut self, get_key: F) -> ReadResult {
        let header = self.read_header();

        if header.opcode.should_ack() {
            self.write_ack();
        }

        if header.length == 0 {
            match header.opcode {
                Opcode::ACK => { ReadResult::Packet(Packet::Ack) },
                Opcode::LIST => { ReadResult::Packet(Packet::ListCommand) },
                Opcode::SUBSCRIBE => { ReadResult::Packet(Packet::SubscriptionResponse) },
                _ => { ReadResult::None }
            }
        } else {
            let mut rw = BodyRW::new(header.opcode.should_ack(), self);

            let res = match header.opcode {
                Opcode::LIST => { 
                    let _: u32 = rw.read_body();
                    ReadResult::Packet(Packet::ListResponse(rw.read_vector_body(header.length as usize)))
                }
                Opcode::DECODE => { 
                    let header = rw.read_body();
                    let key = get_key(&header);
                    let frame = rw.decode_off_wire(&header, key);
                    if let Some(frame) = frame {
                        let mut hasher: Sha256 = Digest::new();
                        hasher.update(&frame.0);
                        if <[u8; 32]>::from(hasher.finalize())[..16] == header.mac_hash {
                            ReadResult::DecodedFrame(DecodedFrame { header, frame })
                        } else {
                            ReadResult::FrameDecodeError
                        }
                    } else {
                        ReadResult::FrameDecodeError
                    }
                }
                Opcode::SUBSCRIBE => { 
                    let packet_len = header.length as usize;
                    let header = rw.read_body();
                    let keys = rw.read_vector_body(packet_len);

                    ReadResult::Packet(Packet::SubscriptionCommand(SubscriptionData { header, keys }))
                }
                _ => { return ReadResult::None; }
            };

            rw.finish_read();

            res
        }
    }
}

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

    fn decode_off_wire(&mut self, _header: &EncodedFramePacketHeader, key: Option<&EncodedSubscriptionKey>) -> Option<Frame> {
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
    
    fn finish_read(&mut self) {
        if self.should_ack && self.cursor % CHUNK_SIZE != 0 {
            self.rw.write_ack();
        }
    }

    fn finish_write(&mut self) {
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

