#![no_std]

extern crate alloc;

use alloc::{string::String, vec::{self, Vec}};
use bincode::{config::{Configuration, Fixint, LittleEndian, NoLimit}, de::read::Reader, enc::write::Writer, Decode, Encode};

pub const CHUNK_SIZE: usize = 256;
pub const FRAME_SIZE: usize = 64;
pub const MAGIC: u8 = b'%';

#[derive(Encode, Decode, PartialEq, Eq)]
pub struct Opcode(u8);

impl Opcode {
    pub const DECODE: Opcode = Opcode(b'D');
    pub const SUBSCRIBE: Opcode = Opcode(b'S');
    pub const LIST: Opcode = Opcode(b'L');
    pub const ACK: Opcode = Opcode(b'A');
    pub const ERROR: Opcode = Opcode(b'E');
    pub const DEBUG: Opcode = Opcode(b'G');
}

#[derive(Encode)]
pub struct MessageHeader {
    pub magic: u8,  // b'%'
    pub opcode: Opcode,
    pub length: u16,
}

#[derive(Encode, Decode)]
pub struct FramePacket {
    pub channel: u32,
    pub timestamp: u64,
    pub data: [u8; FRAME_SIZE]
}

#[derive(Encode, Decode)]
pub struct SubscriptionUpdatePacket {
    pub decoder_id: u32,
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub channel: u32
}

#[derive(Encode, Decode)]
pub struct ChannelInfo {
    pub channel: u32,
    pub start: u64,
    pub end: u64
}

#[derive(Encode, Decode)]
pub struct SubscriptionData {

}

#[derive(Encode, Decode)]
pub struct FrameData {

}

pub enum Packet {
    ListCommand,
    ListResponse(Vec<ChannelInfo>),
    SubscriptionCommand(SubscriptionData),
    SubscriptionResponse,
    DecodeCommand(FrameData),
    DecodeResponse,
    Ack,
    Debug(String),
    Error(String)
}

struct BodyRW<'l, RW: Reader + Writer> {
    cursor: usize,
    rw: &'l mut RW
}

impl<'l, RW: Reader + Writer> Writer for BodyRW<'l, RW> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        let first_chunk_size = CHUNK_SIZE - self.cursor;

        if first_chunk_size >= bytes.len() {
            self.rw.write(bytes)?;
            self.cursor += bytes.len();
            if self.cursor % CHUNK_SIZE == 0 {
                wait_for_ack(self.rw);
            }
        } else {
            let first_slice = &bytes[0..first_chunk_size];
            self.rw.write(first_slice)?;
            wait_for_ack(self.rw);
            self.cursor += first_slice.len();
            for chunk in bytes[first_chunk_size..].chunks(256) {
                if self.cursor % CHUNK_SIZE != 0 {
                    panic!("This should never happen!");
                }
                self.rw.write(chunk)?;
                self.cursor += chunk.len();
                if self.cursor % CHUNK_SIZE == 0 {
                    wait_for_ack(self.rw);
                }
            }
        }

        Ok(())
    }
}

impl<'l, RW: Reader + Writer> Reader for BodyRW<'l, RW> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), bincode::error::DecodeError> {
        let first_chunk_size = CHUNK_SIZE - self.cursor;

        if first_chunk_size >= bytes.len() {
            self.rw.read(bytes)?;
            self.cursor += bytes.len();
            if self.cursor % CHUNK_SIZE == 0 {
                write_ack(self.rw);
            }
        } else {
            let first_slice = &mut bytes[0..first_chunk_size];
            self.rw.read(first_slice)?;
            write_ack(self.rw);
            self.cursor += first_slice.len();
            for chunk in bytes[first_chunk_size..].chunks_mut(256) {
                if self.cursor % CHUNK_SIZE != 0 {
                    panic!("This should never happen!");
                }
                self.rw.read(chunk)?;
                self.cursor += chunk.len();
                if self.cursor % CHUNK_SIZE == 0 {
                    wait_for_ack(self.rw);
                }
            }
        }

        Ok(())
    }
}

struct SizeFinder(u16);

impl Writer for SizeFinder {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        // TODO error on overflow (both in casting and addassign)
        self.0 += bytes.len() as u16;
        Ok(())
    }
}

pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = bincode::config::legacy();

pub fn wait_for_ack<R: Reader>(reader: &mut R) {
    let header = read_header(reader);
    
    if header.opcode != Opcode::ACK {
        // TODO better error handling
        panic!("Non-ack recieved");
    }

    if header.length != 0 {
        // TODO warn because packet size should be zero
        for _ in 0..header.length {
            reader.read(&mut [0u8]).unwrap();
        }
    }
}

pub fn write_ack<W: Writer>(writer: &mut W) {
    write_header(Opcode::ACK, 0, writer);
}

pub fn write_header<W: Writer>(opcode: Opcode, length: u16, writer: &mut W) {
    let header = MessageHeader {
        magic: MAGIC,
        opcode,
        length,
    };
    
    // TODO error handling!
    bincode::encode_into_writer(header, writer, BINCODE_CONFIG).unwrap();
}

// TODO change this to take a packet instead of generic and handle the vector/string body
// accordingly
pub fn write_to_wire<T: Encode, RW: Reader + Writer>(body: &T, opcode: Opcode, rw: &mut RW) {
    let mut size_finder = SizeFinder(0);
    bincode::encode_into_writer(&body, &mut size_finder, BINCODE_CONFIG).unwrap();
    let length = size_finder.0;

    write_header(opcode, length, rw);
    wait_for_ack(rw);

    bincode::encode_into_writer(body, BodyRW {
        cursor: 0,
        rw
    }, BINCODE_CONFIG).unwrap();
}

pub fn read_header<R: Reader>(reader: &mut R) -> MessageHeader {
    // Block until we get the magic character
    let mut buf = [0u8];
    while buf[0] != MAGIC {
        reader.read(&mut buf).unwrap();
    }

    let opcode: Opcode = bincode::decode_from_reader(&mut *reader, BINCODE_CONFIG).unwrap();
    let length: u16 = bincode::decode_from_reader(&mut *reader, BINCODE_CONFIG).unwrap();

    MessageHeader {
        magic: MAGIC,
        opcode,
        length
    }
}

fn read_vector_body<T: Decode, RW: Reader + Writer>(rw: &mut RW, length: usize) -> Vec<T> {
    let mut rw = BodyRW {
        cursor: 0,
        rw
    };

    let mut res = Vec::new();

    while rw.cursor < length {
        res.push(bincode::decode_from_reader(&mut rw, BINCODE_CONFIG).unwrap());
    }
    
    res
}

fn read_body<T: Decode, RW: Reader + Writer>(rw: &mut RW) -> T {
    bincode::decode_from_reader(BodyRW {
        cursor: 0,
        rw,
    }, BINCODE_CONFIG).unwrap()
}

// TODO error handling better than option?
pub fn read_from_wire<T: Encode, RW: Reader + Writer>(rw: &mut RW) -> Option<Packet> {
    let header = read_header(rw);

    Some(if header.length == 0 {
        match header.opcode {
            Opcode::ACK => { Packet::Ack },
            Opcode::LIST => { Packet::ListCommand },
            Opcode::DECODE => { Packet::DecodeResponse },
            Opcode::SUBSCRIBE => { Packet::SubscriptionResponse },
            _ => { return None; }
        }
    } else {
        match header.opcode {
            Opcode::LIST => { Packet::ListResponse(read_vector_body(rw, header.length as usize))}
            Opcode::DECODE => { Packet::DecodeCommand(read_body(rw)) }
            Opcode::SUBSCRIBE => { Packet::SubscriptionCommand(read_body(rw)) }
            // TODO debug and error, string packet handling
            _ => { return None; }
        }
    })
}
