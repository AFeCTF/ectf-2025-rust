use alloc::{string::{String, ToString}, vec::Vec};
use bincode::{config::{Configuration, Fixint, LittleEndian, NoLimit}, de::read::Reader, enc::write::Writer, Decode, Encode};

use crate::packet::Packet;

pub const MAGIC: u8 = b'%';
pub const CHUNK_SIZE: usize = 256;

#[derive(Encode, Decode, PartialEq, Eq)]
pub struct Opcode(u8);

impl Opcode {
    const DECODE: Opcode = Opcode(b'D');
    const SUBSCRIBE: Opcode = Opcode(b'S');
    const LIST: Opcode = Opcode(b'L');
    const ACK: Opcode = Opcode(b'A');
    const ERROR: Opcode = Opcode(b'E');
    const DEBUG: Opcode = Opcode(b'G');

    fn should_ack(&self) -> bool {
        !matches!(self.0, b'G' | b'A')
    }
}

#[derive(Encode)]
pub struct MessageHeader {
    pub magic: u8,  // b'%'
    pub opcode: Opcode,
    pub length: u16,
}

impl Packet {
    fn encoded_size(&self) -> u16 {
        match self {
            Packet::ListCommand | Packet::SubscriptionResponse | Packet::Ack => { 0 }
            Packet::ListResponse(vec) => {
                let mut size_finder = SizeFinder(0);
                for entry in vec {
                    bincode::encode_into_writer(entry, &mut size_finder, BINCODE_CONFIG).unwrap();
                }
                size_finder.0
            }
            Packet::SubscriptionCommand(subscription_data) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(subscription_data, &mut size_finder, BINCODE_CONFIG).unwrap();
                size_finder.0
            }
            Packet::DecodeCommand(frame_data) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(frame_data, &mut size_finder, BINCODE_CONFIG).unwrap();
                size_finder.0
            }
            Packet::DecodeResponse(frame) => {
                let mut size_finder = SizeFinder(0);
                bincode::encode_into_writer(frame, &mut size_finder, BINCODE_CONFIG).unwrap();
                size_finder.0
            }
            Packet::Debug(s) => { s.len() as u16 }
            Packet::Error(s) => { s.len() as u16 }
        }
    }

    fn opcode(&self) -> Opcode {
        match self {
            Packet::ListCommand | Packet::ListResponse(_) => { Opcode::LIST }
            Packet::SubscriptionCommand(_) | Packet::SubscriptionResponse => { Opcode::SUBSCRIBE }
            Packet::DecodeCommand(_) | Packet::DecodeResponse(_) => { Opcode::DECODE }
            Packet::Ack => { Opcode::ACK }
            Packet::Debug(_) => { Opcode::DEBUG }
            Packet::Error(_) => { Opcode::ERROR }
        }
    }
}
struct BodyRW<'l, RW: Reader + Writer> {
    cursor: usize,
    rw: &'l mut RW,
    should_ack: bool
}

impl<'l, RW: Reader + Writer> Writer for BodyRW<'l, RW> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.write(bytes)
        }

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
        if !self.should_ack {
            self.cursor += bytes.len();
            return self.rw.read(bytes)
        }

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

const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = bincode::config::legacy();

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

fn write_body<T: Encode, RW: Reader + Writer>(body: &T, rw: &mut RW) {
    let mut body_rw = BodyRW {
        cursor: 0,
        rw,
        should_ack: true
    };

    bincode::encode_into_writer(body, &mut body_rw, BINCODE_CONFIG).unwrap();

    if body_rw.cursor % CHUNK_SIZE != 0 {
        wait_for_ack(rw);
    }
}

fn write_vector_body<T: Encode, RW: Reader + Writer>(body: &Vec<T>, rw: &mut RW) {
    let mut body_rw = BodyRW {
        cursor: 0,
        rw,
        should_ack: true
    };

    for entry in body {
        bincode::encode_into_writer(entry, &mut body_rw, BINCODE_CONFIG).unwrap();
    }

    if body_rw.cursor % CHUNK_SIZE != 0 {
        wait_for_ack(rw);
    }
}

fn write_string_body<RW: Reader + Writer>(body: &String, rw: &mut RW) {
    BodyRW {
        cursor: 0,
        rw,
        should_ack: false
    }.write(body.as_bytes()).unwrap();
}

pub fn write_to_wire<RW: Reader + Writer>(msg: &Packet, rw: &mut RW) {
    write_header(msg.opcode(), msg.encoded_size(), rw);
    if msg.opcode().should_ack() {
        wait_for_ack(rw);
    }

    match msg {
        Packet::ListResponse(vec) => { write_vector_body(vec, rw); }
        Packet::SubscriptionCommand(subscription_data) => { write_body(subscription_data, rw); }
        Packet::DecodeCommand(frame_data) => { write_body(frame_data, rw); }
        Packet::Error(s) => { write_string_body(s, rw); }
        Packet::Debug(s) => { write_string_body(s, rw); }
        _ => {}
    }
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
    let mut body_rw = BodyRW {
        cursor: 0,
        rw,
        should_ack: true
    };

    let mut res = Vec::new();

    while body_rw.cursor < length {
        res.push(bincode::decode_from_reader(&mut body_rw, BINCODE_CONFIG).unwrap());
    }

    if body_rw.cursor % CHUNK_SIZE != 0 {
        wait_for_ack(rw);
    }
    
    res
}

fn read_string_body<RW: Reader + Writer>(rw: &mut RW, length: usize) -> String {
    let mut res: Vec<u8> = Vec::with_capacity(length);
    BodyRW {
        cursor: 0,
        rw,
        should_ack: false
    }.read(res.as_mut_slice()).unwrap();
    String::from_utf8_lossy(res.as_slice()).to_string()
}

fn read_body<T: Decode, RW: Reader + Writer>(rw: &mut RW) -> T {
    let mut body_rw = BodyRW {
        cursor: 0,
        rw,
        should_ack: true
    };

    let res = bincode::decode_from_reader(&mut body_rw, BINCODE_CONFIG).unwrap();

    if body_rw.cursor % CHUNK_SIZE != 0 {
        wait_for_ack(rw);
    }
    
    res
}

// TODO error handling better than option?
pub fn read_from_wire<RW: Reader + Writer>(is_decoder: bool, rw: &mut RW) -> Option<Packet> {
    let header = read_header(rw);

    if header.opcode.should_ack() {
        write_ack(rw);
    }

    Some(if header.length == 0 {
        match header.opcode {
            Opcode::ACK => { Packet::Ack },
            Opcode::LIST => { Packet::ListCommand },
            Opcode::SUBSCRIBE => { Packet::SubscriptionResponse },
            _ => { return None; }
        }
    } else {
        match header.opcode {
            Opcode::LIST => { Packet::ListResponse(read_vector_body(rw, header.length as usize)) }
            Opcode::DECODE => { 
                if is_decoder {
                    Packet::DecodeCommand(read_body(rw))
                } else {
                    Packet::DecodeResponse(read_body(rw))
                }
            }
            Opcode::SUBSCRIBE => { Packet::SubscriptionCommand(read_body(rw)) }
            Opcode::DEBUG => { Packet::Debug(read_string_body(rw, header.length as usize)) }
            Opcode::ERROR => { Packet::Error(read_string_body(rw, header.length as usize)) }
            _ => { return None; }
        }
    })
}
