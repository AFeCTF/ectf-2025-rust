#![no_std]

use bincode::{config::{Configuration, Fixint, LittleEndian, NoLimit}, enc::write::Writer, Encode};

#[derive(Encode)]
struct Message<'m, T: Encode> {
    magic: u8,  // b'%'
    opcode: u8,
    length: u16,
    body: &'m T
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

pub fn write_to_uart<T: Encode, W: Writer>(body: &T, opcode: u8, writer: W) {
    let mut size_finder = SizeFinder(0);
    bincode::encode_into_writer(&body, &mut size_finder, BINCODE_CONFIG).unwrap();
    let length = size_finder.0;

    let msg = Message {
        magic: b'%',
        opcode,
        length,
        body
    };
    
    // TODO error handling!
    bincode::encode_into_writer(msg, writer, BINCODE_CONFIG).unwrap();
}
