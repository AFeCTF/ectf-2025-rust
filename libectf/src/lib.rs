#![no_std]

use serde::Serialize;

#[derive(Serialize)]
struct Message<'b, T: Serialize> {
    magic: u8,  // b'%'
    opcode: u8,
    length: [u8; 2],
    body: &'b T
}

pub fn write_to_uart<T: Serialize, W: Extend<u8>>(value: &T, opcode: u8, writer: W) {
    let length = postcard::serialize_with_flavor(&value, postcard::ser_flavors::Size::default()).unwrap() as u16;
    
    let msg = Message {
        magic: b'%',
        opcode,
        length: length.to_le_bytes(),
        body: value,
    };
    
    postcard::to_extend(&msg, writer).unwrap();
}
