use rkyv::{Archive, Deserialize, Serialize};

/// The magic character indicating the start of a packet
pub const MAGIC: u8 = b'%';

/// The opcode indicating the type of packet being sent
#[derive(Serialize, Deserialize, Archive, PartialEq, Eq, Debug)]
pub struct Opcode(pub u8);

impl Opcode {
    pub const DECODE: Opcode = Opcode(b'D');
    pub const SUBSCRIBE: Opcode = Opcode(b'S');
    pub const LIST: Opcode = Opcode(b'L');
    pub const ACK: Opcode = Opcode(b'A');
    pub const ERROR: Opcode = Opcode(b'E');
    pub const DEBUG: Opcode = Opcode(b'G');

    /// Do we need to send/recieve ACKs for this opcode?
    pub fn should_ack(&self) -> bool {
        !matches!(self.0, b'G' | b'A')
    }
}

#[derive(Serialize, Deserialize, Archive, Debug)]
pub struct MessageHeader {
    pub magic: u8,
    pub opcode: Opcode,
    pub length: u16,
}

