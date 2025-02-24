use core::ops::Deref;

use max7800x_hal::{pac, uart::BuiltUartPeripheral};

use super::packet::{MessageHeader, Opcode, MAGIC};

impl<UART, RX, TX, CTS, RTS> RawRW for BuiltUartPeripheral<UART, RX, TX, CTS, RTS>
where
    UART: Deref<Target = pac::uart0::RegisterBlock>
{ }

pub trait RawRW: Sized + embedded_io::Read + embedded_io::Write {
    /// Blocking function that waits for an ACK to be recieved.
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

    fn read_u8(&mut self) -> u8 {
        let mut buf = [0u8];
        self.read_exact(&mut buf).unwrap();
        buf[0]
    }

    fn read_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf).unwrap();
        u16::from_le_bytes(buf)
    }

    fn write_u8(&mut self, data: u8) {
        self.write_all(&data.to_le_bytes()).unwrap();
    }

    fn write_u16(&mut self, data: u16) {
        self.write_all(&data.to_le_bytes()).unwrap();
    }

    /// Reads a packet header.
    fn read_header(&mut self) -> MessageHeader {
        // Block until we get the magic character
        let mut buf = [0u8];
        while buf[0] != MAGIC {
            self.read_exact(&mut buf).unwrap();
        }

        let opcode = Opcode(self.read_u8());
        let length = self.read_u16();

        MessageHeader {
            magic: MAGIC,
            opcode,
            length
        }
    }

    /// Writes an ACK.
    fn write_ack(&mut self) {
        self.write_header(Opcode::ACK, 0);
    }

    /// Writes a packet header.
    fn write_header(&mut self, opcode: Opcode, length: u16) {
        self.write_u8(MAGIC);
        self.write_u8(opcode.0);
        self.write_u16(length);
    }

    #[allow(dead_code)]
    fn write_debug(&mut self, msg: &str) {
        self.write_header(Opcode::DEBUG, msg.len() as u16);
        for b in msg.as_bytes() {
            self.write_u8(*b);
        }
    }

    fn write_error(&mut self, error: &str) {
        self.write_header(Opcode::ERROR, error.len() as u16);
        for b in error.as_bytes() {
            self.write_u8(*b);
        }
    }
}

// #[allow(static_mut_refs)]
// #[allow(non_snake_case)]
// #[interrupt]
// unsafe fn UART0() {
//     let uart0 = UART0.as_mut().unwrap();

//     if uart0.int_fl().read().rx_ov().bit_is_set() {
//         panic!("rx buffer overrun");
//     }

//     // Read all bytes off wire
//     let rw = RW.as_mut().unwrap();
//     while rw.inner.read_ready().unwrap() {
//         rw.rxbuf.push(rw.inner.read_byte());
//     }

//     // Clear the interrupt flags
//     uart0.int_fl().write(|w| w
//         .rx_thd().set_bit()
//         // .rx_ov().set_bit()
//     );
// }
