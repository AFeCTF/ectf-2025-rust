use alloc::vec;
use core::ops::Deref;

use alloc::vec::Vec;
use bincode::{de::read::Reader, enc::write::Writer};
use embedded_io::Read;
use libectf::{decode_from_vec, frame::{EncodedFramePacketHeader, Frame, NUM_ENCRYPTED_FRAMES}, subscription::{EncodedSubscriptionKey, SubscriptionData}, BINCODE_CONFIG};
use max7800x_hal::{pac, uart::BuiltUartPeripheral};
use sha2::{Digest, Sha256};

use super::{body_rw::BodyRW, packet::{MessageHeader, Opcode, Packet, MAGIC}};

/// A decoded frame, along with the header of the encoded frame it came from.
pub struct DecodedFrame {
    #[allow(dead_code)]  // TODO do we need this or is just a waste of memory?
    pub header: EncodedFramePacketHeader,
    pub frame: Frame
}

/// The result of [`RawRW::read_packet`], which can either be a packet, a decoded frame, a frame
/// decode error, or an unexpected packet.
pub enum ReadResult {
    Packet(Packet),
    DecodedFrame(DecodedFrame),
    FrameDecodeError,
    UnexpectedPacket
}

/// A wrapper struct for [`BuiltUartPeripheral`] that implements [`Reader`] and
/// [`Writer`] so that [`bincode`] can be used to read and write data to UART.
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

    /// Reads a packet header.
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

    /// Writes an ACK.
    fn write_ack(&mut self) {
        self.write_header(Opcode::ACK, 0);
    }

    /// Writes a packet header.
    fn write_header(&mut self, opcode: Opcode, length: u16) {
        let header = MessageHeader {
            magic: MAGIC,
            opcode,
            length,
        };
        
        // TODO error handling!
        bincode::encode_into_writer(header, self, BINCODE_CONFIG).unwrap();
    }

    /// Writes a packet, using [`BodyRW`] to properly send the body.
    fn write_packet(&mut self, msg: &Packet) {
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

    /// Reads a packet. When an encoded frame is recieved, it will attempt to get a valid key for
    /// that subscription using [`get_key`] and if the decode fails or a key is not found, it will
    /// return a [`ReadResult::FrameDecodeError`]. If a packet is recieved that the decoder
    /// shouldn't have to handle, a [`ReadResult::UnexpectedPacket`] is returned.
    fn read_packet<'l, F: FnOnce(&EncodedFramePacketHeader) -> Option<&'l EncodedSubscriptionKey>>(&mut self, get_key: F, most_recent_timestamp: &mut Option<u64>) -> ReadResult {
        let header = self.read_header();

        if header.opcode.should_ack() {
            self.write_ack();
        }

        let mut read_buf: Vec<u8> = vec![0; header.length as usize];

        let mut remaining = read_buf.as_mut_slice();
        while !remaining.is_empty() {
            let (chunk, rest) = remaining.split_at_mut(256.min(remaining.len()));
            self.read(chunk).unwrap();
            self.write_ack();
            remaining = rest;
        }

        if header.length == 0 {
            match header.opcode {
                Opcode::LIST => { ReadResult::Packet(Packet::ListCommand) },
                _ => { ReadResult::UnexpectedPacket }
            }
        } else {
            let res = match header.opcode {
                Opcode::DECODE => { 
                    let header = decode_from_vec(&mut read_buf);
                    let key = get_key(&header);

                    let mut frame: Option<Frame> = None;

                    if let Some(key) = key {
                        for idx in 0..NUM_ENCRYPTED_FRAMES {
                            let f: Frame = decode_from_vec(&mut read_buf);
                            if idx == key.mask_idx as usize {
                                frame = Some(f);
                            }
                        }
                        
                        if let Some(f) = frame.as_mut() {
                            key.key.cipher().decode_frame(f);
                        }
                    } else {
                        // Throw all frames away
                        for _ in 0..NUM_ENCRYPTED_FRAMES {
                            let _: Frame = decode_from_vec(&mut read_buf);
                        }
                    }

                    // Makes sure timestamp is valid and globally increasing
                    if most_recent_timestamp.map(|t| header.timestamp <= t).unwrap_or(false) {
                        ReadResult::FrameDecodeError
                    } else {
                        // Make sure the hash of our frame data equals the mac_hash in the packet header
                        if let Some(frame) = frame {
                            let mut hasher: Sha256 = Digest::new();
                            hasher.update(frame.0);
                            if <[u8; 32]>::from(hasher.finalize())[..16] == header.mac_hash {
                                *most_recent_timestamp = Some(header.timestamp);
                                ReadResult::DecodedFrame(DecodedFrame { header, frame })
                            } else {
                                ReadResult::FrameDecodeError
                            }
                        } else {
                            ReadResult::FrameDecodeError
                        }
                    }
                }
                Opcode::SUBSCRIBE => { 
                    let _packet_len = header.length as usize;
                    let header = decode_from_vec(&mut read_buf);
                    let mut keys = Vec::new();

                    while !read_buf.is_empty() {
                        keys.push(decode_from_vec(&mut read_buf));
                    }

                    ReadResult::Packet(Packet::SubscriptionCommand(SubscriptionData { header, keys }))
                }
                _ => { return ReadResult::UnexpectedPacket; }
            };

            res
        }
    }
}
