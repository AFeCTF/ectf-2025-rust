use alloc::{string::String, vec::Vec};
use max7800x_hal::pac::dma;
use rkyv::{api::high::HighSerializer, ser::allocator::ArenaHandle, util::AlignedVec, Serialize};

use crate::UART0;

use super::raw_rw::RawRW;

const ALIGNMENT: usize = 16;

/// A wrapper around a raw reader/writer that handles reading/writing the body of 
/// packets. This is needed because the encoder expects ACKs every 256 bytes.
pub struct BodyRW<'l, RW: RawRW> {
    pub rw: &'l mut RW,
    should_ack: bool,
    dma: Option<&'l dma::Ch>,
    cursor: usize,
    last_ack_write: usize,
    dma_read_length: usize,
}

impl<'l, RW: RawRW> BodyRW<'l, RW> {
    const CHUNK_SIZE: usize = 256;
    
    /// Creates a new BodyRW object.
    pub fn new(should_ack: bool, rw: &'l mut RW, dma: Option<&'l dma::Ch>) -> Self {
        Self { rw, should_ack, dma, cursor: 0, dma_read_length: 0, last_ack_write: 0 }
    }
    
    pub fn start_dma_read(&mut self, length: usize) -> AlignedVec<ALIGNMENT> {
        let mut res = AlignedVec::with_capacity(length);
        unsafe { res.set_len(length); }

        self.dma_read_length = length;
        self.last_ack_write = 0;

        let uart0 = unsafe { UART0.as_mut().unwrap() };
        let dma = self.dma.unwrap();

        // 1. Ensure DMA_CHn_CTRL.en, DMA_CHn_CTRL.rlden = 0, and DMA_CHn_STATUS.ctz_if = 0.
        dma.ctrl().modify(|_, w| w.en().clear_bit().rlden().clear_bit());
        dma.status().write(|w| w.ctz_if().clear_bit_by_one());

        // 2. If using memory for the destination of the DMA transfer, configure DMA_CHn_DST to the starting 
        // address of the destination in memory.
        dma.dst().write(|w| unsafe { w.bits(res.as_ptr() as u32) } );

        // 4. Write the number of bytes to transfer to the DMA_CHn_CNT register.
        dma.cnt().write(|w| unsafe { w.bits(length as u32) });

        // 5. Configure the following DMA_CHn_CTRL register fields in one or more instructions. Do not set DMA_CHn_CTRL.en
        // to 1 or DMA_CHn_CTRL.rlden to 1 in this step:
        dma.ctrl().modify(|_, w| unsafe { w
            // 5a. Configure DMA_CHn_CTRL.request to select the transfer operation associated with the DMA channel.
            .request().uart0rx()
            
            // 5b. Configure DMA_CHn_CTRL.burst_size for the desired burst size.
            .burst_size().bits(0)  // 1 byte (TODO can we increase this?)

            // 5c. Configure DMA_CHn_CTRL.pri to set the channel priority relative to other DMA channels.
            .pri().set(0)

            // 5d. Configure DMA_CHn_CTRL.dstwd to set the width of the data written in each transaction.
            .dstwd().word()

            // 5e. If desired, set DMA_CHn_CTRL.dstinc to 1 to enable automatic incrementing of the DMA_CHn_DST register
            // upon every AHB transaction.
            .dstinc().set_bit()

            // 5f. Configure DMA_CHn_CTRL.srcwd to set the width of the data read in each transaction.
            .srcwd().word()

            // 5h. If desired, set DMA_CHn_CTRL.dis_ie = 1 to generate an interrupt when the channel becomes disabled. The
            // channel becomes disabled when the DMA transfer completes, or a bus error occurs.
            // TODO

            // 5i. If desired, set DMA_CHn_CTRL.ctz_ie 1 to generate an interrupt when the DMA_CHn_CNT register is
            // decremented to zero.
            // TODO

            // 5j. If using the reload feature, configure the reload registers to set the destination, source, and count for the
            // following DMA transaction.
            // 1) Load the DMA_CHn_SRCRLD register with the source address reload value.
            // 2) Load the DMA_CHn_DSTRLD register with the destination address reload value.
            // 3) Load the DMA_CHn_CNTRLD register with the count reload value.
            // Not using reload for now

            // 5k. If desired, enable the channel timeout feature described in Channel Timeout Detect. Clear
            // DMA_CHn_CTRL.to_clkdiv to 0 to disable the channel timeout feature.
            .to_clkdiv().set(0)
        });

        // 7. Set DMA_CHn_CTRL.en = 1 to start the DMA transfer immediately.
        dma.ctrl().modify(|_, w| w.en().set_bit());

        // Enable DMA from the UART side
        uart0.dma().modify(|_, w| unsafe { w
            .rx_en().set_bit()
            .rx_thd_val().bits(1)  // TODO is this right?
        });
        
        res
    }
    
    pub fn dma_poll_for_ack(&mut self) -> usize {
        let bytes_read = self.dma_read_length - self.dma.unwrap().cnt().read().bits() as usize;
        if (bytes_read % Self::CHUNK_SIZE == 0 || bytes_read == self.dma_read_length) && bytes_read != self.last_ack_write {
            self.last_ack_write = bytes_read;
            self.rw.write_ack();
        }
        bytes_read
    }

    pub fn reset_cursor(&mut self) {
        self.cursor = 0;
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.rw.write_u8(*byte);
            self.cursor += 1;
            if self.cursor % Self::CHUNK_SIZE == 0 {
                self.rw.wait_for_ack();
            }
        }
    }

    /// Writes encodable data, waiting for ACKs when required.
    pub fn write_body<E: rkyv::rancor::Source>(&mut self, body: &impl for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, E>>) {
        let res = rkyv::to_bytes(body).unwrap();
        self.write_bytes(&res);
    }

    /// Writes a vector of encodable data, this is equivalent to writing each element
    /// sequentially. NOTE: The length of the vector is stored nowhere, it is the 
    /// responsibility of the programmer to store it some other way and pass it to the
    /// [`read_vector_body`] function on the receiving end.
    pub fn write_vector_body<E: rkyv::rancor::Source>(&mut self, body: &Vec<impl for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, E>>>) {
        for entry in body {
            self.write_body(entry);
        }
    }

    /// Writes a string. NOTE: The length of the string is stored nowhere, it is the 
    /// responsibility of the programmer to store it some other way and pass it to the
    /// [`read_string_body`] function on the receiving end.
    pub fn write_string_body(&mut self, body: &String) {
        self.write_bytes(body.as_bytes());
    }

    // /// Reads encodable data, waiting for ACKs when required.
    // pub fn read_body<T: Decode>(&mut self) -> T {
    //     bincode::decode_from_reader(self, BINCODE_CONFIG).unwrap()
    // }

    // /// Reads a vector of decodable data. Until [`length`] bytes have been read.
    // pub fn read_vector_body<T: Decode>(&mut self, length: usize) -> Vec<T> {
    //     let mut res = Vec::new();

    //     while self.cursor < length {
    //         res.push(bincode::decode_from_reader(&mut *self, BINCODE_CONFIG).unwrap());
    //     }
    //     
    //     res
    // }

    // /// Reads a string. This is not used on the decoder so it is commented out.
    // // pub fn read_string_body(&mut self, length: usize) -> String {
    // //     let mut res: Vec<u8> = Vec::with_capacity(length);
    // //     self.read(res.as_mut_slice()).unwrap();
    // //     String::from_utf8_lossy(res.as_slice()).to_string()
    // // }

    /// Decodes a frame off the wire. This function is intended to be called once 
    /// the header of the encoded frame has already been read, and will read frames
    /// one at a time and decode the proper frame with [`key`] (if one is provided).
    // pub(super) fn decode_off_wire(&mut self, key: Option<&EncodedSubscriptionKey>) -> Option<Frame> {
    //     let mut res: Option<Frame> = None;

    //     if let Some(key) = key {
    //         for idx in 0..NUM_ENCRYPTED_FRAMES {
    //             let f: Frame = self.read_body();
    //             if idx == key.mask_idx as usize {
    //                 res = Some(f);
    //             }
    //         }
    //         
    //         if let Some(f) = res.as_mut() {
    //             key.key.cipher().decode_frame(f);
    //         }
    //     } else {
    //         // Throw all frames away
    //         for _ in 0..NUM_ENCRYPTED_FRAMES {
    //             let _: Frame = self.read_body();
    //         }
    //     }
    //     
    //     res
    // }

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

