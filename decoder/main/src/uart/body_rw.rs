use max7800x_hal::pac::dma;
use rkyv::util::AlignedVec;

use super::raw_rw::RawRW;

const ALIGNMENT: usize = 16;

/// A wrapper around a raw reader/writer that handles reading/writing the body of 
/// packets. This is needed because the encoder expects ACKs every 256 bytes.
pub struct BodyRW<'l, RW: RawRW> {
    pub rw: &'l mut RW,
    should_ack: bool,
    dma: &'l dma::Ch,
    cursor: usize,
    last_ack_write: usize,
    dma_read_length: usize,
}

impl<'l, RW: RawRW> BodyRW<'l, RW> {
    const CHUNK_SIZE: usize = 256;
    
    /// Creates a new BodyRW object.
    pub fn new(should_ack: bool, rw: &'l mut RW, dma: &'l dma::Ch) -> Self {
        Self { rw, should_ack, dma, cursor: 0, dma_read_length: 0, last_ack_write: 0 }
    }
    
    pub fn start_dma_read(&mut self, length: usize) -> AlignedVec<ALIGNMENT> {
        let mut res = AlignedVec::with_capacity(length);
        unsafe { res.set_len(length); }

        self.dma_read_length = length;
        self.last_ack_write = 0;

        // 1. Ensure DMA_CHn_CTRL.en, DMA_CHn_CTRL.rlden = 0, and DMA_CHn_STATUS.ctz_if = 0.
        self.dma.ctrl().modify(|_, w| w.en().clear_bit().rlden().clear_bit());
        self.dma.status().write(|w| w.ctz_if().clear_bit_by_one());

        // 2. If using memory for the destination of the DMA transfer, configure DMA_CHn_DST to the starting 
        // address of the destination in memory.
        self.dma.dst().write(|w| unsafe { w.bits(res.as_ptr() as u32) } );

        // 4. Write the number of bytes to transfer to the DMA_CHn_CNT register.
        self.dma.cnt().write(|w| unsafe { w.bits(length as u32) });

        // 5. Configure the following DMA_CHn_CTRL register fields in one or more instructions. Do not set DMA_CHn_CTRL.en
        // to 1 or DMA_CHn_CTRL.rlden to 1 in this step:
        self.dma.ctrl().modify(|_, w| unsafe { w
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
        self.dma.ctrl().modify(|_, w| w.en().set_bit());

        res
    }
    
    pub fn dma_poll_for_ack(&mut self) -> usize {
        let bytes_read = self.dma_read_length - self.dma.cnt().read().bits() as usize;
        if (bytes_read % Self::CHUNK_SIZE == 0 || bytes_read == self.dma_read_length) && bytes_read != self.last_ack_write {
            self.last_ack_write = bytes_read;
            self.rw.write_ack();
        }
        bytes_read
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.rw.write_u8(*byte);
            self.cursor += 1;
            if self.cursor % Self::CHUNK_SIZE == 0 {
                self.rw.wait_for_ack();
            }
        }
    }

    /// Recieve the final ACK once an entire packet has been transmitted.
    pub fn finish_write(&mut self) {
        if self.should_ack && self.cursor % Self::CHUNK_SIZE != 0 {
            self.rw.wait_for_ack();
        }
    }
}

