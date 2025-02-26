use core::{mem, ptr::{slice_from_raw_parts, slice_from_raw_parts_mut}};

use alloc::vec::Vec;
use libectf::subscription::{ArchivedEncodedSubscriptionKey, ArchivedSubscriptionDataHeader};
use max7800x_hal::flc::{FlashError, Flc, FLASH_PAGE_SIZE};
use rkyv::util::AlignedVec;

use crate::keys::FLASH_MAGIC;

const START_ADDR: u32 = 0x1006_0000;  // Should be at the start of a page
const NUM_PAGES: u32 = 4;
const ALIGNMENT: u32 = 16;

pub struct StaticSubscription {
    pub header: &'static ArchivedSubscriptionDataHeader,
    pub keys: &'static [ArchivedEncodedSubscriptionKey]
}

pub struct MutSubscription {
    pub header: &'static ArchivedSubscriptionDataHeader,
    pub keys: &'static mut [ArchivedEncodedSubscriptionKey]
}

pub struct Flash {
    flc: Flc,
    subscriptions: Vec<StaticSubscription>,
    next_entry_addr: u32
}

impl Flash {
    pub fn new(flc: Flc) -> Result<Self, FlashError> {
        if flc.read_32(START_ADDR)? != FLASH_MAGIC {
            // Erase all pages
            let mut addr = START_ADDR;
            for _ in 0..NUM_PAGES {
                unsafe { flc.erase_page(addr)?; }
                addr += FLASH_PAGE_SIZE;
            }
            
            // Write magic to the start address
            flc.write_32(START_ADDR, FLASH_MAGIC)?;
        }

        let mut subscriptions = Vec::new();

        let mut addr = START_ADDR + 4;

        loop {
            // We want the length specifier to be right before our aligned vec
            addr = Self::addr_before_aligned(addr);

            Self::check_addr(addr)?;

            let len = flc.read_32(addr)?;
            
            // If the length specifier is blank (all 1s) we are done
            if len == 0xFFFFFFFF { break }

            addr += 4;
            Self::check_addr(addr + len)?;
            subscriptions.push(Self::access_subscription(addr, len));

            addr += len;
        }

        Ok(Self {
            flc,
            subscriptions,
            next_entry_addr: Self::addr_before_aligned(addr)
        })
    }

    pub fn subscriptions(&self) -> &Vec<StaticSubscription> {
        &self.subscriptions
    }

    pub fn add_subscription(&mut self, data: AlignedVec) -> Result<(), FlashError> {
        Self::check_addr(self.next_entry_addr + 4 + data.len() as u32)?;
        self.flc.write_32(self.next_entry_addr, data.len() as u32)?;

        self.next_entry_addr += 4;

        let entry_addr = self.next_entry_addr;

        for chunk in data.chunks(16) {
            let mut buf = [0xFFu8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            let buf = unsafe { &*(buf.as_ptr() as *const [u32; 4]) };
            self.flc.write_128(self.next_entry_addr, &buf)?;
            self.next_entry_addr += 16;
        }

        self.next_entry_addr = Self::addr_before_aligned(self.next_entry_addr);

        self.subscriptions.push(Self::access_subscription(entry_addr, data.len() as u32));

        Ok(())
    }

    #[inline]
    const fn addr_before_aligned(current: u32) -> u32 {
        (current & !(ALIGNMENT - 1)) + ALIGNMENT - 4
    }

    /// This MUST be called on a RAM address and not flash
    pub fn access_subscription_mut(packet: &mut AlignedVec) -> MutSubscription {
        let addr: usize = packet.as_ptr() as usize;
        let len: usize = packet.len();
        
        // Split the header off of the packet
        let header_size = mem::size_of::<ArchivedSubscriptionDataHeader>();
        let key_size = mem::size_of::<ArchivedEncodedSubscriptionKey>();

        let header: &'static ArchivedSubscriptionDataHeader = unsafe { &*(addr as *const ArchivedSubscriptionDataHeader) };
        
        // Cast the keys that are stored inline
        // Safety: The alignment of the encoded keys is 1 since we just store a bunch
        // of u8s
        let keys: &'static mut [ArchivedEncodedSubscriptionKey] = unsafe {
            &mut *slice_from_raw_parts_mut(
                (addr as usize + header_size) as *mut ArchivedEncodedSubscriptionKey,
                (len as usize - header_size) / key_size
            )
        };

        MutSubscription {
            header, keys
        }
    }

    fn access_subscription(addr: u32, len: u32) -> StaticSubscription {
        // Split the header off of the packet
        let header_size = mem::size_of::<ArchivedSubscriptionDataHeader>();
        let key_size = mem::size_of::<ArchivedEncodedSubscriptionKey>();

        let header: &'static ArchivedSubscriptionDataHeader = unsafe { &*(addr as *const ArchivedSubscriptionDataHeader) };
        
        // Cast the keys that are stored inline
        // Safety: The alignment of the encoded keys is 1 since we just store a bunch
        // of u8s
        let keys: &'static [ArchivedEncodedSubscriptionKey] = unsafe {
            &*slice_from_raw_parts(
                (addr as usize + header_size) as *const ArchivedEncodedSubscriptionKey,
                (len as usize - header_size) / key_size
            )
        };

        StaticSubscription {
            header, keys
        }
    }

    fn check_addr(addr: u32) -> Result<(), FlashError> {
        if addr > START_ADDR + NUM_PAGES * FLASH_PAGE_SIZE {
            Err(FlashError::InvalidAddress)
        } else {
            Ok(())
        }
    }
}
