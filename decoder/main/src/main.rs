#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use embedded_alloc::LlffHeap as Heap;
use keys::{CHANNEL_0_KEYS, DECODER_KEY, VERIFYING_KEY};
use libectf::frame::{ArchivedEncodedFramePacket, EncodedFramePacketHeader, Frame};
use libectf::subscription::{ArchivedEncodedSubscriptionKey, ArchivedSubscriptionDataHeader};
use max7800x_hal::gcr::ClockForPeripheral;
use max7800x_hal::pac::Uart0;
use max7800x_hal as hal;
use rkyv::{access_unchecked, access_unchecked_mut};
use rkyv::util::AlignedVec;
use rsa::signature::Verifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use uart::body_rw::BodyRW;
use uart::packet::Opcode;
use uart::raw_rw::RawRW;
use core::mem::{self, MaybeUninit};
use core::ptr::slice_from_raw_parts_mut;
use core::u64;

pub use hal::pac;
pub use hal::entry;

// pick a panicking behavior
use panic_halt as _; // you can put a breakpoint on `rust_begin_unwind` to catch panics
// use panic_abort as _; // requires nightly
// use panic_itm as _; // logs messages over ITM; requires ITM support
// use panic_semihosting as _; // logs messages to the host stderr; requires a debugger
// use cortex_m_semihosting::heprintln; // uncomment to use this for printing through semihosting

mod uart;
mod keys;

#[global_allocator]
static HEAP: Heap = Heap::empty();
const HEAP_SIZE: usize = 32768*3;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

static mut UART0: Option<Uart0> = None;

fn access_subscription(packet: &mut AlignedVec) -> (&ArchivedSubscriptionDataHeader, &mut [ArchivedEncodedSubscriptionKey]) {
    // Split the header off of the packet
    let header_size = mem::size_of::<ArchivedSubscriptionDataHeader>();
    let key_size = mem::size_of::<ArchivedEncodedSubscriptionKey>();
    let (subscription_header_bytes, remaining) = packet.as_mut_slice().split_at_mut(header_size);
    let subscription_header: &ArchivedSubscriptionDataHeader = unsafe { access_unchecked(subscription_header_bytes) };
    
    // Cast the keys that are stored inline
    // Safety: The alignment of the encoded keys is 1 since we just store a bunch
    // of u8s
    let subscription_keys: &mut [ArchivedEncodedSubscriptionKey] = unsafe {
        &mut *slice_from_raw_parts_mut(
            remaining.as_ptr() as *mut ArchivedEncodedSubscriptionKey,
            remaining.len() / key_size
        )
    };

    (subscription_header, subscription_keys)
}

#[entry]
fn main() -> ! {
    // Initialize the Heap
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE); }

    let mut p = pac::Peripherals::take().unwrap();
    let mut _cp = cortex_m::Peripherals::take().unwrap();

    unsafe { p.dma.enable_clock(&mut p.gcr); }

    // Bad practice is an understatement
    #[allow(static_mut_refs)]
    let uart0 = unsafe { UART0 = Some(p.uart0); UART0.as_mut().unwrap_unchecked() };

    // Initialize clock
    let mut gcr = hal::gcr::Gcr::new(p.gcr, p.lpgcr);
    let ipo = hal::gcr::clocks::Ipo::new(gcr.osc_guards.ipo).enable(&mut gcr.reg);
    let clks = gcr.sys_clk
        .set_source(&mut gcr.reg, &ipo)
        .set_divider::<hal::gcr::clocks::Div1>(&mut gcr.reg)
        .freeze();

    // Initialize GPIO for UART
    let gpio0_pins = hal::gpio::Gpio0::new(p.gpio0, &mut gcr.reg).split();

    // Configure UART to host computer with 115200 8N1 settings
    let rx_pin = gpio0_pins.p0_0.into_af1();
    let tx_pin = gpio0_pins.p0_1.into_af1();
    let mut rw = hal::uart::UartPeripheral::uart0(
        unsafe { mem::transmute_copy(uart0) },
        &mut gcr.reg,
        rx_pin,
        tx_pin
    )
        .baud(115200)
        .clock_pclk(&clks.pclk)
        .parity(hal::uart::ParityBit::None)
        .build();

    let mut subscriptions: Vec<AlignedVec> = Vec::new();

    let mut most_recent_timestamp: Option<u64> = None;

    let verifying_key = VerifyingKey::<Sha256>::from_pkcs1_der(VERIFYING_KEY).unwrap();
    
    loop {
        let header = rw.read_header();

        if header.opcode.should_ack() {
            rw.write_ack();
        }

        if header.length == 0 {
            match header.opcode {
                Opcode::LIST => { 
                    let mut res: Vec<u8> = Vec::new();

                    res.extend_from_slice(&(subscriptions.len() as u32).to_le_bytes());

                    for subscription in &mut subscriptions {
                        let (subscription_header, _) = access_subscription(subscription);
                        res.extend_from_slice(&subscription_header.channel.to_native().to_le_bytes());
                        res.extend_from_slice(&subscription_header.start_timestamp.to_native().to_le_bytes());
                        res.extend_from_slice(&subscription_header.end_timestamp.to_native().to_le_bytes());
                    }

                    rw.write_header(Opcode::LIST, res.len() as u16);
                    let mut body_rw = BodyRW::new(header.opcode.should_ack(), &mut rw, None);
                    body_rw.write_bytes(&res);
                    body_rw.finish_write();
                },
                _ => { 
                    // TODO undefined behavior, no other zero-length commands
                }
            }
        } else {
            let mut body_rw = BodyRW::new(header.opcode.should_ack(), &mut rw, Some(p.dma.ch(0)));
            let mut packet = body_rw.start_dma_read(header.length as usize);

            match header.opcode {
                Opcode::SUBSCRIBE => {
                    let header_size = mem::size_of::<ArchivedSubscriptionDataHeader>();
                    let key_size = mem::size_of::<ArchivedEncodedSubscriptionKey>();
                    let (subscription_header, subscription_keys) = access_subscription(&mut packet);
                    let mut hasher: Sha256 = Digest::new();
                     
                    // Wait till we have a valid header
                    while body_rw.dma_poll_for_ack() < header_size { }
                     
                    hasher.update(subscription_header.start_timestamp.to_native().to_le_bytes());
                    hasher.update(subscription_header.end_timestamp.to_native().to_le_bytes());
                    hasher.update(subscription_header.channel.to_native().to_le_bytes());

                    let mut cipher = DECODER_KEY.cipher();

                    for (i, k) in subscription_keys.iter_mut().enumerate() {
                        // Wait till we have valid key
                        while body_rw.dma_poll_for_ack() < header_size + (i + 1) * key_size { }
                        // body_rw.rw.write_debug(&format!("{:?}", k));
                        cipher.decrypt(&mut k.key.0);
                        hasher.update(k.key.0);
                    }

                    if <[u8; 32]>::from(hasher.finalize()) != subscription_header.mac_hash {
                        rw.write_error("Authentication Failed");
                    } else {
                        subscriptions.push(packet);
                        rw.write_header(Opcode::SUBSCRIBE, 0);
                    }
                }
                Opcode::DECODE => {
                    let header_size = mem::size_of::<EncodedFramePacketHeader>();
                    let frame_size = mem::size_of::<Frame>();
                    let encoded_frame = unsafe { access_unchecked_mut::<ArchivedEncodedFramePacket>(&mut packet) };

                    let mut key = None;

                    // Wait for header
                    while body_rw.dma_poll_for_ack() < header_size { }

                    if encoded_frame.header.channel != 0 {
                        for subscription in &mut subscriptions {
                            let (subscription_header, subscription_keys) = access_subscription(subscription);
                            key = subscription_header.key_for_frame(&encoded_frame.header, subscription_keys);
                            if key.is_some() { break; }
                        }
                    } else {
                        // Dummy header so we can use the same subscription key for frame code
                        let subscription_header = ArchivedSubscriptionDataHeader {
                            start_timestamp: 0.into(),
                            end_timestamp: u64::MAX.into(),
                            channel: 0.into(),
                            mac_hash: [0; 32]
                        };

                        key = subscription_header.key_for_frame(&encoded_frame.header, CHANNEL_0_KEYS);
                    }

                    if let Some((key, mask_idx)) = key {
                        while body_rw.dma_poll_for_ack() < header_size + (mask_idx as usize + 1) * frame_size { }
                        let mut f = encoded_frame.data[mask_idx as usize].0;
                        key.key.cipher().decode_frame(&mut f);

                        // Makes sure timestamp is valid and globally increasing
                        if false {
                        // if most_recent_timestamp.map(|t| encoded_frame.header.timestamp <= t).unwrap_or(false) {
                            // Wait for whole frame to be transferred
                            while body_rw.dma_poll_for_ack() < header.length as usize { }

                            rw.write_error("Frame is from the past");
                        } else {
                            // Make sure the hash of our frame data equals the mac_hash in the packet header
                            let signature = Signature::try_from(encoded_frame.header.signature.as_slice()).unwrap();
                            if verifying_key.verify(&f, &signature).is_ok() {
                                most_recent_timestamp = Some(encoded_frame.header.timestamp.to_native());

                                // Wait for whole frame to be transferred
                                while body_rw.dma_poll_for_ack() < header.length as usize { }

                                // Write decode response
                                rw.write_header(Opcode::DECODE, f.len() as u16);
                                rw.write_bytes(&f);
                            } else {
                                // Wait for whole frame to be transferred
                                while body_rw.dma_poll_for_ack() < header.length as usize { }

                                rw.write_error("Frame validation failed");
                            }
                        }
                    } else {
                        // Wait for whole frame to be transferred
                        while body_rw.dma_poll_for_ack() < header.length as usize { }

                        rw.write_error("No frame for subscription");
                    }
                }
                _ => {
                    // TODO undefined behavior
                }
            }
        }
    }
}

