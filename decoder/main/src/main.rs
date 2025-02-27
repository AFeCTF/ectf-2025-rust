#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use embedded_alloc::LlffHeap as Heap;
use flash::Flash;
use keys::{CHANNEL_0_KEYS, DECODER_KEY, VERIFYING_KEY};
use libectf::frame::{ArchivedEncodedFramePacket, ArchivedEncodedFramePacketHeader};
use libectf::key::{ArchivedKey, Key};
use libectf::subscription::{ArchivedEncodedSubscriptionKey, ArchivedSubscriptionDataHeader};
use max7800x_hal::flc::Flc;
use max7800x_hal::gcr::ClockForPeripheral;
use max7800x_hal::pac::Uart0;
use max7800x_hal as hal;
use rkyv::access_unchecked_mut;
use rsa::signature::Verifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use uart::body_rw::BodyRW;
use uart::packet::Opcode;
use uart::raw_rw::RawRW;
use core::mem::{self, MaybeUninit};
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
mod flash;

#[global_allocator]
static HEAP: Heap = Heap::empty();
const HEAP_SIZE: usize = 0x10000;  // Half of our RAM
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

static mut UART0: Option<Uart0> = None;

#[entry]
fn main() -> ! {
    // Initialize the Heap
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE); }

    let mut p = pac::Peripherals::take().unwrap();

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

    let mut flash = Flash::new(Flc::new(p.flc, clks.sys_clk));

    // Init flash during startup (no debug messages)
    let mut flash_init = true;
    flash.init(&mut rw).unwrap();

    // Init flash on first command
    // let mut flash_init = false;

    let mut most_recent_timestamp: Option<u64> = None;

    let verifying_key = VerifyingKey::<Sha256>::from_pkcs1_der(VERIFYING_KEY).unwrap();
    
    loop {
        let header = rw.read_header();

        if header.opcode.should_ack() {
            rw.write_ack();
        }

        if !flash_init { 
            match flash.init(&mut rw) {
                Ok(_) => {},
                Err(e) => { rw.write_error(&format!("Flash Error: {:?}", e)); },
            }
            flash_init = true;
        }

        if header.length == 0 {
            match header.opcode {
                Opcode::LIST => { 
                    let mut res: Vec<u8> = Vec::new();

                    let subscriptions = flash.subscriptions();

                    res.extend_from_slice(&(subscriptions.len() as u32).to_le_bytes());

                    for subscription in subscriptions {
                        res.extend_from_slice(&subscription.header.channel.to_native().to_le_bytes());
                        res.extend_from_slice(&subscription.header.start_timestamp.to_native().to_le_bytes());
                        res.extend_from_slice(&subscription.header.end_timestamp.to_native().to_le_bytes());
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
                    let subscription = Flash::access_subscription_mut(&mut packet);
                    let mut hasher: Sha256 = Digest::new();
                     
                    // Wait till we have a valid header
                    while body_rw.dma_poll_for_ack() < header_size { }
                     
                    hasher.update(subscription.header.start_timestamp.to_native().to_le_bytes());
                    hasher.update(subscription.header.end_timestamp.to_native().to_le_bytes());
                    hasher.update(subscription.header.channel.to_native().to_le_bytes());

                    let mut cipher = DECODER_KEY.cipher();

                    for (i, k) in subscription.keys.iter_mut().enumerate() {
                        // Wait till we have valid key
                        while body_rw.dma_poll_for_ack() < header_size + (i + 1) * key_size { }

                        // body_rw.rw.write_debug(&format!("{:?}", k));
                        cipher.decrypt(&mut k.key.0);
                        hasher.update(k.key.0);
                    }

                    if <[u8; 32]>::from(hasher.finalize()) != subscription.header.mac_hash {
                        rw.write_error("Authentication Failed");
                    } else {
                        match flash.add_subscription(packet, &mut rw) {
                            Ok(_) => {
                                rw.write_header(Opcode::SUBSCRIBE, 0);
                            },
                            Err(e) => {
                                rw.write_error(&format!("Flash Error {:?}", e));
                            },
                        }
                    }
                }
                Opcode::DECODE => {
                    if packet.len() != mem::size_of::<ArchivedEncodedFramePacket>() {
                        // Wait until the whole message is transferred
                        while body_rw.dma_poll_for_ack() < header.length as usize { }

                        rw.write_error("Unexpected frame packet size");
                    } else {
                        let header_size = mem::size_of::<ArchivedEncodedFramePacketHeader>();
                        let key_size = mem::size_of::<ArchivedKey>();
                        let encoded_frame = unsafe { access_unchecked_mut::<ArchivedEncodedFramePacket>(&mut packet) };

                        let mut key = None;

                        // Wait for header
                        while body_rw.dma_poll_for_ack() < header_size { }

                        if encoded_frame.header.channel != 0 {
                            for subscription in flash.subscriptions() {
                                key = subscription.header.key_for_frame(&encoded_frame.header, subscription.keys);
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
                            // Wait for the key to be transferred
                            while body_rw.dma_poll_for_ack() < header_size + (mask_idx as usize + 1) * key_size { }

                            let mut frame_key = encoded_frame.keys[mask_idx as usize].0;
                            key.key.cipher().decrypt(&mut frame_key);
                            let mut f = encoded_frame.header.frame.0;
                            Key(frame_key).cipher().decrypt(&mut f);

                            // Makes sure timestamp is valid and globally increasing
                            if most_recent_timestamp.map(|t| encoded_frame.header.timestamp <= t).unwrap_or(false) {
                                // Wait until the whole message is transferred
                                while body_rw.dma_poll_for_ack() < header.length as usize { }

                                rw.write_error("Frame is from the past");
                            } else {
                                // Make sure the hash of our frame data equals the mac_hash in the packet header
                                if let Ok(signature) = Signature::try_from(encoded_frame.header.signature.as_slice()) {
                                    if verifying_key.verify(&f, &signature).is_ok() {
                                        most_recent_timestamp = Some(encoded_frame.header.timestamp.to_native());

                                        // Wait until the whole message is transferred
                                        while body_rw.dma_poll_for_ack() < header.length as usize { }

                                        // Write decode response
                                        rw.write_header(Opcode::DECODE, f.len() as u16);
                                        rw.write_bytes(&f);
                                    } else {
                                        // Wait until the whole message is transferred
                                        while body_rw.dma_poll_for_ack() < header.length as usize { }

                                        rw.write_error("Frame validation failed");
                                    }
                                } else {
                                    // Wait until the whole message is transferred
                                    while body_rw.dma_poll_for_ack() < header.length as usize { }

                                    rw.write_error("Frame signature invalid");
                                }
                            }
                        } else {
                            // Wait until the whole message is transferred
                            while body_rw.dma_poll_for_ack() < header.length as usize { }

                            rw.write_error("No subscription for frame");
                        }
                    }
                }
                _ => {
                    // TODO undefined behavior
                }
            }
        }
    }
}

