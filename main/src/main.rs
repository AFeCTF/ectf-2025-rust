#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use embedded_alloc::LlffHeap as Heap;
use libectf::crypto::Key;
use libectf::packet::ChannelInfo;
use libectf::packet::EncodedFramePacketHeader;
use libectf::packet::SubscriptionData;
use max7800x_hal as hal;
use uart::rw::{RawRW, UartRW};
use uart::{Packet, ReadResult};
use core::mem::MaybeUninit;

pub use hal::pac;
pub use hal::entry;


// pick a panicking behavior
use panic_halt as _; // you can put a breakpoint on `rust_begin_unwind` to catch panics
// use panic_abort as _; // requires nightly
// use panic_itm as _; // logs messages over ITM; requires ITM support
// use panic_semihosting as _; // logs messages to the host stderr; requires a debugger
// use cortex_m_semihosting::heprintln; // uncomment to use this for printing through semihosting

mod uart;

#[global_allocator]
static HEAP: Heap = Heap::empty();
const HEAP_SIZE: usize = 32768*3;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[entry]
fn main() -> ! {
    // Initialize the Heap
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE); }

    let device_key: Key = Key([0; 8]);  // TODO

    let p = pac::Peripherals::take().unwrap();

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
    let mut console = hal::uart::UartPeripheral::uart0(
        p.uart0,
        &mut gcr.reg,
        rx_pin,
        tx_pin
    )
        .baud(115200)
        .clock_pclk(&clks.pclk)
        .parity(hal::uart::ParityBit::None)
        .build();

    // Subscriptions stored in the heap
    let mut subscriptions: Vec<SubscriptionData> = Vec::new();

    let mut rw = UartRW(&mut console);

    loop {
        // Read a packet from the wire. This function also handles frame decoding
        let p = rw.read_from_wire(|header: &EncodedFramePacketHeader| {
            for s in &subscriptions {
                if let Some(k) = s.key_for_frame(header) {
                    return Some(k);
                }
            }

            None
        });

        match p {
            ReadResult::DecodedFrame(frame) => {
                rw.write_to_wire(&Packet::DecodeResponse(frame.frame));
            }
            ReadResult::FrameDecodeError => {
                rw.write_to_wire(&Packet::Error("Frame Decode Error".to_string()));
            }
            ReadResult::Packet(Packet::SubscriptionCommand(mut data)) => {
                // write_to_wire(&Packet::Debug(format!("Got subscription data {:?} with {} keys", data.header, data.keys.len())), &mut UartRW(&mut console));

                if data.decrypt_and_authenticate(&device_key) {
                    rw.write_to_wire(&Packet::SubscriptionResponse);
                    subscriptions.push(data);
                } else {
                    rw.write_to_wire(&Packet::Error("Message Authentication Error".to_string()));
                }

            }
            ReadResult::Packet(Packet::ListCommand) => {
                let mut res = Vec::new();

                for s in &subscriptions {
                    res.push(ChannelInfo {
                        channel: s.header.channel,
                        start: s.header.start_timestamp,
                        end: s.header.end_timestamp
                    });
                }

                rw.write_to_wire(&Packet::ListResponse(res));
            }
            _ => {}
        }
    }
}

