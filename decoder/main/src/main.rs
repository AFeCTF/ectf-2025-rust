#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use decode::decode_frame;
use embedded_alloc::LlffHeap as Heap;
use flash::Flash;
use keys::VERIFYING_KEY;
use list::list_subscriptions;
use max7800x_hal::flc::Flc;
use max7800x_hal::gcr::ClockForPeripheral;
use max7800x_hal as hal;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::VerifyingKey;
use sha2::Sha256;
use subscribe::add_subscription;
use uart::body_rw::BodyRW;
use uart::packet::Opcode;
use uart::raw_rw::RawRW;
use core::mem;
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
mod keys;
mod flash;
mod list;
mod subscribe;
mod decode;

#[global_allocator]
static HEAP: Heap = Heap::empty();
const HEAP_SIZE: usize = 0x10000;  // Half of our RAM
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[entry]
fn main() -> ! {
    // Initialize the Heap
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE); }

    let mut p = pac::Peripherals::take().unwrap();

    // Enable DMA
    unsafe { p.dma.enable_clock(&mut p.gcr); }
    let dma = p.dma.ch(0);

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
        unsafe { mem::transmute_copy(&p.uart0) },
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

    // PKCS1v15 Verifying key used to validate frame packets
    let verifying_key = VerifyingKey::<Sha256>::from_pkcs1_der(VERIFYING_KEY).unwrap();
    
    loop {
        // Disable UART DMA
        p.uart0.dma().modify(|_, w| w.rx_en().clear_bit());

        // Read header and ack if needed
        let header = rw.read_header();
        if header.opcode.should_ack() {
            rw.write_ack();
        }

        // Init flash if we haven't 
        if !flash_init { 
            if let Err(e) = flash.init(&mut rw) {
                rw.write_error(&format!("Flash Error: {:?}", e));
            }

            flash_init = true;
        }

        if header.length == 0 {
            match header.opcode {
                Opcode::LIST => { 
                    list_subscriptions(&header, &mut rw, &flash, &dma);
                },
                Opcode::ACK => {
                    // Do nothing when we get an ACK
                }
                _ => { 
                    // Undefined behavior, no other zero-length commands
                    rw.write_error("Unrecognized zero-length command");
                }
            }
        } else {
            // Enable DMA from the UART side
            p.uart0.dma().modify(|_, w| unsafe { w
                .rx_en().set_bit()
                .rx_thd_val().bits(1)
            });

            // Start reding packet body
            let mut body_rw = BodyRW::new(header.opcode.should_ack(), &mut rw, dma);
            let packet = body_rw.start_dma_read(header.length as usize);

            let result = match header.opcode {
                Opcode::SUBSCRIBE => {
                    add_subscription(packet, &mut body_rw, &mut flash)
                }
                Opcode::DECODE => {
                    decode_frame(&header, packet, &verifying_key, &mut most_recent_timestamp, &mut body_rw, &flash)
                }
                _ => {
                    Err("Unrecognized command".to_string())
                }
            };

            // If an error was generated, print it
            if let Err(e) = result {
                // Wait until the whole message is transferred
                while body_rw.dma_poll_for_ack() < header.length as usize { }

                rw.write_error(&e);
            }
        }
    }
}
