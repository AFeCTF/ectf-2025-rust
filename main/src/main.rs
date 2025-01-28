#![no_std]
#![no_main]

extern crate alloc;

use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use embedded_alloc::LlffHeap as Heap;
use libectf::packet::Packet;
use libectf::uart::read_from_wire;
use libectf::uart::write_to_wire;
use max7800x_hal as hal;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::addr_of_mut;

use embedded_io::Read as EIORead;
pub use hal::pac;
pub use hal::entry;

use hal::uart::BuiltUartPeripheral;

// pick a panicking behavior
use panic_halt as _; // you can put a breakpoint on `rust_begin_unwind` to catch panics
// use panic_abort as _; // requires nightly
// use panic_itm as _; // logs messages over ITM; requires ITM support
// use panic_semihosting as _; // logs messages to the host stderr; requires a debugger
// use cortex_m_semihosting::heprintln; // uncomment to use this for printing through semihosting

#[global_allocator]
static HEAP: Heap = Heap::empty();

struct UartRW<'a, UART: Deref<Target = pac::uart0::RegisterBlock>, RX, TX, CTS, RTS>(&'a mut BuiltUartPeripheral<UART, RX, TX, CTS, RTS>);

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

#[entry]
fn main() -> ! {
    {
        // I dont want heap overflow!!
        const HEAP_SIZE: usize = 32768;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE); }
    }

    let p = pac::Peripherals::take().unwrap();

    let mut gcr = hal::gcr::Gcr::new(p.gcr, p.lpgcr);
    let ipo = hal::gcr::clocks::Ipo::new(gcr.osc_guards.ipo).enable(&mut gcr.reg);
    let clks = gcr.sys_clk
        .set_source(&mut gcr.reg, &ipo)
        .set_divider::<hal::gcr::clocks::Div1>(&mut gcr.reg)
        .freeze();

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

    // write_to_wire(&Packet::Debug("Hello, World!".to_string()), &mut UartRW(&mut console));

    loop {
        let p = read_from_wire(true, &mut UartRW(&mut console)).unwrap();
        // write_to_wire(&Packet::Debug(format!("Received packet {:?}\n", p)), &mut UartRW(&mut console));

        match p {
            Packet::DecodeCommand(frame) => {
                write_to_wire(&Packet::DecodeResponse(frame.data[0]), &mut UartRW(&mut console));
            },
            Packet::SubscriptionCommand(data) => {

            }
            _ => {}
        }
    }
}
