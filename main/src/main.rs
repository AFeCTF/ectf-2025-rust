#![no_std]
#![no_main]

use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use embedded_alloc::LlffHeap as Heap;
use libectf::Opcode;
use libectf::BINCODE_CONFIG;
use max7800x_hal as hal;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::addr_of_mut;

use embedded_hal_nb::serial::Read;
use embedded_io::Read as EIORead;
use embedded_io::ReadReady;
use embedded_io::Write;
pub use hal::pac;
pub use hal::entry;

use hal::uart::BuiltUartPeripheral;
use libectf::write_to_wire;
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
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE); }
    }

    let mut rxbuf = [0u8; 1000];

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

    console.write_bytes(b"Writing test packet to the wire:\n");

    write_to_wire(&"Hello, World!", Opcode::DEBUG, &mut UartRW(&mut console));

    loop {
        if console.read_ready().unwrap_or(false) {
            if read_byte(&mut console) == b'%' {
                let opcode = read_byte(&mut console);
                let packet_len = u16::from_le_bytes([
                    read_byte(&mut console),
                    read_byte(&mut console),
                ]);
                // TODO abort read if packet is too big
                // TODO possible vuln if the sent packet was incomplete the rxbuf could be leaked,
                // we might want to zero it out before deserialization. This should be mitigated by
                // the read_exact function blocking until the entire buffer is filled. This might
                // not be desired behavior in the future though so we must tread carefully.
                let slice = &mut rxbuf[0..packet_len as usize];
                console.read_exact(slice).unwrap();
                // TODO handle if bytes decoded differs from packet length
                let (p, _bytes_decoded): ((u32, u32), _) = bincode::decode_from_slice(slice, BINCODE_CONFIG).unwrap();
                // TODO better error handling with this because we are probably gonna get invalid
                // packets
                console.write_fmt(format_args!("Recieved packet type {} with length {}: {:?}\n", opcode, packet_len, p)).unwrap();
            }
        }
    }
}

fn read_byte<T: Read>(console: &mut T) -> u8 {
    Read::read(console).unwrap()
}
