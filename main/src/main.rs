#![no_std]
#![no_main]

extern crate panic_semihosting;

use cortex_m_rt::entry;
#[allow(unused_imports)]
use panic_semihosting as _;

#[entry]
unsafe fn main() -> ! {
    loop { }
}