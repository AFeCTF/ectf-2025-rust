#![feature(inherent_str_constructors)]

#![cfg_attr(not(test), no_std)]

#[cfg(test)] extern crate std;
#[cfg(test)] #[allow(unused_imports)] use std::prelude::*;

extern crate alloc;
pub mod masks;
pub mod key;
pub mod frame;
pub mod subscription;

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::frame::Frame;

    #[test]
    fn test_encode() {
        let secrets = fs::read("../../global.secrets").unwrap();

        let test_frame = Frame(*b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        let encoded_frame = test_frame.encode(12, 1, &secrets);

        println!("{:?}", encoded_frame);

        assert!(true == false);
    }
}
