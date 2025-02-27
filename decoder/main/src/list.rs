use alloc::vec::Vec;
use max7800x_hal::pac::dma::Ch;

use crate::{flash::Flash, uart::{body_rw::BodyRW, packet::{MessageHeader, Opcode}, raw_rw::RawRW}};

pub fn list_subscriptions(header: &MessageHeader, rw: &mut impl RawRW, flash: &Flash, dma: &Ch) {
    let mut output: Vec<u8> = Vec::new();

    let subscriptions = flash.subscriptions();

    // 32-bit number of subscriptions
    output.extend_from_slice(&(subscriptions.len() as u32).to_le_bytes());

    // Add (channel_u32, start_timestamp_u64, end_timestamp_u64) for all
    // subscriptions
    for subscription in subscriptions {
        output.extend_from_slice(&subscription.header.channel.to_native().to_le_bytes());
        output.extend_from_slice(&subscription.header.start_timestamp.to_native().to_le_bytes());
        output.extend_from_slice(&subscription.header.end_timestamp.to_native().to_le_bytes());
    }

    // Write list packet header
    rw.write_header(Opcode::LIST, output.len() as u16);

    // Write list packet body
    let mut body_rw = BodyRW::new(header.opcode.should_ack(), rw, dma);
    body_rw.write_bytes(&output);
    body_rw.finish_write();
}
