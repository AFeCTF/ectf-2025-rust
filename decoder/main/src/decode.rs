use core::mem;

use alloc::{format, string::{String, ToString}};
use libectf::{frame::{ArchivedEncodedFramePacket, ArchivedEncodedFramePacketHeader}, key::{ArchivedKey, Key}, subscription::ArchivedSubscriptionDataHeader};
use rkyv::{access_unchecked_mut, util::AlignedVec};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;

use crate::{flash::Flash, keys::CHANNEL_0_KEYS, uart::{body_rw::BodyRW, packet::{MessageHeader, Opcode}, raw_rw::RawRW}};

pub fn decode_frame<RW: RawRW>(header: &MessageHeader, mut packet: AlignedVec, verifying_key: &VerifyingKey<Sha256>, most_recent_timestamp: &mut Option<u64>, body_rw: &mut BodyRW<RW>, flash: &Flash) -> Result<(), String> {
    // All encoded frame packets have the same size
    if packet.len() != mem::size_of::<ArchivedEncodedFramePacket>() {
        return Err("Unexpected frame packet size".to_string());
    }

    let header_size = mem::size_of::<ArchivedEncodedFramePacketHeader>();
    let key_size = mem::size_of::<ArchivedKey>();

    // "cast" the AlignedVec to an encoded frame packet
    let encoded_frame = unsafe { access_unchecked_mut::<ArchivedEncodedFramePacket>(&mut packet) };

    // Wait for header
    while body_rw.dma_poll_for_ack() < header_size { }

    // Subscription key we will use to decrypt the frame key (if we have one)
    let mut key = None;

    if encoded_frame.header.channel != 0 {
        // Check each subscription in the flash for a key to decrypt our frame
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

    // Error if we don't have a key
    let (key, mask_idx) = key.ok_or("No subscription for frame".to_string())?;    

    // Wait for the key to be transferred
    while body_rw.dma_poll_for_ack() < header_size + (mask_idx as usize + 1) * key_size { }

    // Encrypted frame key
    let mut frame_key = encoded_frame.keys[mask_idx as usize].0;

    // Decrypt the frame key with our subscription key
    key.key.cipher().decrypt(&mut frame_key);

    // Decrypt the frame with our decrypted frame key
    let mut f = encoded_frame.header.frame.0;
    Key(frame_key).cipher().decrypt(&mut f);

    // Makes sure timestamp is valid and globally increasing
    if most_recent_timestamp.map(|t| encoded_frame.header.timestamp <= t).unwrap_or(false) {
        return Err("Frame is from the past".to_string());
    }

    // Parse the signature bytes from the frame header
    let signature = Signature::try_from(encoded_frame.header.signature.as_slice())
        .map_err(|e| format!("Signature invalid: {:?}", e))?;

    // Verify that the signature matches our decrypted frame
    if verifying_key.verify(&f, &signature).is_err() {
        return Err("Frame validation failed".to_string());
    }

    // Update the most recent timestamp now that we know the frame is valid
    *most_recent_timestamp = Some(encoded_frame.header.timestamp.to_native());

    // Wait until the whole message is transferred
    while body_rw.dma_poll_for_ack() < header.length as usize { }

    // Write decode response
    body_rw.rw.write_header(Opcode::DECODE, f.len() as u16);
    body_rw.write_bytes(&f);

    Ok(())
}
