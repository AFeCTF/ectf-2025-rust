use core::mem;

use alloc::{format, string::{String, ToString}};
use libectf::subscription::{ArchivedEncodedSubscriptionKey, ArchivedSubscriptionDataHeader};
use rkyv::util::AlignedVec;
use sha2::{Digest, Sha256};

use crate::{flash::Flash, keys::DECODER_KEY, uart::{body_rw::BodyRW, packet::Opcode, raw_rw::RawRW}};

pub fn add_subscription<RW: RawRW>(mut packet: AlignedVec, body_rw: &mut BodyRW<RW>, flash: &mut Flash) -> Result<(), String> {
    let header_size = mem::size_of::<ArchivedSubscriptionDataHeader>();
    let key_size = mem::size_of::<ArchivedEncodedSubscriptionKey>();

    // "cast" the AlignedVec to subscription data
    let subscription = Flash::access_subscription_mut(&mut packet);

    // Initialize hasher to verify MAC
    let mut hasher: Sha256 = Digest::new();
     
    // Wait until header has been transferred by DMA
    while body_rw.dma_poll_for_ack() < header_size { }

    // Disallow channel 0 subscriptions
    if subscription.header.channel == 0 {
        return Err("Cannot subscribe to channel 0".to_string())
    } 

    // Hash the header components
    hasher.update(subscription.header.start_timestamp.to_native().to_le_bytes());
    hasher.update(subscription.header.end_timestamp.to_native().to_le_bytes());
    hasher.update(subscription.header.channel.to_native().to_le_bytes());

    // All subscription keys are encrypted with the decoder key
    let mut cipher = DECODER_KEY.cipher();

    for (i, k) in subscription.keys.iter_mut().enumerate() {
        // Wait till this key has been transferred by DMA
        while body_rw.dma_poll_for_ack() < header_size + (i + 1) * key_size { }

        // Decrypt the key in-place and then update the hasher with the decrypted key
        cipher.decrypt(&mut k.key.0);
        hasher.update(k.key.0);
    }

    // Ensure that the MAC matches what we got from the hasher
    if <[u8; 32]>::from(hasher.finalize()) != subscription.header.mac_hash {
        return Err("Authentication Failed".to_string());
    } 

    // Write subscription to the flash
    if let Err(e) = flash.add_subscription(packet, body_rw.rw) {
        return Err(format!("Flash error: {:?}", e));
    }

    // Respond
    body_rw.rw.write_header(Opcode::SUBSCRIBE, 0);

    Ok(())
}
