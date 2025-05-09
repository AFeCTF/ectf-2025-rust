//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.
//! For many projects this is optional, as the linker always searches the
//! project root directory -- wherever `Cargo.toml` is. However, if you
//! are using a workspace or have a more complicated build setup, this
//! build script becomes required. Additionally, by requesting that
//! Cargo re-run the build script whenever `memory.x` is changed,
//! updating `memory.x` ensures a rebuild of the application with the
//! new memory settings.
//!
//! The build script also sets the linker flags to tell it which link script to use.

use std::{env, fs};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use libectf::key::Key;
use libectf::subscription::SubscriptionData;
use quote::quote;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::Keypair;

const DEFAULT_DECODER_ID: u32 = 0xdeadbeef;
const SECRETS_FILE: &str = "../../global.secrets";

fn main() -> anyhow::Result<()> {
    let decoder_id: u32 = match env::var("DECODER_ID") {
        Ok(s) => { 
            if s.starts_with("0x") {
                <u32>::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap_or(DEFAULT_DECODER_ID)
            } else {
                s.parse::<u32>().unwrap_or(DEFAULT_DECODER_ID)
            }     
        },
        Err(_) => { DEFAULT_DECODER_ID },
    };

    let secrets: Vec<u8> = fs::read(SECRETS_FILE)?;
    
    // Hash the secrets and take the first 4 bytes as the flash magic so that when we generate new
    // secrets it'll erase the old subscriptions
    let mut hasher: Sha256 = Digest::new();
    hasher.update(&secrets);
    let secrets_hash: [u8; 32] = hasher.finalize().into();
    let flash_magic: u32 = u32::from_le_bytes(secrets_hash[..4].try_into().unwrap());

    let decoder_key = Key::for_device(decoder_id, &secrets).0;

    let s = SubscriptionData::generate(&secrets, 0, u64::MAX, 0, None);

    let keys_code = s.keys.iter().map(|k| {
        let key = k.key.0;

        quote! { 
            ArchivedEncodedSubscriptionKey {
                key: ArchivedKey([#(#key),*])
            } 
        }
    });

    let verifying_key = SigningKey::<Sha256>::from_pkcs1_der(&secrets).unwrap().verifying_key().to_pkcs1_der().unwrap();
    let verifying_key_bytes = verifying_key.as_bytes();

    let code = quote! {
        #![allow(dead_code)]
        use libectf::key::{ArchivedKey, Key};
        use libectf::subscription::ArchivedEncodedSubscriptionKey;
        pub static DECODER_ID: u32 = #decoder_id;
        pub static DECODER_KEY: Key = Key([#(#decoder_key),*]);
        pub static CHANNEL_0_KEYS: &[ArchivedEncodedSubscriptionKey] = &[#(#keys_code),*];
        pub static VERIFYING_KEY: &[u8] = &[#(#verifying_key_bytes),*];
        pub static FLASH_MAGIC: u32 = #flash_magic;
    };

    let dest_path = Path::new("src/keys.rs");
    fs::write(dest_path, code.to_string()).expect("Failed to write keys.rs");

    // If we have new secrets we should rebuild
    println!("cargo:rerun-if-changed={}", SECRETS_FILE);

    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("../memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");

    // Specify linker arguments.

    // `--nmagic` is required if memory section addresses are not aligned to 0x10000,
    // for example the FLASH and RAM sections in your `memory.x`.
    // See https://github.com/rust-embedded/cortex-m-quickstart/pull/95
    println!("cargo:rustc-link-arg=--nmagic");

    // Set the linker script to the one provided by cortex-m-rt.
    println!("cargo:rustc-link-arg=-Tlink.x");

    // Optimizations
    println!("cargo:rustc-cfg=target_cpu=\"cortex-m4\"");
    println!("cargo:rustc-rustflags=-C target-feature=+vfp4,+dsp");

    Ok(())
}
