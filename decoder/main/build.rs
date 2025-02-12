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

use std::{env, fs, io};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use libectf::key::Key;
use quote::quote;

const DEFAULT_DECODER_ID: u32 = 0xdeadbeef;
const SECRETS_PATH: &str = "../../secrets";

fn main() -> anyhow::Result<()> {
    let decoder_id: u32 = match env::var("DECODER_ID") {
        Ok(s) => { s.parse().unwrap_or(DEFAULT_DECODER_ID) },
        Err(_) => { DEFAULT_DECODER_ID },
    };

    let secrets_file = fs::read_dir(SECRETS_PATH)?
        .filter_map(Result::ok)
        .find(|e| e.path().is_file())
        .ok_or(io::Error::new(io::ErrorKind::NotFound, "Secrets file not found"))?;

    let secrets: Vec<u8> = fs::read(secrets_file.path())?;

    let decoder_key = Key::for_device(decoder_id, &secrets).0;

    let code = quote! {
        #![allow(dead_code)]
        use libectf::key::Key;
        pub static DECODER_ID: u32 = #decoder_id;
        pub static DECODER_KEY: Key = Key([#(#decoder_key),*]);
    };

    let dest_path = Path::new("src/keys.rs");
    fs::write(dest_path, code.to_string()).expect("Failed to write keys.rs");

    // If we have new secrets we should rebuild
    println!("cargo:rerun-if-changed={}", SECRETS_PATH);

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

    Ok(())
}
