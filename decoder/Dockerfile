FROM rust:latest

WORKDIR /decoder/main

RUN apt-get update && apt-get install -y binutils-arm-none-eabi && rm -rf /var/lib/apt/lists/*

RUN rustup +nightly target add thumbv7em-none-eabihf

CMD cargo +nightly build --release ; arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabihf/debug/main /out/max78000.bin
