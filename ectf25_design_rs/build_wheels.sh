source ../venv/bin/activate

# ARM Linux
docker run --platform linux/arm64 --rm -v $(pwd):/io -v $(pwd)/../libectf:/libectf ghcr.io/pyo3/maturin build --release -i python3.11 python3.12 python3.13

# x86_64 Linux
docker run --platform linux/amd64 --rm -v $(pwd):/io -v $(pwd)/../libectf:/libectf ghcr.io/pyo3/maturin build --release -i python3.11 python3.12 python3.13

# MacOS
CARGO_TARGET_DIR=target maturin build --release --target universal2-apple-darwin

# Windows (not working)
# CARGO_TARGET_DIR=target maturin build --release -i 3.9 --target x86_64-pc-windows-msvc

rm -rf wheels
cp -r target/wheels wheels
