source ../venv/bin/activate

# ARM Linux
docker run --rm -v $(pwd):/io -v $(pwd)/../libectf:/libectf ghcr.io/pyo3/maturin build --release

# x86_64 Linux
docker run --platform linux/amd64 --rm -v $(pwd):/io -v $(pwd)/../libectf:/libectf ghcr.io/pyo3/maturin build --release

# MacOS
CARGO_TARGET_DIR=target maturin build --release --target universal2-apple-darwin

# Windows (not working)
# CARGO_TARGET_DIR=target maturin build --release -i 3.9 --target x86_64-pc-windows-msvc

rm -rf wheels
cp -r target/wheels wheels
