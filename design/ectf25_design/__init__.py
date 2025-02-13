import importlib.util

spec = importlib.util.find_spec("ectf25_design_rs")

if spec is None or spec.loader is None:
    print("Installing Rust lib...")

    import glob
    import os
    import sys
    import platform
    import subprocess

    # Get Python version and platform
    PY_VERSION = f"cp{sys.version_info.major}{sys.version_info.minor}"
    SYSTEM_PLATFORM = sys.platform
    ARCH = platform.machine().lower()

    # Map to wheel tags
    PLATFORM_TAG = {
        "linux": f"manylinux_2_17_{ARCH}",
        "darwin": "macosx",
        "win32": "win_amd64" if ARCH in ["amd64", "x86_64"] else "win_arm64"
    }.get(SYSTEM_PLATFORM, "unknown")

    if PLATFORM_TAG == "unknown":
        raise RuntimeError(f"Unsupported platform: {SYSTEM_PLATFORM} ({ARCH})")

    # Locate wheel files
    WHEEL_DIR = os.path.abspath(os.path.join(os.getcwd(), "./ectf25_design_rs/wheels"))
    whl_candidates = glob.glob(os.path.join(WHEEL_DIR, "ectf25_design_rs-*.whl"))

    # Match Python version, platform, and architecture
    valid_wheel = None
    for whl in whl_candidates:
        if PY_VERSION in whl and PLATFORM_TAG in whl:
            valid_wheel = whl
            break

    if not valid_wheel:
        raise FileNotFoundError(f"No compatible wheel found in {WHEEL_DIR} for {PY_VERSION} on {PLATFORM_TAG}")

    # Force install the valid wheel
    subprocess.run([sys.executable, "-m" , "pip", "install", valid_wheel], check=True)
