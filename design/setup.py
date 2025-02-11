from setuptools import setup
import glob
import os
import sys

# Get Python version and platform
PY_VERSIONS = [f"cp{sys.version_info.major}{i}" for i in range(1, sys.version_info.minor+1)]  # Example: "cp311"
PLATFORM_TAG = {
    "linux": "manylinux",
    "darwin": "macosx",
    "win32": "win_amd64"
}.get(sys.platform, "unknown")

if PLATFORM_TAG == "unknown":
    raise RuntimeError(f"Unsupported platform: {sys.platform}")

# Locate wheel files
WHEEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../ectf25_design_rs/wheels"))
whl_candidates = glob.glob(os.path.join(WHEEL_DIR, "ectf25_design_rs-*.whl"))

# Find a wheel that matches the current Python version and platform
valid_wheel = None
for whl in whl_candidates:
    for PY_VERSION in PY_VERSIONS:
        if PY_VERSION in whl and PLATFORM_TAG in whl:
            valid_wheel = whl
            break  # Stop at the first compatible match

if not valid_wheel:
    raise FileNotFoundError(f"No compatible wheel found in {WHEEL_DIR} for {PY_VERSION} on {PLATFORM_TAG}")

setup(
    name="ectf25_design",
    version="2025.0+example",
    install_requires=[
        "loguru",
        f"ectf25_design_rs @ file://{valid_wheel}"
    ],
)
