#!/usr/bin/env python3
"""Read the model-specific SquashFS out of a verified official KeeneticOS image."""
import argparse
import hashlib
import struct
import urllib.request
from pathlib import Path

MODELS = {
    "KN-1910": ("8386b5d97f5e7c2512435d32b6ae26d059763cc57ebcaafe312fc1905c6c56fb", 1966080),
    "KN-1913": ("7e1d0b17e5c05f89f912b1a6670aa02c50c3a9c6ad84e0ec05ba178a249531a2", 1835008),
    "KN-3810": ("d3faa5dd4da8f4029c9fe5df4428b1d82cf086dd55f5036575742d8a8eaff4d5", 1966080),
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("model", choices=MODELS)
parser.add_argument("destination", type=Path)
parser.add_argument("--firmware", type=Path, help="Use a previously downloaded official firmware")
args = parser.parse_args()
if args.firmware:
    firmware = args.firmware.read_bytes()
else:
    url = f"https://osvault.keenetic.net/{args.model}/5.01/{args.model}_stable_5.1.8_5.01.C.8.0-2.bin"
    with urllib.request.urlopen(url, timeout=90) as response:
        firmware = response.read(40 * 1024 * 1024)
digest, start = MODELS[args.model]
if hashlib.sha256(firmware).hexdigest() != digest:
    raise SystemExit(f"{args.model}: unexpected firmware SHA-256")
length = struct.unpack_from("<Q", firmware, start + 40)[0]
if firmware[start:start + 4] != b"hsqs" or not (96 < length <= len(firmware) - start):
    raise SystemExit(f"{args.model}: invalid firmware SquashFS bounds")
args.destination.write_bytes(firmware[start:start + length] + bytes(-length % 4096))
print(f"{args.model}: original SquashFS, {length} bytes at offset {start}")
