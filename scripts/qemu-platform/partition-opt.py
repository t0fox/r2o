#!/usr/bin/env python3
"""Place the Entware ext4 image inside the MBR partition nix-keenetic expects."""
import struct
import sys
from pathlib import Path

filesystem, disk = map(Path, sys.argv[1:])
sector_size = 512
first_sector = 2048
bytes_on_disk = filesystem.stat().st_size
assert bytes_on_disk % sector_size == 0 and filesystem != disk
entry = struct.pack('<B3sB3sII', 0, b'\0\x02\0', 0x83, b'\xfe\xff\xff',
                    first_sector, bytes_on_disk // sector_size)
with filesystem.open('rb') as fs, disk.open('wb') as image:
    image.write(bytes(446) + entry + bytes(48) + b'\x55\xaa')
    image.seek(first_sector * sector_size)
    while block := fs.read(1024 * 1024):
        if block.count(0) == len(block):
            image.seek(len(block), 1)
        else:
            image.write(block)
    image.truncate(first_sector * sector_size + bytes_on_disk)
