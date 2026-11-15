#!/usr/bin/env python3
"""Нормализовать случайные поля IP-фрагментов в trace qp_send_fragmented.

IPv4 ID/header checksum и IPv6 fragment ID зависят от процесса; остальные
байты фрагментов обязаны совпадать C/Rust побайтно.
"""
import sys


def normalize(line: str) -> str:
    if not (
        line.startswith("dg|frag")
        and len(line) > 8
        and line[7].isdigit()
        and line[8] == "|"
    ):
        return line
    parts = line.rstrip("\n").split("|")
    index = next((i for i, part in enumerate(parts) if part.startswith("hex=")), None)
    if index is None:
        return line
    data = bytearray.fromhex(parts[index][4:])
    if data and data[0] >> 4 == 4:
        data[4:6] = b"\x00\x00"
        data[10:12] = b"\x00\x00"
    elif data and data[0] >> 4 == 6:
        data[4:8] = b"\x00\x00\x00\x00"
    parts[index] = "hex=" + data.hex()
    return "|".join(parts) + "\n"


for raw in sys.stdin:
    sys.stdout.write(normalize(raw))
