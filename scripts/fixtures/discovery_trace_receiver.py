#!/usr/bin/env python3
"""Loopback Discord Discovery responder/trace.

Печатает порт, затем по строке на датаграмму: len/ttl/hex. На каждый
74-байтный запрос отвечает валидным Discovery-ответом, эхо SSRC. В трассе
SSRC (байты 4..8) обнуляется, чтобы C/Rust можно было сравнить побайтово.
TTL снимается через IP_RECVTTL, если ядро поддерживает.
"""
import os
import socket
import struct
import sys
import time

IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IP_TTL = getattr(socket, "IP_TTL", 2)
DISCOVERY_REQUEST = bytes.fromhex("00010046")
IDLE_SECONDS = 0.5
EMPTY_SECONDS = float(os.environ.get("TRACE_EMPTY_SECONDS", "60"))
MAX_SECONDS = float(os.environ.get("TRACE_MAX_SECONDS", "90"))


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    except OSError:
        pass
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(IDLE_SECONDS)
    print(sock.getsockname()[1], flush=True)

    started = time.monotonic()
    last_packet = None
    answered = 0
    while time.monotonic() - started < MAX_SECONDS:
        try:
            data, ancillary, _flags, address = sock.recvmsg(2048, 256)
        except socket.timeout:
            now = time.monotonic()
            if last_packet is not None and now - last_packet >= IDLE_SECONDS:
                break
            if last_packet is None and now - started >= EMPTY_SECONDS:
                break
            continue
        ttl = None
        for level, kind, payload in ancillary:
            if level == socket.IPPROTO_IP and kind == IP_TTL and len(payload) >= 4:
                ttl = struct.unpack("i", payload[:4])[0]
        if len(data) == 74 and data[:4] == DISCOVERY_REQUEST:
            response = bytearray(74)
            response[0:4] = bytes([0, 2, 0, 70])
            response[4:8] = data[4:8]
            response[8:19] = b"203.0.113.7"
            response[19] = 0
            response[72:74] = (50_001).to_bytes(2, "big")
            sock.sendto(response, address)
            answered += 1
            data = data[:4] + b"\x00" * 4 + data[8:]
        print(
            f"len={len(data)} ttl={'-' if ttl is None else ttl} data={data.hex()}",
            flush=True,
        )
        last_packet = time.monotonic()
    sock.close()
    return 0 if answered <= 25 else 1


if __name__ == "__main__":
    sys.exit(main())
