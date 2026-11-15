#!/usr/bin/env python3
"""Loopback-приёмник datagram-трассы voice send_one/voice_ask.

Печатает порт, затем по строке на датаграмму: len/ttl/hex. У STUN Binding
Request обнуляет txid (байты 8..20), чтобы сравнение C/Rust не зависело от
случайного идентификатора транзакции. TTL снимается через IP_RECVTTL, если
ядро поддерживает; иначе печатается `-`.
"""
import os
import socket
import struct
import sys
import time

IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IP_TTL = getattr(socket, "IP_TTL", 2)
STUN_HEADER = bytes.fromhex("000100002112a442")
IDLE_SECONDS = 0.5
MAX_SECONDS = float(os.environ.get("TRACE_MAX_SECONDS", "60"))


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
    seen = False
    while time.monotonic() - started < MAX_SECONDS:
        try:
            data, ancillary, _flags, _address = sock.recvmsg(2048, 256)
        except socket.timeout:
            if seen:
                break
            continue
        ttl = None
        for level, kind, payload in ancillary:
            if level == socket.IPPROTO_IP and kind == IP_TTL and len(payload) >= 4:
                ttl = struct.unpack("i", payload[:4])[0]
        if len(data) >= 20 and data[:8] == STUN_HEADER:
            data = data[:8] + b"\x00" * 12 + data[20:]
        print(
            f"len={len(data)} ttl={'-' if ttl is None else ttl} data={data.hex()}",
            flush=True,
        )
        seen = True
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
