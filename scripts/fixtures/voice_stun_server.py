#!/usr/bin/env python3
"""Loopback STUN responder для CLI-дифференциала d2kvoice/r2o-controller.

Режимы:
  reply  — отвечать на каждый Binding Request;
  flaky  — ответить только на первый;
  silent — не отвечать.

Печатает фактический порт первой строкой и сбрасывает stdout.
"""
import socket
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else "reply"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1], flush=True)
sock.settimeout(10.0)
answered = 0
deadline = time.monotonic() + 9.0
while time.monotonic() < deadline:
    try:
        data, peer = sock.recvfrom(2048)
    except socket.timeout:
        break
    if len(data) < 20 or data[0:2] != b"\x00\x01":
        continue
    if mode == "silent":
        continue
    answered += 1
    if mode == "flaky" and answered > 1:
        continue
    txid = data[8:20]
    sock.sendto(b"\x01\x01\x00\x00\x21\x12\xa4\x42" + txid, peer)
sock.close()
