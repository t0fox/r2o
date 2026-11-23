#!/usr/bin/env python3
"""Локальные HTTPS CONNECT и TLS origin для проверки прозрачного RT-прокси."""

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import signal
import ssl
import subprocess
import time


HOSTS = (
    "rutracker.org",
    "www.rutracker.org",
    "rutracker.wiki",
    "api.rutracker.cc",
    "rep.rutracker.cc",
    "static.rutracker.cc",
    "cloudflare-ech.com",
)


def prepare(state):
    state.mkdir(parents=True, exist_ok=True)
    cert = state / "origin-cert.pem"
    key = state / "origin-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj",
            "/CN=rutracker.org", "-addext",
            "subjectAltName=" + ",".join("DNS:" + host for host in HOSTS)
            + ",DNS:connect.r2o.test,DNS:localhost,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True, capture_output=True,
    )
    key.chmod(0o600)
    public_pem = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"]
    )
    public_der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_pem
    )
    upload = bytes(index % 251 for index in range(96 * 1024))
    download = bytes(250 - index % 251 for index in range(128 * 1024))
    (state / "upload.bin").write_bytes(upload)
    (state / "download.bin").write_bytes(download)
    return cert, key, upload, download, base64.b64encode(
        hashlib.sha256(public_der).digest()
    ).decode()


async def headers(reader):
    data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    if len(data) > 65536:
        raise ValueError("слишком большой HTTP-заголовок")
    lines = data.decode("ascii").split("\r\n")
    fields = {}
    for line in lines[1:]:
        if line:
            name, value = line.split(":", 1)
            fields[name.strip().lower()] = value.strip()
    return lines[0], fields


async def run(args):
    state = Path(args.state_dir).resolve()
    cert, key, upload, download, pin = prepare(state)
    events = (state / "events.jsonl").open("w", buffering=1)
    names = {}

    def record(kind, **fields):
        events.write(json.dumps({"time": time.time(), "kind": kind, **fields}) + "\n")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    context.set_servername_callback(lambda socket, name, _context: names.__setitem__(id(socket), name))

    async def close(writer):
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass

    async def origin(reader, writer):
        tls = writer.get_extra_info("ssl_object")
        sni = names.pop(id(tls), None)
        record("origin_tls", sni=sni, version=tls.version())
        try:
            while True:
                request, fields = await headers(reader)
                method, path, _version = request.split(" ", 2)
                length = int(fields.get("content-length", "0"))
                if not 0 <= length <= 4 * 1024 * 1024:
                    raise ValueError("недопустимая длина запроса")
                body = await asyncio.wait_for(reader.readexactly(length), 30)
                status = "200 OK"
                if path == "/forum/index.php":
                    reply = b"r2o-local-health\n" * 1024
                elif path == "/download":
                    reply = download
                elif path == "/exchange" and method == "POST":
                    reply = download
                    if body != upload:
                        status = "409 Conflict"
                else:
                    status, reply = "404 Not Found", b"unknown fixture path\n"
                keep = fields.get("connection", "").lower() == "keep-alive"
                digest = hashlib.sha256(body).hexdigest()
                record("origin_http", method=method, path=path, sni=sni,
                       upload_bytes=len(body), upload_sha256=digest,
                       download_bytes=len(reply), download_sha256=hashlib.sha256(reply).hexdigest(),
                       status=status, keep_alive=keep)
                response = (
                    f"HTTP/1.1 {status}\r\nContent-Length: {len(reply)}\r\n"
                    f"Content-Type: application/octet-stream\r\nX-Upload-SHA256: {digest}\r\n"
                    f"Connection: {'keep-alive' if keep else 'close'}\r\n\r\n"
                ).encode("ascii")
                writer.write(response + reply)
                await writer.drain()
                if not keep:
                    break
        except asyncio.IncompleteReadError:
            pass
        except Exception as error:
            record("origin_error", error=repr(error), sni=sni)
        finally:
            await close(writer)

    origin_server = await asyncio.start_server(
        origin, args.bind, args.origin_port, ssl=context, limit=65536
    )
    origin_port = origin_server.sockets[0].getsockname()[1]

    async def connect_proxy(reader, writer):
        remote = None
        target = None
        try:
            request, _fields = await headers(reader)
            method, target, _version = request.split(" ", 2)
            record("connect_request", target=target, method=method)
            # Публичные адреса никогда не открываются: разрешённые имена
            # направляются только на локальный контролируемый TLS origin.
            if method != "CONNECT" or target not in {host + ":443" for host in HOSTS}:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            origin_reader, remote = await asyncio.open_connection(args.bind, origin_port)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()

            async def pump(source, destination):
                count = 0
                while chunk := await source.read(32768):
                    destination.write(chunk)
                    await destination.drain()
                    count += len(chunk)
                if destination.can_write_eof():
                    destination.write_eof()
                else:
                    destination.close()
                return count

            sent, received = await asyncio.gather(
                pump(reader, remote), pump(origin_reader, writer)
            )
            record("connect_closed", target=target, to_origin_bytes=sent, from_origin_bytes=received)
        except Exception as error:
            record("connect_error", target=target, error=repr(error))
        finally:
            if remote is not None:
                await close(remote)
            await close(writer)

    proxy_server = await asyncio.start_server(
        connect_proxy, args.bind, args.proxy_port, ssl=context, limit=65536
    )
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    receipt = {
        "bind": args.bind, "proxy_port": proxy_port, "origin_port": origin_port,
        "certificate": str(cert), "health_spki_pin": pin,
        "upload_bytes": len(upload), "upload_sha256": hashlib.sha256(upload).hexdigest(),
        "download_bytes": len(download), "download_sha256": hashlib.sha256(download).hexdigest(),
        "note": "Полностью локальные TLS endpoints; настоящий ECH этим fixture не проверяется.",
    }
    (state / "ready.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(receipt, ensure_ascii=False), flush=True)
    stopped = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(signum, stopped.set)
    async with origin_server, proxy_server:
        await stopped.wait()
    record("fixture_stopped")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=24443)
    parser.add_argument("--origin-port", type=int, default=24444)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
