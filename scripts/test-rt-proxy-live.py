#!/usr/bin/env python3
"""Реальный TLS/CONNECT-прогон runtime без подмены его сетевых функций."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time


def wait_for(check, processes, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"процесс {process.args} завершился: {process.returncode}")
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError("ожидание локального слушателя или health-check истекло")


def read_text(path):
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--qemu")
    parser.add_argument("--qemu-cpu", default="24Kc")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture_dir = output / "fixture"
    fixture_path = Path(__file__).resolve().parent / "fixtures/rt_proxy_tls_lab.py"
    fixture_log = (output / "fixture.log").open("w")
    runtime_log = (output / "runtime.log").open("w")
    fixture = subprocess.Popen(
        [sys.executable, str(fixture_path), "--state-dir", str(fixture_dir),
         "--proxy-port", "0", "--origin-port", "0"],
        stdout=fixture_log, stderr=subprocess.STDOUT,
    )
    runtime = None
    first = None
    try:
        wait_for(lambda: (fixture_dir / "ready.json").exists(), [fixture])
        ready = json.loads((fixture_dir / "ready.json").read_text())
        health = output / "runtime.health"
        command = []
        if args.qemu:
            command = [str(Path(args.qemu).resolve()), "-cpu", args.qemu_cpu]
        command += [
            str(Path(args.binary).resolve()), "--rt-proxy", "--listen", "127.0.0.1:0",
            "--proxy-host", "127.0.0.1", "--proxy-port", str(ready["proxy_port"]),
            "--no-direct-fallback", "--health-spki-pin", ready["health_spki_pin"],
            "--health-file", str(health), "--health-interval", "1h",
            "--timeout", "30s", "--verbose",
        ]
        runtime = subprocess.Popen(command, stdout=runtime_log, stderr=subprocess.STDOUT)
        body = wait_for(lambda: read_text(health), [fixture, runtime])
        magic, pid, listen = body.split()
        assert magic == "R2ORT1" and int(pid) == runtime.pid, body
        host, port = listen.rsplit(":", 1)
        port = int(port)
        wait_for(
            lambda: "health: 1/1 upstream IP live" in read_text(output / "runtime.log"),
            [fixture, runtime],
        )

        # Первый HTTPS-сеанс остаётся живым после ответа, пока второй клиент
        # выполняет самостоятельные TLS handshake, upload и download.
        context = ssl.create_default_context(cafile=ready["certificate"])
        first = context.wrap_socket(socket.create_connection((host, port), timeout=15),
                                    server_hostname="rutracker.org")
        first.sendall(b"GET /download HTTP/1.1\r\nHost: rutracker.org\r\nConnection: keep-alive\r\n\r\n")
        reader = first.makefile("rb")
        assert reader.readline().startswith(b"HTTP/1.1 200 ")
        fields = {}
        while (line := reader.readline()) != b"\r\n":
            if not line:
                raise EOFError("незавершённые заголовки первого ответа")
            name, value = line.decode("ascii").split(":", 1)
            fields[name.lower()] = value.strip()
        first_body = reader.read(int(fields["content-length"]))
        assert hashlib.sha256(first_body).hexdigest() == ready["download_sha256"]
        assert fields["connection"] == "keep-alive"

        subprocess.run(
            ["curl", "-q", "--noproxy", "*", "--fail", "--show-error", "--silent", "--http1.1",
             "--max-time", "15", "--cacert", ready["certificate"], "--connect-to",
             f"rutracker.org:443:{host}:{port}", "--data-binary", "@" + str(fixture_dir / "upload.bin"),
             "-D", str(output / "client-headers.txt"), "-o", str(output / "client-download.bin"),
             "https://rutracker.org/exchange"],
            check=True, timeout=20,
        )
        received = (output / "client-download.bin").read_bytes()
        assert hashlib.sha256(received).hexdigest() == ready["download_sha256"]
        assert ready["upload_sha256"] in (output / "client-headers.txt").read_text()
        events = [json.loads(line) for line in (fixture_dir / "events.jsonl").read_text().splitlines()]
        exchanges = [event for event in events if event["kind"] == "origin_http"
                     and event["path"] == "/exchange"]
        assert len(exchanges) == 1
        assert exchanges[0]["upload_sha256"] == ready["upload_sha256"]
        assert exchanges[0]["download_sha256"] == ready["download_sha256"]
        assert exchanges[0]["sni"] == "rutracker.org"
        assert any(event["kind"] == "origin_http" and event["path"] == "/forum/index.php"
                   and event["download_bytes"] >= 8192 for event in events)
        reader.close()
        first.close()
        first = None
        runtime.terminate()
        assert runtime.wait(timeout=10) == 0
        assert not health.exists(), "SIGTERM должен убрать локальную готовность"
        result = {
            "passed": True,
            "scope": "process TLS/HTTPS CONNECT; NAT, DNS interception и fw3/fw4 этим прогоном не проверены",
            "command": command,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "tls_origin_certificate_verified_by_clients": True,
            "health_body_bytes_at_least": 8192,
            "keep_alive_does_not_block_second_client": True,
            "upload_bytes": ready["upload_bytes"], "upload_sha256": ready["upload_sha256"],
            "download_bytes": len(received), "download_sha256": ready["download_sha256"],
            "readiness_removed_on_sigterm": True,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(result, ensure_ascii=False))
    finally:
        if first is not None:
            first.close()
        if runtime is not None:
            stop(runtime)
        stop(fixture)
        fixture_log.close()
        runtime_log.close()


if __name__ == "__main__":
    main()
