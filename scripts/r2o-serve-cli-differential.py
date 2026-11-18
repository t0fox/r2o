#!/usr/bin/env python3
"""C/Rust differential: d2kc main — запуск, CLI и приветствие датапата.

Стенд поднимает Unix control-сокет и отвечает приветствием нужной версии
(22 для C-оракула, 48 для R2O по умолчанию). Сравниваются stdout/stderr/exit
и старт демона: пустой/битый каталог, нет сокета, битое приветствие, мягкая
остановка по SIGTERM. Долгий цикл измерений не входит в этот differential —
он покрыт профильными differential'ами планировщика/HTTP/HTTPS.
"""

import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

KEY_LEN = 38
EVENT_PROTOCOL = 0x000A


def frame(kind: int, body: bytes) -> bytes:
    return struct.pack(">IH", 2 + len(body), kind) + body


def greeting(version: int, release: str = "dev") -> bytes:
    body = (
        b"\x04"
        + b"\0" * (KEY_LEN - 1)
        + struct.pack(">HI", version, 4096)
        + bytes([len(release)])
        + release.encode()
    )
    return frame(EVENT_PROTOCOL, body)


def serve(path: str, ready, mode: str, version: int) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    ready.set()
    try:
        conn, _ = server.accept()
    except OSError:
        return
    with conn:
        if mode == "ok":
            conn.sendall(greeting(version))
            while conn.recv(4096):
                pass
        elif mode == "bad-version":
            conn.sendall(greeting(version + 1))
            time.sleep(0.3)
        elif mode == "bad-release":
            conn.sendall(greeting(version, "other"))
            time.sleep(0.3)
        elif mode == "silent":
            time.sleep(3.5)
    server.close()


class threading_event:
    def __init__(self) -> None:
        self.flag = False

    def set(self) -> None:
        self.flag = True

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.flag:
                return True
            time.sleep(0.01)
        return False


def run(command, path=None, mode="ok", version=48, stop_after=None, timeout=20):
    ready = threading_event()
    thread = None
    if path:
        thread = threading.Thread(
            target=serve, args=(path, ready, mode, version), daemon=True
        )
        thread.start()
        ready.wait(2)
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        if stop_after is not None:
            time.sleep(stop_after)
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=timeout)
        return process.returncode, out, err
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        if thread:
            thread.join(1)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def normalize(text: str) -> str:
    text = text.replace("d2kc: ", "CLI: ")
    text = text.replace("r2o-controller --serve: ", "CLI: ")
    text = text.replace("r2o-controller: ", "CLI: ")
    text = re.sub(r"^(?:d2kc|r2o-controller) release=", "CLI release=", text, flags=re.M)
    text = re.sub(r"/tmp/r2o-serve-[A-Za-z0-9_./-]+", "TMP", text)
    text = re.sub(r"wire=\d+", "wire=WIRE", text)
    text = re.sub(
        r"не разобрался: .*", "не разобрался: REASON", text
    )
    text = re.sub(
        r"нет корректного приветствия датапата: .*",
        "нет корректного приветствия датапата: REASON",
        text,
    )
    text = re.sub(
        r"несовместимое приветствие датапата, нужна версия \d+",
        "несовместимое приветствие датапата, нужна версия WIRE",
        text,
    )
    # CLI-форма d2kc (--control/--catalog) и R2O (--serve <сокет> <каталог>)
    # различаются архитектурно: сравниваем наличие usage и код 2, не текст.
    if "использование:" in text or "используйте `r2o-controller --help`" in text:
        text = "USAGE"
    # R2O печатает дополнительные строки загрузки/синхронизации каталога;
    # общие с C строки запуска/остановки и exit сравниваются как есть.
    lines = [
        line
        for line in text.splitlines()
        if not line.startswith("каталог загружен:")
        and not line.startswith("каталог синхронизирован:")
    ]
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def compare(name: str, c_result, r_result) -> bool:
    left = "rc={}\n--- stdout ---\n{}--- stderr ---\n{}".format(
        c_result[0], normalize(c_result[1]), normalize(c_result[2])
    )
    right = "rc={}\n--- stdout ---\n{}--- stderr ---\n{}".format(
        r_result[0], normalize(r_result[1]), normalize(r_result[2])
    )
    if left == right:
        print(f"PASS {name}")
        return True
    print(f"FAIL {name}")
    import difflib

    for line in difflib.unified_diff(
        left.splitlines(), right.splitlines(), "C", "Rust", lineterm=""
    ):
        print(line)
    return False


def main() -> int:
    donor = os.environ.get("R2O_DONOR_ROOT", "/mnt/e/d2o-current")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_bin = os.environ.get("R2O_SERVE_C", os.path.join(donor, "core", "d2kc"))
    r_bin = os.environ.get(
        "R2O_SERVE_RUST", os.path.join(root, "target/debug/r2o-controller")
    )
    tmp = tempfile.mkdtemp(prefix="r2o-serve-")
    missing = os.path.join(tmp, "missing.json")
    bad = os.path.join(tmp, "bad.json")
    with open(bad, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    health = os.path.join(tmp, "health")
    live = os.path.join(tmp, "live.json")
    https = os.path.join(tmp, "https-cache.txt")
    ok = True

    def c_args(sock, catalog=missing):
        return [
            c_bin,
            "--control",
            sock,
            "--catalog",
            catalog,
            "--health-file",
            health,
            "--live",
            live,
            "--https-cache",
            https,
        ]

    def r_args(sock, catalog=missing):
        return [r_bin, "--serve", sock, catalog, "--live", live]

    ok &= compare(
        "version", run([c_bin, "--version"]), run([r_bin, "--version"])
    )
    ok &= compare("no-args", run([c_bin]), run([r_bin, "--serve"]))
    ok &= compare(
        "unknown-arg",
        run([c_bin, "--bogus"]),
        run([r_bin, "--serve", os.path.join(tmp, "unused.sock"), missing, "--bogus"]),
    )
    ok &= compare(
        "bad-catalog",
        run(c_args(os.path.join(tmp, "unused.sock"), bad)),
        run(r_args(os.path.join(tmp, "unused.sock"), bad)),
    )

    sock = os.path.join(tmp, "missing.sock")
    ok &= compare(
        "missing-catalog-no-socket", run(c_args(sock)), run(r_args(sock))
    )

    for name, mode in (
        ("greeting-timeout", "silent"),
        ("bad-greeting-version", "bad-version"),
        ("bad-greeting-release", "bad-release"),
    ):
        c_sock = os.path.join(tmp, f"c-{name}.sock")
        r_sock = os.path.join(tmp, f"r-{name}.sock")
        ok &= compare(
            name,
            run(c_args(c_sock), c_sock, mode, 22),
            run(r_args(r_sock), r_sock, mode, 48),
        )

    c_sock = os.path.join(tmp, "c-run.sock")
    r_sock = os.path.join(tmp, "r-run.sock")
    ok &= compare(
        "start-and-stop",
        run(c_args(c_sock), c_sock, "ok", 22, stop_after=1.0),
        run(r_args(r_sock), r_sock, "ok", 48, stop_after=1.0),
    )

    for path in (bad, health, live, https):
        try:
            os.unlink(path)
        except OSError:
            pass
    try:
        os.rmdir(tmp)
    except OSError:
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
