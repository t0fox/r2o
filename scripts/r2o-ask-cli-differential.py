#!/usr/bin/env python3
"""C/Rust differential: d2kask main — снимки, счётчики и error-пути.

Стенд поднимает Unix control-сокет: C-оракулу нужен только accept (его
`d2k_link_open` — это connect), Rust-контроллеру — greeting и ACK на
ARM_SHAPE. Сравниваются stdout/stderr/exit и файлы `--save-trigger`/
`--save-control`. Нормализуется только имя исполняемого файла, временный
путь сокета и имя временного файла снимка.

Живой путь вопросов (D2K_EV_*) требует полноценного event-сервера и в этот
differential не входит.
"""

import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

KEY_LEN = 38
PROTOCOL_VERSION = 48
EVENT_PROTOCOL = 0x000A
EVENT_ACK = 0x0008
COMMAND_ARM_SHAPE = 0x0087
COMMAND_SET_NAME_PROBE = 0x0088
ACK_OK = 0


def frame(kind: int, body: bytes) -> bytes:
    return struct.pack(">IH", 2 + len(body), kind) + body


def greeting(release: str = "dev") -> bytes:
    body = (
        b"\x04"
        + b"\0" * (KEY_LEN - 1)
        + struct.pack(">HI", PROTOCOL_VERSION, 4096)
        + bytes([len(release)])
        + release.encode()
    )
    return frame(EVENT_PROTOCOL, body)


def arm_ack() -> bytes:
    body = (
        b"\x04"
        + b"\0" * (KEY_LEN - 1)
        + struct.pack(">HBB", COMMAND_ARM_SHAPE, 1, ACK_OK)
    )
    return frame(EVENT_ACK, body)


def client_hello(sni: str | None = "example.com") -> bytes:
    """Собрать полный TLS 1.3 ClientHello с SNI и supported_versions."""
    extensions = b""
    if sni is not None:
        name = sni.encode()
        server_name = b"\x00" + struct.pack(">H", len(name)) + name
        server_name_list = struct.pack(">H", len(server_name)) + server_name
        extensions += struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list
    extensions += struct.pack(">HH", 0x002B, 3) + b"\x02\x03\x04"
    extensions += struct.pack(">HH", 0x000D, 4) + b"\x00\x02\x04\x03"
    handshake = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(handshake).to_bytes(3, "big") + handshake
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def negative_probe_ack(trial_id: bytes) -> bytes:
    """ACK SET_NAME_PROBE с ok=0: датапат отверг план."""
    body = (
        b"\x04"
        + b"\0" * (KEY_LEN - 1)
        + struct.pack(">HBB", COMMAND_SET_NAME_PROBE, 0, 1)
        + trial_id
    )
    return frame(EVENT_ACK, body)


def serve(path: str, ready: threading.Event, peer: str, reject: bool = False) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    ready.set()
    try:
        conn, _ = server.accept()
    except OSError:
        return
    with conn:
        if peer == "r2o":
            conn.sendall(greeting())
        while True:
            header = conn.recv(6)
            if len(header) < 6:
                break
            length, kind = struct.unpack(">IH", header)
            body = b""
            remaining = length - 2
            while remaining > 0:
                chunk = conn.recv(remaining)
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
            if kind == COMMAND_ARM_SHAPE and peer == "r2o":
                conn.sendall(arm_ack())
            if kind == COMMAND_SET_NAME_PROBE and reject:
                name_len = body[0]
                trial_id = body[1 + name_len + 2 + 2 :][-16:]
                conn.sendall(negative_probe_ack(trial_id))
    server.close()


def run(command, path=None, peer="c", reject=False, timeout=20):
    ready = threading.Event()
    thread = None
    if path:
        thread = threading.Thread(target=serve, args=(path, ready, peer, reject), daemon=True)
        thread.start()
        ready.wait(2)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    finally:
        if thread:
            thread.join(1)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def normalize(text: str) -> str:
    text = text.replace("d2kask: ", "CLI: ")
    text = text.replace("r2o-controller --ask: ", "CLI: ")
    text = text.replace("r2o-controller: ", "CLI: ")
    text = re.sub(r"/tmp/r2o-cli-[A-Za-z0-9_]+\.sock", "SOCK", text)
    # Диалект плана: C печатает d2k-plan, R2O — r2o-plan (R2OP), и R2O
    # добавляет служебные записи input/segment. Сам диалект сверяется
    # отдельными TLV-differential'ами; здесь сравнивается отчёт CLI.
    text = re.sub(r"^[ \t]*(?:d2k|r2o)-plan \d+ \d+$", "PLAN-HEADER", text, flags=re.M)
    text = re.sub(r"план: \d+ байт", "план: N байт", text)
    text = re.sub(r"/tmp/r2o-ask-[A-Za-z0-9_.]+\.(?:hex|bin)", "SNAP", text)
    return text


def compare(name: str, c_result, r_result, c_files=None, r_files=None) -> bool:
    c_code, c_out, c_err = c_result
    r_code, r_out, r_err = r_result
    left = f"rc={c_code}\n--- stdout ---\n{normalize(c_out)}--- stderr ---\n{normalize(c_err)}"
    right = f"rc={r_code}\n--- stdout ---\n{normalize(r_out)}--- stderr ---\n{normalize(r_err)}"
    if c_files is not None or r_files is not None:
        left += "\n--- files ---\n" + (c_files or "")
        right += "\n--- files ---\n" + (r_files or "")
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


class Stand:
    def __init__(self, c_bin: str, r_bin: str) -> None:
        self.c_bin = c_bin
        self.r_bin = r_bin
        self.ok = True
        self.hello = Path("/tmp/r2o-ask-hello.hex")
        self.control_hello = Path("/tmp/r2o-ask-control.hex")
        self.no_sni = Path("/tmp/r2o-ask-nosni.hex")
        self.saved = Path("/tmp/r2o-ask-saved.hex")
        self.missing = "/tmp/r2o-ask-missing.sock"

    def write_fixtures(self) -> None:
        self.hello.write_text(client_hello("example.com").hex() + "\n")
        self.control_hello.write_text(client_hello("control.example").hex() + "\n")
        self.no_sni.write_text(client_hello(None).hex() + "\n")

    def socket_case(self, name: str, args: list[str], save: bool = False, reject: bool = False) -> None:
        c_path = tempfile.mktemp(prefix="r2o-cli-", suffix=".sock")
        c_args = [self.c_bin, "--control", c_path] + args
        c_result = run(c_args, c_path, "c", reject)
        c_saved = self._take_saved(save)
        r_path = tempfile.mktemp(prefix="r2o-cli-", suffix=".sock")
        r_args = [self.r_bin, "--ask", "--control", r_path] + args
        r_result = run(r_args, r_path, "r2o", reject)
        r_saved = self._take_saved(save)
        self.ok &= compare(name, c_result, r_result, c_saved, r_saved)

    def plain_case(self, name: str, args: list[str]) -> None:
        self.ok &= compare(
            name,
            run([self.c_bin] + args),
            run([self.r_bin, "--ask"] + args),
        )

    def _take_saved(self, save: bool) -> str:
        if not save or not self.saved.exists():
            return "(нет файла)"
        text = self.saved.read_text()
        self.saved.unlink()
        return text

    def run(self) -> int:
        self.write_fixtures()
        base = ["--ip", "127.0.0.1", "--sni", "example.com"]
        self.socket_case("no-trigger", base + ["--arm-wait-ms", "20"])
        self.socket_case(
            "no-trigger-mark-port",
            base + ["--arm-wait-ms", "20", "--mark", "0x2d", "--port", "8443"],
        )
        self.socket_case(
            "no-trigger-v6", ["--ip", "::1", "--sni", "example.com", "--arm-wait-ms", "20"]
        )
        self.socket_case(
            "control-sni-timeout",
            base + ["--arm-wait-ms", "20", "--control-sni", "control.example"],
        )
        # Полный путь вопросов: датапат-заглушка отвергает каждый
        # SET_NAME_PROBE, поэтому ни TCP-цель, ни D2K_EV_* не нужны.
        self.socket_case(
            "ask-refused",
            base
            + [
                "--hello-hex", str(self.hello),
                "--control-hex", str(self.control_hello),
            ],
            reject=True,
        )
        self.socket_case(
            "ask-refused-no-control",
            base + ["--hello-hex", str(self.hello)],
            reject=True,
        )
        self.socket_case(
            "hello-no-sni",
            base + ["--hello-hex", str(self.no_sni)],
        )
        self.socket_case(
            "save-trigger",
            base
            + ["--hello-hex", str(self.hello), "--save-trigger", str(self.saved)],
            save=True,
            reject=True,
        )
        self.socket_case(
            "save-control",
            base
            + [
                "--hello-hex", str(self.hello),
                "--control-hex", str(self.control_hello),
                "--save-control", str(self.saved),
            ],
            save=True,
            reject=True,
        )

        self.plain_case("no-socket", ["--control", self.missing] + base + ["--arm-wait-ms", "20"])
        self.plain_case(
            "bad-hello-missing",
            ["--control", self.missing] + base + ["--hello-hex", "/nope"],
        )
        empty = Path("/tmp/r2o-ask-empty.hex")
        empty.write_text("")
        odd = Path("/tmp/r2o-ask-odd.hex")
        odd.write_text("abc")
        invalid = Path("/tmp/r2o-ask-invalid.hex")
        invalid.write_text("zz")
        self.plain_case(
            "bad-hello-empty", ["--control", self.missing] + base + ["--hello-hex", str(empty)]
        )
        self.plain_case(
            "bad-hello-odd", ["--control", self.missing] + base + ["--hello-hex", str(odd)]
        )
        self.plain_case(
            "bad-hello-invalid",
            ["--control", self.missing] + base + ["--hello-hex", str(invalid)],
        )
        self.plain_case(
            "bad-control-hex",
            ["--control", self.missing] + base + ["--hello-hex", str(self.hello), "--control-hex", "/nope"],
        )

        self.plain_case("missing-control", base + ["--arm-wait-ms", "20"])
        self.plain_case(
            "missing-ip", ["--control", self.missing, "--sni", "example.com", "--arm-wait-ms", "20"]
        )
        self.plain_case(
            "missing-sni", ["--control", self.missing, "--ip", "127.0.0.1", "--arm-wait-ms", "20"]
        )
        self.plain_case("missing-trigger", ["--control", self.missing] + base)
        self.plain_case(
            "both-triggers",
            ["--control", self.missing] + base + ["--hello-hex", str(self.hello), "--arm-wait-ms", "20"],
        )
        self.plain_case(
            "control-pair",
            ["--control", self.missing]
            + base
            + ["--arm-wait-ms", "20", "--control-hex", str(self.control_hello), "--control-sni", "x"],
        )
        self.plain_case(
            "control-sni-no-arm",
            ["--control", self.missing] + base + ["--hello-hex", str(self.hello), "--control-sni", "x"],
        )
        self.plain_case("bad-port", ["--control", self.missing] + base + ["--arm-wait-ms", "20", "--port", "0"])
        self.plain_case("bad-mark", ["--control", self.missing] + base + ["--arm-wait-ms", "20", "--mark", "zz"])
        self.plain_case(
            "bad-arm-wait", ["--control", self.missing] + base + ["--arm-wait-ms", "0"]
        )
        self.plain_case("unknown-arg", ["--bogus"])
        self.plain_case("missing-value", ["--control"])
        self.plain_case(
            "empty-control", ["--control", "", "--ip", "127.0.0.1", "--sni", "example.com", "--arm-wait-ms", "20"]
        )
        for path in (empty, odd, invalid, self.hello, self.control_hello, self.no_sni):
            try:
                path.unlink()
            except OSError:
                pass
        return 0 if self.ok else 1


def main() -> int:
    donor = os.environ.get("R2O_DONOR_ROOT", "/mnt/e/d2o-current")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_bin = os.environ.get("R2O_ASK_C", os.path.join(donor, "core", "d2kask"))
    r_bin = os.environ.get("R2O_ASK_RUST", os.path.join(root, "target/debug/r2o-controller"))
    return Stand(c_bin, r_bin).run()


if __name__ == "__main__":
    sys.exit(main())
