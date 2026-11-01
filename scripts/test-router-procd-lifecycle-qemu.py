#!/usr/bin/env python3
"""Compare D2O/R2O OpenWrt init waiter lifecycle through real procd in QEMU.

Run in WSL with R2O_OPENWRT_QEMU_KERNEL, R2O_DONOR_ROOT, and
R2O_QEMU_ARTIFACT_DIR pointing to files/directories on E:.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time

D2O_REVISION = "304ba893dd37197128ac8799c0495b035f6a38c0"


def require_on_e(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(pathlib.Path("/mnt/e")):
        raise SystemExit(f"{label} must be on E: (/mnt/e): {resolved}")
    return resolved


def cpio_entry(name: str, data: bytes, mode: int, inode: int) -> bytes:
    encoded_name = name.encode() + b"\0"
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded_name), 0]
    header = b"070701" + b"".join(f"{field:08x}".encode() for field in fields)
    entry = header + encoded_name
    entry += b"\0" * (-len(entry) % 4)
    entry += data
    entry += b"\0" * (-len(data) % 4)
    return entry


class Guest:
    def __init__(self, process: subprocess.Popen[bytes], serial: socket.socket, log: pathlib.Path):
        self.process = process
        self.serial = serial
        self.log = log

    def read_until(self, token: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        received = bytearray()
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"QEMU exited with {self.process.returncode}")
            try:
                chunk = self.serial.recv(8192)
            except TimeoutError:
                continue
            if not chunk:
                continue
            received.extend(chunk)
            with self.log.open("ab") as output:
                output.write(chunk)
            if token in received:
                return bytes(received)
        excerpt = bytes(received[-1200:]).decode("utf-8", "replace")
        raise TimeoutError(f"timed out waiting for {token!r}: {excerpt}")

    def drain(self) -> None:
        while True:
            try:
                chunk = self.serial.recv(8192)
            except TimeoutError:
                return
            if not chunk:
                return
            with self.log.open("ab") as output:
                output.write(chunk)

    def command(self, name: str, command: str) -> str:
        self.drain()
        self.serial.sendall((command + "\n").encode())
        result = self.read_until(b"~#", 20).decode("utf-8", "replace").replace("\r", "")
        print(f"--- {name} ---\n{result[-2600:]}")
        return result


def trace_lines(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if line.strip() in {
        "R2O:start", "R2O:stop", "D2O:start", "D2O:stop"
    }]


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    kernel = require_on_e(pathlib.Path(os.environ["R2O_OPENWRT_QEMU_KERNEL"]), "QEMU kernel")
    donor = require_on_e(pathlib.Path(os.environ["R2O_DONOR_ROOT"]), "clean D2O checkout")
    artifacts = require_on_e(pathlib.Path(os.environ["R2O_QEMU_ARTIFACT_DIR"]), "artifact directory")
    artifacts.mkdir(parents=True, exist_ok=True)
    qemu = shutil.which("qemu-system-aarch64")
    if not qemu:
        raise SystemExit("qemu-system-aarch64 is required in WSL")
    if not kernel.is_file():
        raise SystemExit(f"QEMU kernel not found: {kernel}")

    donor_revision = subprocess.check_output(["git", "-C", str(donor), "rev-parse", "HEAD"], text=True).strip()
    if donor_revision != D2O_REVISION:
        raise SystemExit(f"expected clean D2O {D2O_REVISION}, got {donor_revision}")
    donor_script = donor / "files" / "d2k-openwrt-init"
    r2o_script = repo / "router" / "openwrt-init"
    today = time.strftime("%Y-%m-%d")
    serial_log = artifacts / f"r2o-procd-differential-{today}.log"
    qemu_log = artifacts / f"r2o-procd-differential-{today}-qemu.log"
    serial_log.unlink(missing_ok=True)
    qemu_log.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="r2o-procd-", dir=artifacts) as temporary:
        overlay = pathlib.Path(temporary) / "init-overlay.cpio"
        entries = [
            ("etc/init.d/r2o", r2o_script.read_bytes(), stat.S_IFREG | 0o755),
            ("etc/rc.d/S99r2o", b"../init.d/r2o", stat.S_IFLNK | 0o777),
            ("etc/init.d/d2k", donor_script.read_bytes(), stat.S_IFREG | 0o755),
            ("etc/rc.d/S99d2k", b"../init.d/d2k", stat.S_IFLNK | 0o777),
        ]
        archive = b"".join(cpio_entry(name, data, mode, index + 1)
                           for index, (name, data, mode) in enumerate(entries))
        overlay.write_bytes(archive + cpio_entry("TRAILER!!!", b"", 0, 10))

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        args = [
            qemu, "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "128M",
            "-kernel", str(kernel), "-initrd", str(overlay), "-append", "console=ttyAMA0",
            "-netdev", "user,id=management", "-device", "virtio-net-device,netdev=management",
            "-no-reboot", "-display", "none", "-monitor", "none",
            "-serial", f"tcp:127.0.0.1:{port},server=on,wait=off",
        ]
        with qemu_log.open("wb") as output:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        serial = socket.socket()
        serial.settimeout(0.3)
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    serial.connect(("127.0.0.1", port))
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(f"QEMU exited with {process.returncode}")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("QEMU serial did not start")
                    time.sleep(0.2)
            guest = Guest(process, serial, serial_log)
            guest.read_until(b"Please press Enter", 35)
            serial.sendall(b"\n")
            boot = guest.read_until(b"~#", 15)
            if b"OpenWrt 25.12.5" not in boot:
                raise AssertionError("expected the pinned OpenWrt 25.12.5 initramfs image")
            print("OpenWrt 25.12.5 procd booted; D2O and R2O init scripts are installed.")

            workers = guest.command(
                "start waiters through rc.d links",
                '/etc/rc.d/S99r2o start; /etc/rc.d/S99d2k start; sleep 1; ps w | grep "[b]oot_wait"',
            )
            if "/etc/init.d/r2o boot_wait" not in workers or "/etc/init.d/d2k boot_wait" not in workers:
                raise AssertionError("both rc.d entries must start their procd waiters")
            stopped_waiters = guest.command(
                "cancel both waiters before /opt appears",
                '/etc/init.d/r2o stop; /etc/init.d/d2k stop; sleep 1; '
                'ps w | grep "[b]oot_wait" || echo NO_BOOT_WORKERS',
            )
            if "NO_BOOT_WORKERS" not in stopped_waiters:
                raise AssertionError("stop must cancel both pending boot waiters")

            guest.command("prepare /opt fixtures", "mkdir -p /opt/etc/init.d /opt/r2o /opt/d2k")
            guest.command(
                "install R2O service fixture",
                "printf '%s\\n' '#!/bin/sh' 'echo R2O:$1 >> /tmp/r2o-procd-trace' "
                "> /opt/etc/init.d/S99r2o; chmod 755 /opt/etc/init.d/S99r2o",
            )
            guest.command(
                "install D2O service fixture",
                "printf '%s\\n' '#!/bin/sh' 'echo D2O:$1 >> /tmp/d2o-procd-trace' "
                "> /opt/etc/init.d/S99d2k; chmod 755 /opt/etc/init.d/S99d2k",
            )
            guest.command(
                "install manager and config",
                'printf "%s\\n" "#!/bin/sh" "exit 0" > /opt/r2o/r2o-manager; '
                'chmod 755 /opt/r2o/r2o-manager; : > /opt/r2o/config; : > /opt/d2k/config',
            )
            canceled = guest.command(
                "canceled waiters do not start late",
                "test ! -e /tmp/r2o-procd-trace && test ! -e /tmp/d2o-procd-trace "
                "&& echo CANCELLED_NO_LATE_START",
            )
            if "CANCELLED_NO_LATE_START" not in canceled:
                raise AssertionError("a canceled waiter must not start after /opt appears")

            started = guest.command(
                "restart with delayed /opt ready",
                "/etc/rc.d/S99r2o start; /etc/rc.d/S99d2k start; sleep 3; "
                "cat /tmp/r2o-procd-trace /tmp/d2o-procd-trace",
            )
            if trace_lines(started) != ["R2O:start", "D2O:start"]:
                raise AssertionError(f"start traces differ or repeated: {trace_lines(started)}")
            stopped = guest.command(
                "stop both and check no repeated start",
                "/etc/init.d/r2o stop; /etc/init.d/d2k stop; sleep 3; "
                "cat /tmp/r2o-procd-trace /tmp/d2o-procd-trace",
            )
            expected = ["R2O:start", "R2O:stop", "D2O:start", "D2O:stop"]
            if trace_lines(stopped) != expected:
                raise AssertionError(f"expected one start/stop per side: {trace_lines(stopped)}")

            print("D2O/R2O procd lifecycle matches: delayed /opt, canceled waiter, one start/stop, no repeat.")
            print(f"D2O={donor_revision}; R2O=" + subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip())
            print(f"serial log: {serial_log}")
            print(f"QEMU log: {qemu_log}")
            return 0
        finally:
            serial.close()
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
