#!/usr/bin/env python3
"""Short OpenWrt ARM64 process-restart and persistent-catalog reapply check."""

from __future__ import annotations

import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import time

GUEST_SCRIPT = r"""#!/bin/sh
set -eu
DP=/etc/r2o-test/r2o-datapath
CTRL=/etc/r2o-test/r2o-controller
SOCK=/tmp/r2o-process-reapply.sock
CAT=/mnt/r2o-persist/r2o-process-reapply/catalog.json
QUEUE=65440
PHASE=$1
mkdir -p /mnt/r2o-persist /mnt/r2o-persist/r2o-process-reapply
mount -t ext4 /dev/vda /mnt/r2o-persist
mkdir -p /mnt/r2o-persist/r2o-process-reapply
if [ ! -s "$CAT" ]; then cp /etc/r2o-test/catalog.json "$CAT"; fi
cmp /etc/r2o-test/catalog.json "$CAT"
"$CTRL" --check-catalog "$CAT"
if command -v apk >/dev/null 2>&1; then
    if ! apk add --allow-untrusted --force-non-repository --no-network /etc/r2o-test/kmod-nfnetlink-queue.apk /etc/r2o-test/kmod-nft-queue.apk >/tmp/r2o-apk.log 2>&1; then cat /tmp/r2o-apk.log >&2; exit 1; fi
fi
if command -v modprobe >/dev/null 2>&1; then
    modprobe nfnetlink_queue
    modprobe nft_queue
fi


if command -v nft >/dev/null 2>&1; then
    nft add table inet r2o_reapply
    nft add chain inet r2o_reapply output '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet r2o_reapply output ip daddr 127.0.0.1 tcp dport 65000 queue num "$QUEUE" bypass
fi
"$DP" --mode apply --queue "$QUEUE" --family ipv4 --controller-only --control "$SOCK" --mark 291 --stats 0 >/etc/r2o-test/r2o-datapath.log 2>&1 &
DPID=$!
i=0
while [ ! -S "$SOCK" ]; do
    if ! kill -0 "$DPID" 2>/dev/null; then cat /etc/r2o-test/r2o-datapath.log >&2; exit 1; fi
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then cat /etc/r2o-test/r2o-datapath.log >&2; exit 1; fi
done
start_controller() {
    label=$1
    log=$2
    "$CTRL" --serve "$SOCK" "$CAT" >"$log" 2>&1 &
    CPID=$!
    i=0
    while ! grep -Fq 'каталог синхронизирован:' "$log"; do
        if ! kill -0 "$CPID" 2>/dev/null; then cat "$log" >&2; cat /etc/r2o-test/r2o-datapath.log >&2; return 1; fi
        sleep 1
        i=$((i + 1))
        if [ "$i" -ge 45 ]; then cat "$log" >&2; cat /etc/r2o-test/r2o-datapath.log >&2; return 1; fi
    done
    line=$(grep -F 'каталог синхронизирован:' "$log" | tail -n 1)
    case "$line" in *'отправлено 0'*) echo "$label: no commands sent: $line" >&2; return 1;; esac
    case "$line" in *'пропущено 0'*) ;; *) echo "$label: catalog entries skipped: $line" >&2; return 1;; esac
    if grep -q 'датапат отверг' "$log"; then cat "$log" >&2; return 1; fi
    sleep 1
    if ! kill -0 "$CPID" 2>/dev/null; then cat "$log" >&2; return 1; fi
    echo "$label: $line"
}
if [ "$PHASE" = first ]; then
    start_controller first-start /etc/r2o-test/r2o-controller-first.log
    kill -KILL "$CPID"
    wait "$CPID" 2>/dev/null || true
    CPID=
    sleep 1
    start_controller after-crash /etc/r2o-test/r2o-controller-after-crash.log
elif [ "$PHASE" = reboot ]; then
    start_controller after-reboot /etc/r2o-test/r2o-controller-after-reboot.log
else
    echo "unknown phase: $PHASE" >&2
    exit 2
fi
kill -TERM "$CPID"
wait "$CPID"
kill -TERM "$DPID"
wait "$DPID"
grep -Fq 'процессор ' /etc/r2o-test/r2o-datapath.log
grep -Fq ' RSS ' /etc/r2o-test/r2o-datapath.log
grep -Fq 'TCP-потоки' /etc/r2o-test/r2o-datapath.log
grep -Fq 'снимки TLS/TCP:' /etc/r2o-test/r2o-datapath.log
echo R2O_STATS_SHUTDOWN_OK=1
cmp /etc/r2o-test/catalog.json "$CAT"
echo "R2O_REAPPLY_OK=$PHASE"
sync
umount /mnt/r2o-persist
"""

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
        excerpt = bytes(received[-1400:]).decode("utf-8", "replace")
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

    def command(self, name: str, command: str, timeout: float = 45) -> str:
        self.drain()
        self.serial.sendall((command + "\n").encode())
        result = self.read_until(b"~#", timeout).decode("utf-8", "replace").replace("\r", "")
        print(f"--- {name} ---\n{result[-2400:]}")
        return result


def boot_once(
    qemu: str,
    kernel: pathlib.Path,
    overlay: pathlib.Path,
    disk: pathlib.Path,
    artifacts: pathlib.Path,
    phase: str,
) -> None:
    serial_log = artifacts / f"{phase}-serial.log"
    qemu_log = artifacts / f"{phase}-qemu.log"
    serial_log.unlink(missing_ok=True)
    qemu_log.unlink(missing_ok=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    args = [
        qemu, "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "128M",
        "-kernel", str(kernel), "-initrd", str(overlay), "-append", "console=ttyAMA0",
        "-drive", f"if=none,file={disk},format=qcow2,id=persist",
        "-device", "virtio-blk-device,drive=persist",
        "-netdev", "user,id=management", "-device", "virtio-net-device,netdev=management",

        "-no-reboot", "-display", "none", "-monitor", "none",
        "-serial", f"tcp:127.0.0.1:{port},server=on,wait=off",
    ]
    with qemu_log.open("wb") as output:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
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
            raise AssertionError("expected OpenWrt 25.12.5 ARM64 guest")
        output = guest.command(f"persistent catalog {phase}", f"sh /etc/r2o-test/process-reapply.sh {phase}; echo QEMU_PHASE_EXIT=$?")
        if ("QEMU_PHASE_EXIT=0" not in output or f"R2O_REAPPLY_OK={phase}" not in output or "R2O_STATS_SHUTDOWN_OK=1" not in output):
            raise AssertionError(f"process reapply phase {phase} failed; see {serial_log}")
        print(f"OpenWrt ARM64 QEMU {phase}: persistent catalog reapply passed.")
    finally:
        serial.close()
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    image_dir = require_on_e(pathlib.Path(os.environ.get("R2O_OPENWRT_QEMU_DIR", "/mnt/e/r2o-tooling/openwrt-qemu-armv8")), "OpenWrt image directory")
    artifacts = require_on_e(pathlib.Path(os.environ.get("R2O_QEMU_ARTIFACT_DIR", "/mnt/e/r2o-tooling/tests")), "artifact directory")
    kernel = require_on_e(pathlib.Path(os.environ.get("R2O_OPENWRT_QEMU_KERNEL", str(image_dir / "kernel.bin"))), "OpenWrt ARM64 kernel")
    rootfs = require_on_e(image_dir / "openwrt-25.12.5-armsr-armv8-generic-ext4-rootfs.img", "OpenWrt ARM64 rootfs")
    binary_dir = require_on_e(pathlib.Path(os.environ.get("R2O_OPENWRT_AARCH64_BIN_DIR", "/mnt/e/r2o-tooling/openwrt-target/aarch64-unknown-linux-musl/release")), "AArch64 release binaries")
    qemu = shutil.which("qemu-system-aarch64")
    qemu_img = shutil.which("qemu-img")
    if not qemu or not qemu_img:
        raise SystemExit("qemu-system-aarch64 and qemu-img are required in WSL")
    controller = binary_dir / "r2o-controller"
    datapath = binary_dir / "r2o-datapath"
    seed = repo / "crates" / "r2o-controller" / "tests" / "fixtures" / "d2o_catalog_sync_wire.json"
    apk_queue = image_dir / "kmod-nfnetlink-queue-6.12.94-r1.apk"
    apk_nft_queue = image_dir / "kmod-nft-queue-6.12.94-r1.apk"
    for path, label in [(controller, "controller"), (datapath, "datapath"), (seed, "catalog fixture"), (apk_queue, "NFQUEUE module"), (apk_nft_queue, "nft queue module")]:
        require_on_e(path, label)
        if not path.is_file():
            raise SystemExit(f"missing {label}: {path}")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    artifacts.mkdir(parents=True, exist_ok=True)
    artifacts = artifacts / f"r2o-process-reapply-{stamp}"
    artifacts.mkdir(parents=True, exist_ok=True)
    overlay = artifacts / "overlay.cpio"
    disk = artifacts / "persistent-rootfs.qcow2"
    # Match the production donor import: the fixture's first plan directive changes from D2K to R2O.
    seed_bytes = seed.read_bytes().replace(b"d2k-plan ", b"r2o-plan ")
    entries = [
        ("etc/r2o-test", b"", stat.S_IFDIR | 0o755),
        ("etc/r2o-test/r2o-controller", controller.read_bytes(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/r2o-datapath", datapath.read_bytes(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/catalog.json", seed_bytes, stat.S_IFREG | 0o644),
        ("etc/r2o-test/process-reapply.sh", GUEST_SCRIPT.encode(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/kmod-nfnetlink-queue.apk", apk_queue.read_bytes(), stat.S_IFREG | 0o644),
        ("etc/r2o-test/kmod-nft-queue.apk", apk_nft_queue.read_bytes(), stat.S_IFREG | 0o644),
    ]
    archive = b"".join(cpio_entry(name, data, mode, index + 1) for index, (name, data, mode) in enumerate(entries))
    overlay.write_bytes(archive + cpio_entry("TRAILER!!!", b"", 0, len(entries) + 1))
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", str(rootfs), str(disk)], check=True)
    boot_once(qemu, kernel, overlay, disk, artifacts, "first")
    boot_once(qemu, kernel, overlay, disk, artifacts, "reboot")
    print(f"D2O fixture: {seed}")
    print(f"Persistent OpenWrt disk overlay: {disk}")
    print(f"QEMU serial logs: {artifacts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
