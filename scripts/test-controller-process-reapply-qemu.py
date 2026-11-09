#!/usr/bin/env python3
"""Short OpenWrt ARM64 process-restart and persistent-catalog reapply check."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import time

SERVICE_MANAGER_SCRIPT = r"""#!/bin/sh
set -eu
[ "${1:-}" = exec ] || exit 2
shift
root=
component=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) root=$2; shift 2 ;;
        --component) component=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
case "$component" in
    r2o-controller|r2o-datapath) exec "$root/releases/qemu/builds/$component-linux-aarch64" "$@" ;;
    *) exit 2 ;;
esac
"""

SERVICE_FIREWALL_SCRIPT = r"""#!/bin/sh
set -eu
case "${1:-}" in
    backend) echo nft ;;
    ipv6-enabled) echo 0 ;;
    status) test -e /tmp/r2o-test/firewall-installed ;;
    up) : > /tmp/r2o-test/firewall-installed ;;
    down) rm -f /tmp/r2o-test/firewall-installed ;;
    flowoffload-ensure|flowoffload-restore|dns-ensure) ;;
    *) echo "unexpected firewall action: ${1:-}" >&2; exit 2 ;;
esac
"""

SERVICE_CONFIG = r"""MODE=apply
QUEUE_NUM=65440
QUEUE_NUM6=65441
MARK=291
PROBE_MARK=0
IPV6_ENABLED=0
PANEL_LISTEN=
TG_ENABLED=0
R2O_PPE_DEOFFLOAD=0
STATE_DIR=/mnt/r2o-persist/r2o-process-reapply
"""

GUEST_SCRIPT = r"""#!/bin/sh
set -eu
HARNESS=/etc/r2o-test
ROOT=/opt/r2o
CTRL=$ROOT/releases/qemu/builds/r2o-controller-linux-aarch64
SERVICE=/opt/etc/init.d/S99r2o
OPENWRT_INIT=/etc/init.d/r2o
CAT=/mnt/r2o-persist/r2o-process-reapply/catalog.json
PHASE=$1
mkdir -p /mnt/r2o-persist /mnt/r2o-persist/r2o-process-reapply
mkdir -p /tmp/r2o-test
mount -t ext4 /dev/vda /mnt/r2o-persist
mkdir -p /mnt/r2o-persist/r2o-process-reapply
if [ "$PHASE" = first ] && [ ! -s "$CAT" ]; then cp "$HARNESS/catalog.json" "$CAT"; fi
mkdir -p "$ROOT/releases/qemu/builds" /opt/etc/init.d
cp "$HARNESS/S99r2o" /opt/etc/init.d/S99r2o
cp "$HARNESS/r2o-manager" "$ROOT/r2o-manager"
cp "$HARNESS/r2o-firewall.sh" /opt/etc/init.d/r2o-firewall.sh
cp "$HARNESS/config" "$ROOT/config"
cp "$HARNESS/releases/qemu/builds/r2o-controller-linux-aarch64" "$ROOT/releases/qemu/builds/r2o-controller-linux-aarch64"
cp "$HARNESS/releases/qemu/builds/r2o-datapath-linux-aarch64" "$ROOT/releases/qemu/builds/r2o-datapath-linux-aarch64"
cp "$HARNESS/catalog.json" "$ROOT/catalog.json"
cmp "$ROOT/catalog.json" "$CAT"
"$CTRL" --check-catalog "$CAT"
if command -v apk >/dev/null 2>&1; then
    if ! apk add --allow-untrusted --force-non-repository --no-network "$HARNESS/kmod-nfnetlink-queue.apk" "$HARNESS/kmod-nft-queue.apk" >/tmp/r2o-apk.log 2>&1; then cat /tmp/r2o-apk.log >&2; exit 1; fi
fi
if command -v modprobe >/dev/null 2>&1; then
    modprobe nfnetlink_queue
    modprobe nft_queue
fi
export R2O_DIR="$ROOT" R2O_CONFIG="$ROOT/config" R2O_INIT="$SERVICE" R2O_MANAGER="$ROOT/r2o-manager"
export R2O_FIREWALL=/opt/etc/init.d/r2o-firewall.sh R2O_LOG_MAINTENANCE="$ROOT/missing-log-worker"
export R2O_FIREWALL_WATCHDOG="$ROOT/missing-firewall-watchdog" R2O_PPE_ADAPTER="$ROOT/missing-ppe"
export R2O_RUNTIME_DIR=/tmp/r2o
# Этот harness проверяет раздельные PID-файлы и журналы, поэтому
# принудительно использует старый split-режим.
export R2O_SPLIT_RUNTIME=1
wait_for_sync() {
    label=$1
    expected=$2
    allow_restart=${3:-0}
    log=$ROOT/log/r2o-controller4.log
    i=0
    while [ "$i" -lt 45 ]; do
        count=$(grep -Fc 'каталог синхронизирован:' "$log" 2>/dev/null || true)
        [ -n "$count" ] || count=0
        if [ "$count" -ge "$expected" ]; then break; fi
        pid=$(cat "$ROOT/run/r2o-controller4.pid" 2>/dev/null || true)
        if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
            if [ "$allow_restart" != 1 ]; then cat "$ROOT/engine-$label.log" >&2; cat "$log" >&2; exit 1; fi
        fi
        sleep 1
        i=$((i + 1))
    done
    count=$(grep -Fc 'каталог синхронизирован:' "$log" 2>/dev/null || true)
    [ -n "$count" ] || count=0
    if [ "$count" -lt "$expected" ]; then cat "$ROOT/engine-$label.log" >&2; cat "$log" >&2; exit 1; fi
    line=$(grep -F 'каталог синхронизирован:' "$log" | tail -n 1)
    case "$line" in 'каталог синхронизирован: отправлено 3, пропущено 0') ;; *) echo "$label: unexpected catalog sync: $line" >&2; exit 1;; esac
    if grep -q 'датапат отверг' "$log"; then cat "$log" >&2; exit 1; fi
    pid=$(cat "$ROOT/run/r2o-controller4.pid" 2>/dev/null || true)
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; exit 1; fi
    echo "$label: $line"
}
start_engine() {
    label=$1
    expected=$2
    if ! "$SERVICE" engine-start >"$ROOT/engine-$label.log" 2>&1; then cat "$ROOT/engine-$label.log" >&2; exit 1; fi
    wait_for_sync "$label" "$expected"
}
if [ "$PHASE" = first ]; then
    start_engine first-start 1
    DPID=$(cat "$ROOT/run/r2o-datapath4.pid")
    CPID=$(cat "$ROOT/run/r2o-controller4.pid")
    if ! "$SERVICE" engine-start >"$ROOT/engine-idempotent.log" 2>&1; then cat "$ROOT/engine-idempotent.log" >&2; exit 1; fi
    [ "$(cat "$ROOT/run/r2o-datapath4.pid")" = "$DPID" ] || { echo "idempotent engine-start replaced datapath" >&2; exit 1; }
    [ "$(cat "$ROOT/run/r2o-controller4.pid")" = "$CPID" ] || { echo "idempotent engine-start replaced controller" >&2; exit 1; }
    kill -KILL "$CPID"
    sleep 1
    start_engine after-crash 2
    NEW_DPID=$(cat "$ROOT/run/r2o-datapath4.pid")
    NEW_CPID=$(cat "$ROOT/run/r2o-controller4.pid")
    [ "$NEW_DPID" != "$DPID" ] || { echo "crash recovery did not restart datapath" >&2; exit 1; }
    [ "$NEW_CPID" != "$CPID" ] || { echo "crash recovery did not restart controller" >&2; exit 1; }

    : > "$ROOT/engine-procd-start.log"
    if ! R2O_RECOVERY_INTERVAL=1 "$OPENWRT_INIT" start >"$ROOT/engine-procd-start.log" 2>&1; then
        cat "$ROOT/engine-procd-start.log" >&2
        exit 1
    fi
    i=0
    while [ "$i" -lt 10 ] && ! ps w | grep -q '[r]2o boot_wait'; do
        sleep 1
        i=$((i + 1))
    done
    ps w | grep -q '[r]2o boot_wait' || { cat "$ROOT/engine-procd-start.log" >&2; exit 1; }
    sleep 2
    DPID=$(cat "$ROOT/run/r2o-datapath4.pid")
    CPID=$(cat "$ROOT/run/r2o-controller4.pid")
    kill -KILL "$DPID"
    wait_for_sync after-procd-crash 3 1
    NEW_DPID=$(cat "$ROOT/run/r2o-datapath4.pid")
    NEW_CPID=$(cat "$ROOT/run/r2o-controller4.pid")
    [ "$NEW_DPID" != "$DPID" ] || { echo "procd recovery did not restart datapath" >&2; exit 1; }
    [ "$NEW_CPID" != "$CPID" ] || { echo "procd recovery did not restart controller" >&2; exit 1; }
    echo R2O_PROCD_AUTO_RECOVERY_OK=1

    DPID=$NEW_DPID
    CPID=$NEW_CPID
    kill -KILL "$CPID"
    wait_for_sync after-procd-controller-crash 4 1
    NEW_DPID=$(cat "$ROOT/run/r2o-datapath4.pid")
    NEW_CPID=$(cat "$ROOT/run/r2o-controller4.pid")
    [ "$NEW_DPID" != "$DPID" ] || { echo "controller crash recovery did not restart datapath" >&2; exit 1; }
    [ "$NEW_CPID" != "$CPID" ] || { echo "controller crash recovery did not restart controller" >&2; exit 1; }
    echo R2O_PROCD_CONTROLLER_RECOVERY_OK=1
elif [ "$PHASE" = reboot ]; then
    start_engine after-reboot 1
else
    echo "unknown phase: $PHASE" >&2
    exit 2
fi
if [ "$PHASE" = first ]; then
    "$OPENWRT_INIT" stop >"$ROOT/engine-stop.log" 2>&1 || { cat "$ROOT/engine-stop.log" >&2; exit 1; }
else
    "$SERVICE" engine-stop >"$ROOT/engine-stop.log" 2>&1 || { cat "$ROOT/engine-stop.log" >&2; exit 1; }
fi
grep -Fq 'процессор ' "$ROOT/log/r2o-datapath4.log"
grep -Fq ' RSS ' "$ROOT/log/r2o-datapath4.log"
grep -Fq 'TCP-потоки' "$ROOT/log/r2o-datapath4.log"
grep -Fq 'снимки TLS/TCP:' "$ROOT/log/r2o-datapath4.log"
echo R2O_STATS_SHUTDOWN_OK=1
cmp "$ROOT/catalog.json" "$CAT"
echo "R2O_REAPPLY_OK=$PHASE"
echo "R2O_SERVICE_RESTART_OK=$PHASE"
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
        if ("QEMU_PHASE_EXIT=0" not in output or f"R2O_REAPPLY_OK={phase}" not in output or "R2O_STATS_SHUTDOWN_OK=1" not in output or f"R2O_SERVICE_RESTART_OK={phase}" not in output):
            raise AssertionError(f"process reapply phase {phase} failed; see {serial_log}")
        if phase == "first" and "R2O_PROCD_AUTO_RECOVERY_OK=1" not in output:
            raise AssertionError(f"production procd recovery did not pass; see {serial_log}")
        if phase == "first" and "R2O_PROCD_CONTROLLER_RECOVERY_OK=1" not in output:
            raise AssertionError(f"production controller crash recovery did not pass; see {serial_log}")
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
    catalog = json.loads(seed.read_text(encoding="utf-8"))
    box = catalog["boxes"][0]
    box["plans"].append(
        {
            "id": "voice-plan",
            "proto": "voice",
            "text": (
                "r2o-plan 1 1\n"
                "id 00000000000000000000000000000000\n"
                "proto udp voice\n"
                "payload 1 46414b45\n"
                "poison 1 ttl=2\n"
                "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n"
            ),
            "added": "2026-10-24T00:00:00Z",
            "successes": 1,
            "enabled": True,
        }
    )
    box["bindings"].append(
        {
            "kind": "name",
            "target": "@discord-voice",
            "plan_id": "voice-plan",
            "level": 3,
            "confirmed": "2026-10-24T00:00:00Z",
            "successes": 1,
            "enabled": True,
            "transport": 17,
            "family": 4,
            "shape": 5,
        }
    )
    seed_bytes = json.dumps(catalog, ensure_ascii=False).encode("utf-8").replace(
        b"d2k-plan ", b"r2o-plan "
    )
    entries = [
        ("etc/r2o-test", b"", stat.S_IFDIR | 0o755),
        ("etc/r2o-test/releases", b"", stat.S_IFDIR | 0o755),
        ("etc/r2o-test/releases/qemu", b"", stat.S_IFDIR | 0o755),
        ("etc/r2o-test/releases/qemu/builds", b"", stat.S_IFDIR | 0o755),
        ("etc/r2o-test/S99r2o", (repo / "router" / "S99r2o").read_bytes(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/r2o-manager", SERVICE_MANAGER_SCRIPT.encode(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/r2o-firewall.sh", SERVICE_FIREWALL_SCRIPT.encode(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/config", SERVICE_CONFIG.encode(), stat.S_IFREG | 0o644),
        ("etc/r2o-test/releases/qemu/builds/r2o-controller-linux-aarch64", controller.read_bytes(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/releases/qemu/builds/r2o-datapath-linux-aarch64", datapath.read_bytes(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/catalog.json", seed_bytes, stat.S_IFREG | 0o644),
        ("etc/r2o-test/process-reapply.sh", GUEST_SCRIPT.encode(), stat.S_IFREG | 0o755),
        ("etc/r2o-test/kmod-nfnetlink-queue.apk", apk_queue.read_bytes(), stat.S_IFREG | 0o644),
        ("etc/r2o-test/kmod-nft-queue.apk", apk_nft_queue.read_bytes(), stat.S_IFREG | 0o644),
        ("etc/init.d/r2o", (repo / "router" / "openwrt-init").read_bytes(), stat.S_IFREG | 0o755),
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
