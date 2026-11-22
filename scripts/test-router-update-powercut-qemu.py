#!/usr/bin/env python3
"""Проверка журнала менеджера после аварийного отключения OpenWrt в QEMU."""

import argparse
import gzip
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time


GUEST_INIT = """#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
root=/audit/r2o
manager=/audit/r2o-manager
slot() { sed -n '2p' "$root/release-slots"; }
if [ -f /audit/reboot-test ]; then
    [ "$(slot)" = r2o-base ]
    [ -s "$root/state/update-pending.json" ]
    "$manager" update-recover --root "$root"
    [ "$(slot)" = r2o-next ]
    [ ! -e "$root/state/update-pending.json" ]
    grep -qx 'MODE=observe' "$root/config"
    grep -qx '{"schema":1,"boxes":[]}' "$root/state/catalog.json"
    grep -q '"bad_release":"r2o-base"' "$root/state/update.json"
    printf 'R2O_RECOVERY_OK\\n'
    sync
    poweroff -f
    exit 0
fi
mkdir -p "$root/state" /audit/bundle/builds /audit/bundle/router
for component in datapath controller panel telegram manager fetch; do
    ln "$manager" "/audit/bundle/builds/r2o-$component-linux-aarch64-openwrt-musl"
done
printf 'R2O-STATE-1\\n' > /audit/bundle/router/update-schema
for tag in r2o-base r2o-next; do
    "$manager" install-local --root "$root" --bundle /audit/bundle \\
        --release-id "$tag" --architecture aarch64-openwrt-musl
done
printf 'MODE=observe\\n' > "$root/config"
printf '{"schema":1,"boxes":[]}\\n' > "$root/state/catalog.json"
touch /audit/reboot-test
sync
exec "$manager" update-rollback --root "$root" --service /audit/adapter.sh
"""

ADAPTER = """#!/bin/sh
set -eu
case "$1" in
    update-stop) ;;
    update-start)
        printf 'R2O_POWER_CUT_NOW\\n'
        exec sleep 120
        ;;
    *) exit 1 ;;
esac
"""


def boot(command, token, log):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as vm:
        deadline = time.monotonic() + 90
        received = b""
        try:
            with log.open("wb") as output:
                while time.monotonic() < deadline:
                    if not select.select([vm.stdout], [], [], 0.5)[0]:
                        continue
                    chunk = os.read(vm.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    output.write(chunk)
                    received = (received + chunk)[-16384:]
                    if token in received:
                        return
            raise RuntimeError(received.decode(errors="replace"))
        finally:
            vm.kill()
            vm.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=Path)
    parser.add_argument("rootfs_gzip", type=Path)
    parser.add_argument("manager", type=Path)
    parser.add_argument("logs", type=Path)
    args = parser.parse_args()
    args.logs.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="r2o-qemu-update-") as dirname:
        work = Path(dirname)
        disk = work / "rootfs.ext4"
        with gzip.open(args.rootfs_gzip, "rb") as source, disk.open("wb") as target:
            shutil.copyfileobj(source, target)
        files = {"guest-init.sh": GUEST_INIT, "adapter.sh": ADAPTER}
        for name, body in files.items():
            path = work / name
            path.write_text(body, encoding="utf8")
            path.chmod(0o755)
        bundled = work / "r2o-manager"
        shutil.copyfile(args.manager, bundled)
        bundled.chmod(0o755)
        commands = work / "debugfs"
        commands.write_text("mkdir /audit\n" + "".join(
            f"write {work / name} /audit/{name}\n" for name in [*files, "r2o-manager"]
        ), encoding="utf8")
        subprocess.run(["debugfs", "-w", "-f", commands, disk], check=True, capture_output=True)
        vm = [
            "qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "256",
            "-kernel", args.kernel, "-append", "root=/dev/vda rw console=ttyAMA0 init=/audit/guest-init.sh",
            "-drive", f"file={disk},format=raw,if=none,id=disk,cache=none",
            "-device", "virtio-blk-device,drive=disk", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
        ]
        boot(vm, b"R2O_POWER_CUT_NOW", args.logs / "before-powercut.log")
        boot(vm, b"R2O_RECOVERY_OK", args.logs / "after-powercut.log")
    print("OpenWrt QEMU восстановил рабочий слот и каталог после отключения во время активации")


if __name__ == "__main__":
    main()
