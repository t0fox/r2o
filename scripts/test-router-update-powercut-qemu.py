#!/usr/bin/env python3
"""Проверка журнала менеджера после аварийного отключения OpenWrt в QEMU."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tempfile
import time


GUEST_INIT = """#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
if [ ! -c /dev/null ]; then
    mount -t devtmpfs devtmpfs /dev || mknod /dev/null c 1 3
fi
[ -c /dev/null ]
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
root=/audit/r2o
manager=/audit/r2o-manager
slot() { sed -n '2p' "$root/release-slots"; }
user_data_kept() {
    grep -Fqx 'MODE=observe' "$root/config" &&
        grep -Fqx '{"schema":1,"boxes":[]}' "$root/state/catalog.json"
}
setup_network() {
    ip link set lo up
    ip link set eth0 up
    ip addr add 10.0.2.15/24 dev eth0
    ip route add default via 10.0.2.2
}
staged=$root/state/update-stage.json
journal=$root/state/update-pending.json
status=$root/state/update.json
for option in $(cat /proc/cmdline); do
    case "$option" in
        r2o_audit_phase=*) export R2O_AUDIT_PHASE=${option#*=} ;;
        r2o_audit_release=*) target=${option#*=} ;;
        r2o_audit_archive=*) digest=${option#*=} ;;
    esac
done
if [ -f /audit/reboot-test ]; then
    expected_current=r2o-next
    expected_previous=r2o-base
    case "$R2O_AUDIT_PHASE" in
        stage-ready) [ "$(slot)" = r2o-next ] && [ -s "$staged" ] && [ ! -e "$journal" ] ;;
        public-*) [ "$(slot)" = r2o-next ] && [ ! -e "$journal" ] &&
            grep -q "\\\"phase\\\":\\\"${R2O_AUDIT_PHASE#public-}\\\"" "$status" ;;
        update-stop) [ "$(slot)" = r2o-next ] && [ -s "$journal" ] ;;
        commit-recorded)
            [ "$(slot)" = r2o-base ] && grep -q '"committed":true' "$journal"
            expected_current=r2o-base
            expected_previous=-
            ;;
        *) [ "$(slot)" = r2o-base ] && [ -s "$journal" ] ;;
    esac || exit 1
    "$manager" update-recover --root "$root"
    "$manager" update-recover --root "$root"
    [ "$(slot)" = "$expected_current" ]
    [ "$(sed -n '3p' "$root/release-slots")" = "$expected_previous" ]
    [ ! -e "$journal" ] && [ ! -e "$staged" ] || exit 1
    user_data_kept
    case "$R2O_AUDIT_PHASE" in
        public-*)
            for work in "$root"/.install-*; do
                [ ! -e "$work" ] || { echo "Осиротел каталог подготовки: $work"; exit 1; }
            done
            ;;
    esac
    case "$R2O_AUDIT_PHASE" in
        stage-ready|update-stop|public-*)
            grep -q '"last_ok":false' "$status"
            if grep -q '"bad_release":"r2o-base"' "$status"; then exit 1; fi
            ;;
        commit-recorded)
            grep -q '"last_ok":true' "$status"
            [ "$(grep -o '"healthy":true' "$status" | wc -l)" -eq 1 ]
            if grep -q '"bad_release":"r2o-base"' "$status"; then exit 1; fi
            ;;
        *) grep -q '"bad_release":"r2o-base"' "$status" ;;
    esac
    if [ "$R2O_AUDIT_PHASE" = public-migrate ]; then
        setup_network
        "$manager" update-install --root "$root" --service /audit/adapter.sh --release "$target" --source github
        [ "$(slot)" = "$target" ]
        [ "$(sed -n '3p' "$root/release-slots")" = - ]
        user_data_kept
        printf 'R2O_RETRY_OK\\n'
    fi
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
printf '1\\n' > /audit/bundle/router/update-sequence
for tag in r2o-base r2o-next; do
    "$manager" install-local --root "$root" --bundle /audit/bundle \\
        --release-id "$tag" --architecture aarch64-openwrt-musl
done
printf 'MODE=observe\\n' > "$root/config"
printf '{"schema":1,"boxes":[]}\\n' > "$root/state/catalog.json"
touch /audit/reboot-test
sync
case "$R2O_AUDIT_PHASE" in
    stage-ready) syscall=renameat,renameat2 ;;
    commit-recorded) syscall=unlinkat ;;
    public-*)
        syscall=renameat,renameat2,unlinkat
        setup_network
        mkdir -p "$root/state/update-download"
        case "$R2O_AUDIT_PHASE" in
            public-check|public-download) cached=/audit/archive-prefix ;;
            *) cached=/audit/archive-full ;;
        esac
        cp "$cached" "$root/state/update-download/$digest"
        ;;
    *) exec "$manager" update-rollback --root "$root" --service /audit/adapter.sh ;;
esac
printf 'file:///audit/strace-packages/packages.adb\\n' > /audit/repos
apk --no-network --repositories-file /audit/repos add strace
case "$R2O_AUDIT_PHASE" in
    public-*) set -- update-install --root "$root" --service /audit/adapter.sh --release "$target" --source github ;;
    *) set -- update-rollback --root "$root" --service /audit/adapter.sh ;;
esac
strace -o /audit/update.trace -e "trace=$syscall" -e "inject=$syscall:delay_enter=3s" \\
    sh -c 'echo $$ >/audit/update-pid; exec "$@"' sh "$manager" "$@" &
tracer=$!
cut_ready() {
    case "$R2O_AUDIT_PHASE" in
        stage-ready) [ -s "$staged" ] && [ ! -e "$journal" ] ;;
        commit-recorded) grep -qs '"committed":true' "$journal" && grep -qs '"phase":"commit"' "$status" ;;
        public-*) [ ! -e "$journal" ] && grep -qs "\\\"phase\\\":\\\"${R2O_AUDIT_PHASE#public-}\\\"" "$status" ;;
    esac
}
while ! cut_ready; do
    kill -0 "$tracer"
    sleep 1
done
kill -STOP "$(cat /audit/update-pid)"
sync
cut_ready
printf 'R2O_POWER_CUT_NOW\\n'
exec sleep 120
"""

ADAPTER = """#!/bin/sh
set -eu
if [ "$1" = "$R2O_AUDIT_PHASE" ]; then
    printf 'R2O_POWER_CUT_NOW\\n'
    exec sleep 120
fi
"""


def boot(command, token, log, timeout=90):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as vm:
        deadline = time.monotonic() + timeout
        received = b""
        try:
            with log.open("wb", buffering=0) as output:
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
    parser.add_argument("--strace-packages", type=Path, help="Каталог с OpenWrt strace APK и подписанным packages.adb")
    parser.add_argument("--public-update", nargs=2, type=Path, metavar=("ARCHIVE", "MANIFEST"),
                        help="Дополнительно проверить загрузку публичного ARM64-выпуска")
    parser.add_argument("--phase", action="append", help="Запустить только выбранную фазу, можно указать несколько раз")
    args = parser.parse_args()
    args.logs.mkdir(parents=True, exist_ok=True)
    phases = ["update-stop", "update-start", "update-health"]
    packages = []
    internet = []
    if args.strace_packages is not None:
        packages = [args.strace_packages / "packages.adb", *sorted(args.strace_packages.glob("*.apk"))]
        if len(packages) < 2 or not all(package.is_file() for package in packages):
            parser.error("Нужны packages.adb и APK strace для гостевого OpenWrt")
        phases = ["stage-ready", *phases, "commit-recorded"]
    if args.public_update:
        if not packages:
            parser.error("--public-update требует --strace-packages")
        archive, manifest_path = args.public_update
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        release_id = manifest["release_id"]
        expected = manifest["assets"]["aarch64-openwrt-musl"]["sha256"]
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", release_id) or digest != expected:
                parser.error("Тег или SHA-256 публичного архива не совпадают")
        internet = [f"public-{phase}" for phase in ("check", "download", "verify", "stage", "migrate")]
        phases += internet
    if args.phase:
        if not set(args.phase).issubset(phases):
            parser.error("Выбранная фаза недоступна с указанными параметрами")
        phases = list(dict.fromkeys(args.phase))
    with tempfile.TemporaryDirectory(prefix="r2o-qemu-update-") as dirname:
        work = Path(dirname)
        disk = work / "rootfs.ext4"
        with gzip.open(args.rootfs_gzip, "rb") as source, disk.open("wb") as target:
            shutil.copyfileobj(source, target)
        if internet:
            with disk.open("r+b") as image:
                image.truncate(max(disk.stat().st_size, 192 * 1024 * 1024))
            subprocess.run(["resize2fs", disk], check=True, capture_output=True)
        files = {"guest-init.sh": GUEST_INIT, "adapter.sh": ADAPTER}
        for name, body in files.items():
            path = work / name
            path.write_text(body, encoding="utf8")
            path.chmod(0o755)
        bundled = work / "r2o-manager"
        shutil.copyfile(args.manager, bundled)
        bundled.chmod(0o755)
        commands = work / "debugfs"
        entries = ["mkdir /audit", *(f"write {work / name} /audit/{name}" for name in [*files, "r2o-manager"])]
        if packages:
            entries.append("mkdir /audit/strace-packages")
            for package in packages:
                staged = work / package.name
                shutil.copyfile(package, staged)
                entries.append(f"write {staged} /audit/strace-packages/{package.name}")
        if internet:
            prefix = work / "archive-prefix"
            with archive.open("rb") as source:
                prefix.write_bytes(source.read(1024 * 1024))
            entries.append(f"write {prefix} /audit/archive-prefix")
            complete = work / "archive-full"
            shutil.copyfile(archive, complete)
            entries.append(f"write {complete} /audit/archive-full")
        commands.write_text("\n".join(entries) + "\n", encoding="utf8")
        subprocess.run(["debugfs", "-w", "-f", commands, disk], check=True, capture_output=True)
        for phase in phases:
            case_disk = work / f"{phase}.ext4"
            shutil.copyfile(disk, case_disk)
            kernel_args = f"root=/dev/vda rw console=ttyAMA0 init=/audit/guest-init.sh r2o_audit_phase={phase}"
            network = ["-nic", "none"]
            if phase in internet:
                kernel_args += f" r2o_audit_release={manifest['release_id']} r2o_audit_archive={expected}"
                network = ["-netdev", "user,id=wan", "-device", "virtio-net-device,netdev=wan"]
            vm = [
                "qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "256",
                "-kernel", args.kernel, "-append", kernel_args,
                "-drive", f"file={case_disk},format=raw,if=none,id=disk,cache=none",
                "-device", "virtio-blk-device,drive=disk", "-display", "none", "-monitor", "none",
                "-serial", "stdio", *network, "-no-reboot",
            ]
            boot(vm, b"R2O_POWER_CUT_NOW", args.logs / f"{phase}-before-powercut.log", 150 if phase in internet else 90)
            boot(vm, b"R2O_RECOVERY_OK", args.logs / f"{phase}-after-powercut.log")
            print(f"OpenWrt QEMU проверил слоты и данные после отключения в {phase}")


if __name__ == "__main__":
    main()
