#!/usr/bin/env python3
"""Приёмка Keenetic с двумя отдельными загрузками одного тестового USB-диска."""
import argparse
import os
import select
import subprocess
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("model", choices=["KN-1910", "KN-3810"])
parser.add_argument("--qemu", required=True)
parser.add_argument("--qemu-data", required=True)
parser.add_argument("--kernel", required=True)
parser.add_argument("--initramfs", required=True)
parser.add_argument("--firmware-rootfs", required=True)
parser.add_argument("--opt", required=True)
parser.add_argument("--log", required=True)
parser.add_argument("--root-device", default="/dev/sda")
parser.add_argument("--usb-opt", action="store_true")
parser.add_argument("--entropy", action="store_true")
parser.add_argument("--smp", type=int, default=1)
parser.add_argument("--ram", type=int)
parser.add_argument("--soak", type=int, default=600)
parser.add_argument("--measure", action="store_true", help="Замер холодного и тёплого подбора из TLS-фикстуры")
parser.add_argument("--phase", choices=["install", "reboot", "discovery", "discovery-after-boot"], required=True)
args = parser.parse_args()
if args.measure and args.phase not in {"discovery", "discovery-after-boot"}:
    parser.error("--measure применяется к фазам discovery")
discovery_markers = (("KEENETIC_DISCOVERY_MEASURE_PASS",) if args.measure else
                     ("KEENETIC_TLS_DISCOVERY_PASS", "KEENETIC_TLS_REUSE_PASS"))
discovery_timeout = 420 if args.measure else 250
ram = args.ram or (128 if args.model == "KN-1910" else 256)
cmd = [
    args.qemu, "-L", args.qemu_data, "-M", "malta", "-cpu", "34Kf" if args.smp > 1 else "24Kf",
    "-smp", str(args.smp), "-m", str(ram), "-nodefaults", "-display", "none",
    "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
    "-kernel", args.kernel, "-initrd", args.initramfs, "-append",
    f"console=ttyS0 ndm.root={args.root_device} rdinit=/init ndm.zram=0 ndm.ballast=0 ndm.net=none loglevel=6",
    "-drive", f"file={args.firmware_rootfs},format=raw,if=ide,index=0,snapshot=on",
]
if args.usb_opt:
    cmd += ["-device", "qemu-xhci,id=xhci", "-drive",
            f"file={args.opt},format=raw,if=none,id=opt",
            "-device", "usb-storage,bus=xhci.0,drive=opt"]
else:
    cmd += ["-drive", f"file={args.opt},format=raw,if=ide,index=1"]

if args.entropy:
    cmd += ["-object", "rng-random,id=testrng,filename=/dev/urandom",
            "-device", "virtio-rng-pci,rng=testrng"]

if args.phase in {"reboot", "discovery-after-boot"}:
    cmd[cmd.index("-append") + 1] += " ndm.auto=1 ndm.chroot=0 ndm.disk=R2OLAB"

with Path(args.log).open("wb") as log, subprocess.Popen(
    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    env={**os.environ, "QEMU_AUDIO_DRV": "none"},
) as proc:
    pending = b""

    def expect(pattern, timeout):
        global pending
        end = time.monotonic() + timeout
        while (pos := pending.find(pattern)) < 0:
            remaining = end - time.monotonic()
            if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
                raise RuntimeError(f"timeout while waiting for {pattern!r}")
            block = os.read(proc.stdout.fileno(), 65536)
            if not block:
                raise RuntimeError(f"QEMU ended before {pattern!r}")
            log.write(block)
            log.flush()
            pending += block
        observed, pending = pending[:pos + len(pattern)], pending[pos + len(pattern):]
        return observed

    def issue(command, *markers, timeout=25):
        log.write(f"\nHOST_COMMAND {command}\n".encode())
        log.flush()
        proc.stdin.write((command + "\n").encode())
        proc.stdin.flush()
        reply = expect(b"\n= ", timeout) + expect(b"\n", timeout)
        if not reply.replace(b"\r", b"").endswith(b"= ok\n") or any(m.encode() not in reply for m in markers):
            raise RuntimeError(f"failed command {command!r}: {reply[-1000:]!r}")

        return reply

    def await_boot():
        try:
            expect(b"R2O_BOOT_INITRC_PASS", 45)
        except RuntimeError:
            issue("cat /tmp/r2o-autoboot.log", timeout=15)
            expect(b"R2O_BOOT_INITRC_PASS", 80)
        expect(b"initrc finished: initrc started", 25)

    try:
        expect(b"fake NDM started on Linux", 45)
        expect(b"\n", 5)
        if args.phase in {"install", "discovery"}:
            issue("show status", "opkg disk was never set")
            issue("show mounts", "squashfs ro")
            issue("opkg disk R2OLAB:/", "ENTWARE_INSTALL_PASS", timeout=175)
            issue("exec /opt/lab/lifecycle.sh prepare", "PREPARE_PASS", timeout=90)
            issue("exec /opt/lab/lifecycle.sh clean", "CLEAN_INSTALL_PASS", timeout=120)
            if args.phase == "discovery":
                issue("exec /opt/lab/keenetic-discovery.sh", *discovery_markers, timeout=discovery_timeout)
            else:
                issue("exec /opt/lab/lifecycle.sh uninstall", "UNINSTALL_PASS", timeout=90)
                issue("exec /opt/lab/lifecycle.sh upgrade", "PUBLISHED_UPGRADE_PASS", timeout=180)
        elif args.phase == "discovery-after-boot":
            expect(b"initrc finished: initrc started", 130)
            issue("exec /opt/lab/keenetic-discovery.sh", *discovery_markers, timeout=discovery_timeout)
        else:
            await_boot()
            issue("exec /opt/lab/lifecycle.sh reboot-network", timeout=60)
            issue("exec /opt/lab/lifecycle.sh rebooted", "AUTOBOOT_PASS", timeout=120)
            issue(f"exec /opt/lab/lifecycle.sh soak-start {args.soak}", "SOAK_STARTED")
            # Malta под TCG может продвигать гостевые часы медленнее часов хоста.
            deadline = time.monotonic() + args.soak * 2 + 60
            while True:
                reply = issue("exec /opt/lab/lifecycle.sh soak-status")
                if b"SOAK_FAIL" in reply or time.monotonic() > deadline:
                    issue("cat /tmp/r2o-soak.log")
                    for component in ("datapath", "controller"):
                        for suffix in ("", "4", "6"):
                            try:
                                issue(f"cat /opt/r2o/log/r2o-{component}{suffix}.log", timeout=8)
                            except RuntimeError:
                                pass
                    raise RuntimeError("тест стабильности завершился ошибкой или тайм-аутом")
                if b"SOAK_PASS" in reply:
                    issue("cat /tmp/r2o-soak.log", "SOAK_PASS")
                    break
                time.sleep(15)
            issue("exec /opt/lab/lifecycle.sh uninstall", "UNINSTALL_PASS", timeout=90)
        issue("poweroff")
        expect(b"Emulator: exit status 0", 75)
        proc.wait(timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"QEMU shutdown code {proc.returncode}")
        log.write(b"\nHOST_RESULT PASS\n")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as err:
        log.write(f"HOST_RESULT FAIL {err}\n".encode())
        print(f"{args.model}: {err}", file=sys.stderr)
        sys.exit(1)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
