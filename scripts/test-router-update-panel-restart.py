#!/usr/bin/env python3
"""Проверка обновления через HTTP после SIGKILL и перезапуска панели."""

import argparse
import hashlib
import json
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ARCH = "x86_64-musl"
BASE = "r2o-panel-restart-base"
NEXT = "r2o-panel-restart-next"

SERVICE = """#!/bin/sh
set -eu
case "$1" in
    update-install|update-rollback)
        action=$1
        shift
        printf '%s\\n' "$action" >> "$WORK/launches"
        exec "$MANAGER" "$action" --root "$ROOT" --service "$0" "$@"
        ;;
    update-stop)
        printf '%s\\n' "$PPID" > "$WORK/at-stop"
        for attempt in $(seq 1 300); do
            if [ -e "$WORK/continue" ]; then exit 0; fi
            sleep .1
        done
        exit 1
        ;;
    update-start|update-health) exit 0 ;;
    *) exit 2 ;;
esac
"""


def wait_for(action, matches, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = action()
            if matches(value):
                return value
        except (FileNotFoundError, urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(.02)
    raise AssertionError("Стенд не достиг ожидаемого состояния")


def run(work, manager, panel, public):
    root = work / "root"
    bundle = work / "bundle"
    builds = bundle / "builds"
    builds.mkdir(parents=True)
    (bundle / "router").mkdir()
    (bundle / "router/update-schema").write_text("R2O-STATE-1\n")
    (bundle / "router/update-sequence").write_text("1\n")
    for component in ("datapath", "controller", "panel", "telegram", "manager", "fetch"):
        name = builds / f"r2o-{component}-linux-{ARCH}"
        shutil.copyfile(manager, name)
        name.chmod(0o755)
    for tag in [NEXT] if public else [BASE, NEXT]:
        subprocess.run([manager, "install-local", "--root", root, "--bundle", bundle,
                        "--release-id", tag, "--architecture", ARCH], check=True, stdout=subprocess.DEVNULL)
    state = root / "state"
    state.mkdir(exist_ok=True)
    config = root / "config"
    catalog = state / "catalog.json"
    config.write_bytes(b"MODE=observe\n")
    catalog.write_bytes(b'{"schema":1,"boxes":[],"note":"panel-restart-fixture"}\n')
    adapter = work / "adapter"
    assignments = {"MANAGER": manager, "ROOT": root, "WORK": work}
    adapter.write_text(SERVICE.replace("set -eu\n", "set -eu\n" + "".join(
        f"{name}={shlex.quote(str(path))}\n" for name, path in assignments.items()), 1))
    adapter.chmod(0o700)
    action = "update-rollback"
    expected = BASE
    if public:
        archive, manifest = public
        release = json.loads(manifest.read_text())
        expected = release["release_id"]
        digest = release["assets"][ARCH]["sha256"]
        with archive.open("rb") as handle:
            assert hashlib.file_digest(handle, "sha256").hexdigest() == digest
        downloads = state / "update-download"
        downloads.mkdir()
        shutil.copyfile(archive, downloads / digest)
        action = f"update-select/{expected}/github"

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        authority = f"127.0.0.1:{listener.getsockname()[1]}"
    origin = f"http://{authority}"
    args = [panel, "serve", "--listen", authority, "--config", config,
            "--state-dir", state, "--manager", root / "r2o-manager", "--manager-root", root,
            "--service", adapter]

    def request(path, method="GET"):
        req = urllib.request.Request(origin + path, method=method, headers={"Origin": origin})
        try:
            with urllib.request.urlopen(req, timeout=1) as reply:
                return reply.status, json.load(reply)
        except urllib.error.HTTPError as reply:
            return reply.code, json.load(reply)

    def start(log):
        with (work / log).open("w") as output:
            return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=output)

    def update():
        return request("/api/update")[1]

    first = start("panel-initial.log")
    second = None
    updating = False
    try:
        wait_for(lambda: request("/api/status"), lambda reply: reply[0] == 200)
        assert request(f"/api/control/{action}", "POST")[0] == 202
        updating = True
        manager_pid = wait_for(lambda: int((work / "at-stop").read_text()), bool, 40)
        assert update()["phase"] == "activate"
        first.kill()
        assert first.wait(timeout=5) == -9
        second = start("panel-restarted.log")
        visible = wait_for(update, lambda value: value.get("phase") == "activate")
        assert visible["busy"] == "activating", visible
        assert request("/api/status")[0] == 200
        assert manager_pid > 1 and Path(f"/proc/{manager_pid}/cmdline").exists()
        code, reply = request(f"/api/control/{action}", "POST")
        (work / "continue").touch()
        installed = wait_for(update, lambda value: value.get("phase") == "commit", 20)
        assert installed["current"] == expected and installed["previous"] is None, installed
        wait_for(lambda: list((root / "releases").iterdir()), lambda slots: [slot.name for slot in slots] == [expected])
        assert installed["last_ok"] and installed["history"][-1]["healthy"], installed
        assert config.read_bytes() == b"MODE=observe\n"
        assert catalog.read_bytes() == b'{"schema":1,"boxes":[],"note":"panel-restart-fixture"}\n'
        assert code == 409, (code, reply)
        assert len((work / "launches").read_text().splitlines()) == 1
        print(f"Панель пережила SIGKILL, HTTP {code} на повторный запуск, активен {expected}")
    finally:
        (work / "continue").touch()
        if updating:
            subprocess.run(["flock", "-w", "8", state / "update-router.lock", "true"])
        for child in (first, second):
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manager", type=Path)
    parser.add_argument("panel", type=Path)
    parser.add_argument("--public-release", nargs=2, type=Path, metavar=("ARCHIVE", "MANIFEST"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="r2o-panel-restart-") as directory:
        run(Path(directory), args.manager.resolve(), args.panel.resolve(), args.public_release)
