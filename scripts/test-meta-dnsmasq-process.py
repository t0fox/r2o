#!/usr/bin/env python3
"""Exercise the current Meta hosts publisher against two real dnsmasq processes.

The standalone crate copies the production adapter, its parent helpers, and the
Meta hostname classifier verbatim. Only service inspection and signal IPC use a
Runtime fixture; SIGHUP reaches a real child process. The fixture uses loopback
high ports, temporary configuration, and a local upstream. It never changes the
host DNS configuration, UCI, or a system service.

This is DNS process integration, not OpenWrt procd/ujail or router acceptance.
The host must permit dnsmasq's normal netlink sockets. If it cannot, --build-only
produces a test executable for a disposable Linux guest; do not replace kernel
operations with mocks to claim a passing live DNS test.

Examples:
  python3 -B scripts/test-meta-dnsmasq-process.py --dnsmasq /usr/sbin/dnsmasq
  python3 -B scripts/test-meta-dnsmasq-process.py --offline --build-only \
      --work-dir /tmp/r2o-meta-dns-build

Inside a disposable guest, use a 180-second timeout for the reported executable,
with DNSMASQ_BIN pointing to dnsmasq and DNSMASQ_TEST_WORK pointing to a new
writable directory. Pass --nocapture --test-threads=1 to include the JSON result.
Set R2O_DNSMASQ_TEST_ENV to describe the guest in that result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import tomllib


def positive_seconds(value: str) -> int:
    seconds = int(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return seconds


def run_bounded(command: list[str], timeout: int, **options) -> subprocess.CompletedProcess:
    process = subprocess.Popen(command, start_new_session=True, **options)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        # This session contains only the harness/cargo and its own children.
        # Terminate the whole group so a timed-out test cannot leave dnsmasq
        # listening after the parent test executable has exited.
        for signum in [signal.SIGTERM, signal.SIGKILL]:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                break
            try:
                process.communicate(timeout=5)
                break
            except subprocess.TimeoutExpired:
                continue
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise RuntimeError(f"command exceeded its {timeout}-second timeout: {command[0]}") from None


def parent_function(source: str, name: str) -> str:
    match = re.search(rf"(?m)^fn {re.escape(name)}\(", source)
    if match is None:
        raise RuntimeError(f"production parent helper was not found: {name}")
    # Rust top-level functions in this module close at column zero. Fail rather
    # than substitute a fixture implementation if their shape changes.
    end = source.find("\n}", match.start())
    if end < 0:
        raise RuntimeError(f"production parent helper was not complete: {name}")
    return source[match.start():end + 2]


def pinned_dependencies(repo: Path) -> str:
    packages = tomllib.loads((repo / "Cargo.lock").read_text())["package"]
    dependencies = []
    for name in ["libc", "serde", "serde_json", "sha2", "hex"]:
        candidates = [item["version"] for item in packages if item["name"] == name]
        if name == "sha2":
            candidates = [version for version in candidates if version.startswith("0.10.")]
        if len(candidates) != 1:
            raise RuntimeError(f"expected one locked {name} version, found {candidates}")
        version = candidates[0]
        if name == "serde":
            dependencies.append(f'{name} = {{ version = "={version}", features = ["derive"] }}')
        else:
            dependencies.append(f'{name} = "={version}"')
    return "\n".join(dependencies)


def build(repo: Path, work: Path, cargo: str, offline: bool, timeout: int) -> Path:
    crate = work / "crate"
    crate.mkdir(parents=True, exist_ok=True)
    manifest = crate / "Cargo.toml"
    package = "r2o-dnsmasq-host-integration"
    if manifest.exists() and tomllib.loads(manifest.read_text()).get("package", {}).get("name") != package:
        raise RuntimeError(f"refusing to replace an unrelated crate: {manifest}")
    manifest.write_text(
        f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2024"\n'
        '\n[lib]\npath = "lib.rs"\n\n[profile.test]\ndebug = 0\nincremental = false\n\n[dependencies]\n'
        + pinned_dependencies(repo) + "\n"
    )
    adapter = repo / "crates/r2o-telegram/src/meta_dns/dnsmasq.rs"
    source = adapter.read_text()
    (crate / "dnsmasq.rs").write_text(
        source + '\n#[cfg(test)]\n#[path = "host_integration.rs"]\nmod host_integration;\n'
    )
    helpers = ["dnsmasq_section", "is_managed_host", "read_manifest", "atomic_write_with_mode"]
    parent = (repo / "crates/r2o-telegram/src/meta_dns.rs").read_text()
    (crate / "lib.rs").write_text(
        "#![allow(dead_code)]\n"
        "use std::collections::BTreeSet;\nuse std::io::{self, Write};\n"
        "use std::net::IpAddr;\nuse std::path::Path;\n"
        '#[path = "classifier.rs"]\nmod meta;\nuse meta::product as meta_family;\n'
        "type PinPair = (String, String);\nmod dnsmasq;\n\n"
        + "\n\n".join(parent_function(parent, name) for name in helpers) + "\n"
    )
    shutil.copyfile(repo / "crates/r2k-core/src/meta.rs", crate / "classifier.rs")
    shutil.copyfile(repo / "scripts/fixtures/meta-dnsmasq-process.rs", crate / "host_integration.rs")
    provenance = {
        "adapter_source": str(adapter),
        "adapter_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "copied_parent_helpers": helpers,
        "classifier_source": "crates/r2k-core/src/meta.rs",
        "injection": "Runtime inspection and signal IPC only; real child receives SIGHUP",
    }
    (work / "source-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    command = [cargo, "test", "--manifest-path", str(manifest), "--lib", "--no-run", "--message-format=json"]
    if offline:
        command.append("--offline")
    result = run_bounded(command, timeout, cwd=crate, text=True, stdout=subprocess.PIPE)
    binary = None
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            print(line)
            continue
        if item.get("reason") == "compiler-message":
            message = item.get("message", {}).get("rendered")
            if message:
                print(message, end="")
        if item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test"):
            binary = item.get("executable") or binary
    if result.returncode:
        raise RuntimeError(f"integration crate build failed with exit {result.returncode}")
    if not binary:
        raise RuntimeError("cargo did not report a test executable")
    print(f"Adapter SHA256: {provenance['adapter_sha256']}")
    print(f"Test executable: {binary}")
    return Path(binary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dnsmasq", default="dnsmasq", help="dnsmasq executable (unused with --build-only)")
    parser.add_argument("--cargo", default="cargo", help="Cargo executable from the project Rust toolchain")
    parser.add_argument("--work-dir", type=Path, help="retain build, provenance, logs, and JSON result here")
    parser.add_argument("--offline", action="store_true", help="use only locally cached Cargo dependencies")
    parser.add_argument("--build-only", action="store_true", help="prepare executable for a disposable Linux guest")
    parser.add_argument("--timeout", type=positive_seconds, default=180, help="test timeout in seconds (default: 180)")
    parser.add_argument("--build-timeout", type=positive_seconds, default=600, help="build timeout in seconds (default: 600)")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    work = (args.work_dir or Path(tempfile.mkdtemp(prefix="r2o-meta-dnsmasq-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    print(f"Integration work directory: {work}", flush=True)
    binary = build(repo, work, args.cargo, args.offline, args.build_timeout)
    if args.build_only:
        return 0
    executable = shutil.which(args.dnsmasq)
    if not executable:
        raise RuntimeError(f"dnsmasq executable not found: {args.dnsmasq}")
    run = work / "run"
    if run.exists():
        raise RuntimeError(f"use a fresh --work-dir; preserving the existing test state: {run}")
    environment = dict(os.environ, DNSMASQ_BIN=str(Path(executable).resolve()), DNSMASQ_TEST_WORK=str(run))
    return run_bounded(
        [str(binary), "--nocapture", "--test-threads=1"], args.timeout, env=environment
    ).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as failure:
        raise SystemExit(str(failure)) from failure
