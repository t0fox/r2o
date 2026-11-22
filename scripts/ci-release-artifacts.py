#!/usr/bin/env python3
"""Выбор и проверка бинарников успешного CI для подписанного выпуска."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import sys
from zoneinfo import ZoneInfo


ABIS = (
    "mipsel", "mipsel-openwrt-musl", "aarch64-openwrt-musl", "armv5-musleabi",
    "armv7-openwrt-musl", "armv7-musleabi", "mips-openwrt-musl", "mips64el-musl",
    "x86_64-musl", "i686-musl", "powerpc64-musl", "riscv64-musl",
)
BINARIES = tuple(f"r2o-{name}" for name in (
    "datapath", "controller", "panel", "telegram", "manager", "fetch", "detect",
))
WORKFLOW = ".github/workflows/ci.yml"


def trusted_run(run, sha, repo):
    return (
        run["path"] == WORKFLOW
        and run["head_sha"] == sha
        and run["head_branch"] == "main"
        and run["event"] in {"push", "workflow_dispatch"}
        and (run.get("head_repository") or {}).get("full_name") == repo
    )


def select_run(runs, sha, repo):
    candidates = [run for run in runs if trusted_run(run, sha, repo)]
    if not candidates:
        raise ValueError("нет запуска CI для этого коммита main")
    run = max(candidates, key=lambda run: run["id"])
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise ValueError(f"последний CI {run['id']} не завершился успешно")
    return run


def artifact_name(sha, abi, attempt):
    return f"r2o-bin-{sha}-{abi}-a{attempt}"


def select_artifacts(jobs, artifacts, sha, run, attempt, repo_id):
    selected = {}
    for abi in ABIS:
        matches = [job for job in jobs if job["name"] == f"Выпуск ABI — {abi}"]
        if not matches:
            raise ValueError(f"нет задания сборки {abi}")
        job = max(matches, key=lambda job: (job["run_attempt"], job["id"]))
        if (job["run_id"] != run or job["head_sha"] != sha or job["run_attempt"] > attempt
                or job["status"] != "completed" or job["conclusion"] != "success"):
            raise ValueError(f"задание сборки {abi} не прошло проверку")
        name = artifact_name(sha, abi, job["run_attempt"])
        matches = [asset for asset in artifacts if asset["name"] == name]
        if len(matches) != 1:
            raise ValueError(f"ожидался ровно один артефакт {name}")
        asset = matches[0]
        source = asset["workflow_run"]
        if (asset["expired"] or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or "")
                or source["id"] != run or source["head_sha"] != sha or source["head_branch"] != "main"
                or source["repository_id"] != repo_id or source["head_repository_id"] != repo_id):
            raise ValueError(f"артефакт {name} устарел или не соответствует успешному запуску CI")
        selected[name] = {"abi": abi, "attempt": job["run_attempt"], "id": asset["id"]}
    return selected


def metadata(sha, run_id, abi, attempt):
    return {"sha": sha, "run_id": run_id, "abi": abi, "attempt": attempt}


def checksums(directory):
    lines = []
    for name in BINARIES:
        binary = directory / name
        if binary.is_symlink() or not binary.is_file() or not binary.stat().st_size:
            raise ValueError(f"отсутствует обычный непустой бинарник {binary}")
        with binary.open("rb") as source:
            lines.append(f"{hashlib.file_digest(source, 'sha256').hexdigest()}  {name}\n")
    return "".join(lines)


def prepare(downloads, builds, selected, sha, run_id):
    if {entry.name for entry in downloads.iterdir()} != set(selected):
        raise ValueError("набор скачанных артефактов не совпадает с планом CI")
    for name, info in selected.items():
        abi, attempt = info["abi"], info["attempt"]
        directory = downloads / name
        expected_names = set(BINARIES) | {"SHA256SUMS", "build-info.json"}
        if directory.is_symlink() or {entry.name for entry in directory.iterdir()} != expected_names:
            raise ValueError(f"неожиданный состав артефакта {name}")
        for entry in directory.iterdir():
            if entry.is_symlink() or not entry.is_file():
                raise ValueError(f"артефакт содержит недопустимый файл {entry}")
        if json.loads((directory / "build-info.json").read_text()) != metadata(sha, run_id, abi, attempt):
            raise ValueError(f"метаданные артефакта {name} не совпадают с CI")
        if (directory / "SHA256SUMS").read_text() != checksums(directory):
            raise ValueError(f"не совпадает SHA-256 бинарников {name}")
        stage = builds / abi
        stage.mkdir(parents=True)
        for binary in BINARIES:
            (directory / binary).chmod(0o755)
        subprocess.run(["sh", "scripts/check-release-abi.sh", abi, directory, "--elf-only"], check=True)
        for binary in BINARIES:
            shutil.copyfile(directory / binary, stage / f"{binary}-linux-{abi}")


def pages(path, key):
    return [item for page in json.loads(Path(path).read_text()) for item in page[key]]


def main(command, *args):
    if command == "identity":
        sha, run = args
        epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", sha]))
        stamp = datetime.fromtimestamp(epoch, timezone.utc)
        print(f"release_id=r2o-{stamp:%Y%m%d-%H%M}-{sha[:7]}-{int(run)}")
        print(f"title=R2O {stamp.astimezone(ZoneInfo('Europe/Simferopol')):%d.%m.%Y} ({sha[:7]})")
    elif command == "run":
        runs, sha, repo = args
        run = select_run(pages(runs, "workflow_runs"), sha, repo)
        print(run["id"], run["run_attempt"])
    elif command == "record":
        path, sha, run, abi, attempt = args
        directory = Path(path)
        (directory / "build-info.json").write_text(json.dumps(metadata(sha, int(run), abi, int(attempt))))
        (directory / "SHA256SUMS").write_text(checksums(directory))
    elif command == "select":
        jobs, artifacts, sha, run, attempt, repo_id, output = args
        selected = select_artifacts(pages(jobs, "jobs"), pages(artifacts, "artifacts"), sha,
                                    int(run), int(attempt), int(repo_id))
        Path(output).write_text(json.dumps(selected))
        print(",".join(str(info["id"]) for info in selected.values()))
    elif command == "prepare":
        downloads, builds, plan, sha, run = args
        prepare(Path(downloads), Path(builds), json.loads(Path(plan).read_text()), sha, int(run))
        print(" ".join(ABIS))
    else:
        raise ValueError(f"неизвестная команда: {command}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Проверка CI: {error}")
