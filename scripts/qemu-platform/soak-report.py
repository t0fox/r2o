#!/usr/bin/env python3
"""Извлекает длительность, CPU, PSS и файловые дескрипторы из serial-журнала."""
import argparse
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("logs", nargs="+", type=Path)
parser.add_argument("--clock-ticks", type=int, default=100, help="USER_HZ гостевого Linux")
args = parser.parse_args()


def report(path):
    samples = {}
    elapsed = None
    process = None
    uptime = None
    responses = 0
    for line in path.read_text(errors="replace").splitlines():
        marker = re.fullmatch(r"SOAK_SAMPLE elapsed_s=(\d+)", line)
        if marker:
            elapsed = int(marker[1])
            samples[elapsed] = {}
        tracked = re.fullmatch(r"VmHWM:=(\d+) VmRSS:=(\d+) Threads:=(\d+) pid=(\d+) cpu_ticks=(\d+) start_ticks=(\d+)", line)
        if tracked and elapsed is not None:
            hwm, rss, threads, pid, cpu, start = map(int, tracked.groups())
            process = samples[elapsed][pid] = {"rss": rss, "hwm": hwm, "threads": threads, "cpu": cpu, "start": start}
        if process is not None:
            for key in ("pss_kib", "fd_count"):
                if line.startswith(key + "="):
                    process[key] = int(line.split("=", 1)[1])
        if line.startswith("LAN_RESPONSE_PASS ") and elapsed is not None:
            responses += 1
        passed = re.fullmatch(r"SOAK_PASS elapsed_s=(\d+) samples=(\d+)", line)
        if passed and samples:
            uptime, expected = map(int, passed.groups())
            break
    if uptime is None or not samples or len(samples) != expected or responses != expected * 6:
        raise ValueError(f"{path}: неполный результат теста стабильности")
    first = samples[min(samples)]
    last = samples[max(samples)]
    if uptime != max(samples) or not first or any(sample.keys() != first.keys() for sample in samples.values()):
        raise ValueError(f"{path}: неполные снимки процессов")
    for pid, metric in first.items():
        if any(sample[pid]["start"] != metric["start"] for sample in samples.values()):
            raise ValueError(f"{path}: PID {pid} был переиспользован")
    all_pss = all("pss_kib" in p for sample in samples.values() for p in sample.values())
    return {
        "log": str(path), "elapsed_s": uptime, "samples": len(samples), "lan_responses": responses,
        "rss_first_kib": sum(p["rss"] for p in first.values()),
        "rss_last_kib": sum(p["rss"] for p in last.values()),
        "rss_peak_kib": max(sum(p["rss"] for p in sample.values()) for sample in samples.values()),
        "pss_first_kib": sum(p["pss_kib"] for p in first.values()) if all_pss else None,
        "pss_last_kib": sum(p["pss_kib"] for p in last.values()) if all_pss else None,
        "pss_peak_kib": max(sum(p["pss_kib"] for p in sample.values()) for sample in samples.values()) if all_pss else None,
        "fds_first": sum(p["fd_count"] for p in first.values()),
        "fds_last": sum(p["fd_count"] for p in last.values()),
        "cpu_seconds": round(sum(last[pid]["cpu"] - p["cpu"] for pid, p in first.items()) / args.clock_ticks, 3),
    }


print(json.dumps([report(path) for path in args.logs], ensure_ascii=False, indent=2))
