#!/usr/bin/env python3
"""Нарезка реестра C-функций на группы для параллельного аудита."""
from __future__ import annotations

import csv
import json
from pathlib import Path

OUT = Path("/mnt/e/r2o-tooling/audit")
GROUPS = {
    "core-net": [
        "core/hello.c",
        "core/tls12.c",
        "core/tls13.c",
        "core/tls13core.c",
        "core/verify.c",
        "core/verify_quic_replay.c",
        "core/httpsprobe.c",
        "core/httpup_logic.c",
        "core/httpsearch.c",
        "core/h3.c",
        "core/quicwire.c",
        "core/quic.c",
        "core/quichello.c",
        "core/quicsnap.c",
        "core/quicsnap_reseal.c",
        "core/quicprobe.c",
        "core/quicarms.c",
        "core/quicconn.c",
        "core/ipfrag.c",
        "core/stun.c",
        "core/voice.c",
        "core/voice_discovery.c",
        "core/udpplan.c",
        "core/udpruntime.c",
        "core/volume.c",
        "core/include/d2k_http_reply.h",
        "core/include/d2k_ip6frag_send.h",
        "core/include/d2k_quicprobe.h",
        "core/include/d2k_arm.h",
    ],
    "core-state": [
        "core/catalog.c",
        "core/compose.c",
        "core/crypto.c",
        "core/d2kask.c",
        "core/d2kc.c",
        "core/d2kfetch.c",
        "core/d2kvoice.c",
        "core/diagnostics.c",
        "core/domain.c",
        "core/groups.c",
        "core/link.c",
        "core/match.c",
        "core/meas.c",
        "core/measured.c",
        "core/net4.c",
        "core/p256.c",
        "core/plantlv.c",
        "core/props.c",
        "core/sched.c",
        "core/verdict.c",
        "core/x25519.c",
        "core/include/d2k_link.h",
        "core/include/d2k_resource.h",
    ],
    "datapath-core": [
        "datapath/d2kd.c",
        "datapath/session.c",
        "datapath/track.c",
        "datapath/capture.c",
        "datapath/hold.c",
        "datapath/udp_hold.c",
        "datapath/udp_path.c",
        "datapath/udp_release.c",
        "datapath/nfq.c",
        "datapath/nl.c",
        "datapath/icmpguard.c",
        "datapath/http80.c",
        "datapath/http_trace.c",
        "datapath/journal.c",
        "datapath/nat.c",
        "datapath/ctq.c",
        "datapath/sched.c",
        "datapath/wire.c",
        "datapath/wire_udp.c",
        "datapath/addr.c",
        "datapath/tls.c",
        "datapath/include/d2k_ctl.h",
        "datapath/include/d2k_http_request_stream.h",
        "datapath/include/d2k_http_response.h",
        "datapath/include/d2k_packet.h",
        "datapath/include/d2k_track.h",
    ],
    "datapath-plan": [
        "datapath/plans.c",
        "datapath/plan_parse.c",
        "datapath/plan_apply.c",
        "datapath/ctl.c",
        "datapath/ctlsrv.c",
        "datapath/raw.c",
        "datapath/routemark.c",
        "datapath/routemark_nl.c",
        "datapath/include/d2k_plans.h",
    ],
    "detect": [
        "detect/bridge.c",
        "detect/classify.c",
        "detect/main.c",
        "detect/poison.c",
        "detect/props.c",
        "detect/raw.c",
        "detect/response.c",
        "detect/trigger.c",
        "detect/include/d2k_detect.h",
    ],
}


def main() -> int:
    rows = json.loads((OUT / "function-map-a378.json").read_text(encoding="utf-8"))
    by_file: dict[str, list[dict]] = {}
    for row in rows:
        by_file.setdefault(row["file"], []).append(row)
    for name, files in GROUPS.items():
        selected = []
        for file in files:
            if file not in by_file:
                print(f"warning: {name}: no functions for {file}")
                continue
            selected.extend(by_file[file])
        dest = OUT / f"slice-{name}.csv"
        fields = [
            "file",
            "name",
            "line",
            "end_line",
            "lines",
            "static",
            "signature",
            "sha256",
            "rust_candidates",
        ]
        with dest.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in selected:
                out = {key: row.get(key, "") for key in fields}
                out["rust_candidates"] = json.dumps(
                    row.get("rust_candidates", []), ensure_ascii=False
                )
                writer.writerow(out)
        print(f"{name}: {len(selected)} functions -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
