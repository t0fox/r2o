#!/bin/sh
# C/Rust differential: dns_service_observe / dns_service_note_applied,
# task-ячейки DNS, live-состояния dns_services и production
# dns_health_start_due/dns_health_finish current main 7a5fab9.
# Health-ветка линкует полный C core/datapath; результат finish подаётся
# mock-полями worker'а, сеть — только закрытый 127.0.0.1:1.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DNS_DONOR_ROOT=${R2O_DNS_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_DNS_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_DNS_SHA=$(git -C "$DNS_DONOR_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_DNS_SHA" != "$EXPECTED_DNS_SHA" ]; then
    printf 'Expected D2O current %s, got %s\n' "$EXPECTED_DNS_SHA" "$ACTUAL_DNS_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-state.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
    -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
    -o "$TEMP/d2o-dns-state" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_state_differential.c" \
    "$DNS_DONOR_ROOT/core/catalog.c" "$DNS_DONOR_ROOT/core/groups.c" \
    "$DNS_DONOR_ROOT/core/domain.c" "$DNS_DONOR_ROOT/runtime/d2k_dns_config.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-dns-state" >"$TEMP/c.json"

R2O_DNS_STATE_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::dns_live_state_differential_matches_current_d2o \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
# В панели R2O используются свои формулировки для тех же состояний.
reasons = {
    "План применён к пробному соединению D2O; корректный DNS-ответ ещё не подтверждён.":
        "План применён к пробному соединению. Корректный DNS-ответ ещё не подтверждён.",
    "Проверяется кандидат штатным конвейером D2O.": "Проверяется кандидат.",
    "Подозрение передано в штатный конвейер D2O.": "Подозрение передано на проверку.",
}
for item in c:
    item.pop("end", None)
    for service in item["dns_services"]:
        reason = service["status_reason"]
        service["status_reason"] = reasons.get(reason, reason)
# Прямой ответ не подтверждает пробу кандидата. Для этой ветки нужен
# отдельный контракт, поскольку донор смешивает два источника ответа.
case = "candidate_without_answer_live_answer"
for snapshots, expected in [(c, ("bypass_ok", True)), (r, ("no_bypass", False))]:
    service = next(item for item in snapshots if item["scenario"] == case)["dns_services"][0]
    assert (service["state"], service["dns_answer_via_plan"]) == expected
    assert service["candidate_plan_applied"] and service["dns_answer_confirmed"]
    del service["state"], service["dns_answer_via_plan"], service["status_reason"]
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: dns_services observe/applied live C/Rust match (current main)")
PY

printf 'cases=%s\n' "$(grep -o '"scenario"' "$TEMP/c.json" | wc -l)"

# --- Production dns_health_start_due/dns_health_finish ---------------------
# Health-ветка start_due требует настоящий sched.c worker, поэтому линкуется
# полный набор C-объектов core/datapath (без libd2k_udp.a: он собирается из
# тех же исходников). Сеть не нужна: проба идёт на закрытый 127.0.0.1:1, а
# результаты finish подаются в поля задачи напрямую.
HEALTH_SRC="verify tls13 tls12 p256 tls13core x25519 crypto quicconn quicwire h3 compose measured hello meas link quicprobe quicsnap quicsnap_reseal quic quicarms ipfrag props voice voice_discovery stun net4 volume plantlv quichello verify_quic_replay catalog groups domain match diagnostics udpplan udpruntime"
HEALTH_DP_SRC="plan_parse plan_apply wire wire_udp"
for name in $HEALTH_SRC; do
    "$CC" -std=gnu11 -O1 -ffunction-sections -fdata-sections \
        -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
        -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
        -c -o "$TEMP/health-$name.o" "$DNS_DONOR_ROOT/core/$name.c"
done
for name in $HEALTH_DP_SRC; do
    "$CC" -std=gnu11 -O1 -ffunction-sections -fdata-sections \
        -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
        -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
        -c -o "$TEMP/dphealth-$name.o" "$DNS_DONOR_ROOT/datapath/$name.c"
done
"$CC" -std=gnu11 -O1 -ffunction-sections -fdata-sections \
    -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
    -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
    -c -o "$TEMP/health-d2k_dns_config.o" "$DNS_DONOR_ROOT/runtime/d2k_dns_config.c"
"$CC" -std=gnu11 -O1 -ffunction-sections -fdata-sections \
    -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
    -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
    -c -o "$TEMP/health-fixture.o" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_health_state_differential.c"
"$CC" -o "$TEMP/d2o-dns-health-state" "$TEMP"/health-*.o \
    "$TEMP"/dphealth-*.o -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-dns-health-state" >"$TEMP/health-c.json"

R2O_DNS_HEALTH_STATE_DIFF_OUTPUT="$TEMP/health-rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::dns_health_state_differential_matches_current_d2o \
    -- --exact >"$TEMP/health-cargo.log" 2>&1

python3 - "$TEMP/health-c.json" "$TEMP/health-rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: dns_health_start_due/finish C/Rust match (current main)")
PY

printf 'health_cases=%s\n' "$(grep -o '"scenario"' "$TEMP/health-c.json" | wc -l)"
