#!/bin/sh
# TG1: donor-interface differential (z2kOW 42c8111 vs r2o-telegram).
# Сравниваются shared CLI/env/defaults; R2O-only modes и пути исключены.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR_ROOT=${R2O_Z2KOW_ROOT:?set R2O_Z2KOW_ROOT to the z2kOW checkout}
EXPECTED_SHA=42c8111765fe5bc5a2a690223df2523e85400eb5
ACTUAL_SHA=$(git -C "$DONOR_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected z2kOW %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-config-interface.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

python3 - "$TEMP/cases.tsv" <<'PY'
import sys
from pathlib import Path

cases = []


def case(name, args="", env=""):
    cases.append(f"{name}\t{args}\t{env}")


case("defaults")
case(
    "all-flags",
    "--check --stats --transparent-ports 443,5222 "
    "--transparent-cidrs 149.154.160.0/20,2001:67c::/32 "
    "--dc-map-refresh-secs 123 --port 2443 --host 127.0.0.1 "
    "--max-connections 42 --verbose --quiet --log-file /tmp/a.log "
    "--cf-domain a.example,b.example --cf-worker-domain worker.example "
    "--cf-balance --cf-ip 1.1.1.1,8.8.8.8 --ws-routing hedged "
    "--ws-hedge-delay-ms 100 --ws-hedge-limit 4 --ws-connect-timeout 11 "
    "--ws-fail-probe-timeout 3 --ws-fail-cooldown 31 "
    "--ws-redirect-cooldown 301 --ip-fail-cooldown 32 "
    "--handshake-timeout 6 --tcp-fallback-timeout 12 "
    "--cf-connect-timeout 13 --cf-fail-cooldown 61 --default-domains",
)
case("check-flag", "--check")
case("stats-flag", "--stats")
case("host-ipv6", "--host ::")
case("host-bracketed", "--host [::1]")
case("port-zero", "--port 0")
case("port-max", "--port 65535")
case("port-overflow", "--port 65536")
case("max-zero", "--max-connections 0")
case("max-invalid", "--max-connections x")
case("ports-empty", "--transparent-ports ''")
case("ports-spaces", "--transparent-ports 443, 5222")
case("cidr-comma", "--transparent-cidrs 149.154.160.0/20,2001:67c::/32")
case("cf-many", "--cf-domain a.example,b.example,c.example")
case("cf-empty", "--cf-domain ''")
case("worker-normalize", "--cf-worker-domain https://Worker.Example/Path")
case("worker-duplicate", "--cf-worker-domain a.example,A.EXAMPLE,a.example")
case("worker-ip", "--cf-worker-domain 1.2.3.4")
case("worker-alias", "--cfproxy-worker-domain worker.example")
case(
    "worker-eight",
    "--cf-worker-domain a.example,b.example,c.example,d.example,"
    "e.example,f.example,g.example,h.example",
)
case(
    "worker-nine",
    "--cf-worker-domain a.example,b.example,c.example,d.example,"
    "e.example,f.example,g.example,h.example,i.example",
)
case("hedge-32", "--ws-hedge-limit 32")
case("hedge-33", "--ws-hedge-limit 33")
case("hedge-negative", "--ws-hedge-limit -1")
for routing in ("adaptive", "sequential", "cf-first", "hedged", "invalid"):
    case(f"routing-{routing}", f"--ws-routing {routing}")
case("cf-ip-invalid", "--cf-ip not-an-ip")
case("cf-ip-v6", "--cf-ip 2606:4700::1111")
case("log-quoted", '--log-file "/tmp/a b.log"')
case("log-unterminated", '--log-file "/tmp/a b.log')
case("backslash", r"--log-file /tmp/a\ b.log")
case("prefixed-name", "probe --port 2443")
case("default-domains", "--default-domains")
case("verbose-short", "-v")
case("quiet-short", "-q")

envs = [
    ("env-check", "TG_CHECK", "true"),
    ("env-check-1", "TG_CHECK", "1"),
    ("env-port", "TG_PORT", "2443"),
    ("env-host", "TG_HOST", "127.0.0.1"),
    ("env-max", "TG_MAX_CONNECTIONS", "42"),
    ("env-verbose", "TG_VERBOSE", "true"),
    ("env-quiet", "TG_QUIET", "true"),
    ("env-log", "TG_LOG_FILE", "/tmp/a.log"),
    ("env-cf", "TG_CF_DOMAIN", "a.example,b.example"),
    ("env-worker", "TG_CF_WORKER_DOMAIN", "worker.example"),
    ("env-balance", "TG_CF_BALANCE", "true"),
    ("env-cf-ip", "TG_CF_IP", "1.1.1.1,8.8.8.8"),
    ("env-routing", "TG_WS_ROUTING", "cf-first"),
    ("env-hedge-delay", "TG_WS_HEDGE_DELAY_MS", "100"),
    ("env-hedge-limit", "TG_WS_HEDGE_LIMIT", "4"),
    ("env-connect", "TG_WS_CONNECT_TIMEOUT", "11"),
    ("env-probe", "TG_WS_FAIL_PROBE_TIMEOUT", "3"),
    ("env-fail", "TG_WS_FAIL_COOLDOWN", "31"),
    ("env-redirect", "TG_WS_REDIRECT_COOLDOWN", "301"),
    ("env-ip-fail", "TG_IP_FAIL_COOLDOWN", "32"),
    ("env-handshake", "TG_HANDSHAKE_TIMEOUT", "6"),
    ("env-tcp", "TG_TCP_FALLBACK_TIMEOUT", "12"),
    ("env-cf-connect", "TG_CF_CONNECT_TIMEOUT", "13"),
    ("env-cf-fail", "TG_CF_FAIL_COOLDOWN", "61"),
    ("env-default-domains", "TG_DEFAULT_DOMAINS", "true"),
    ("env-refresh", "TG_DC_MAP_REFRESH_SECS", "123"),
]
for name, key, value in envs:
    case(name, "", f"{key}={value}")

case("cli-over-env", "--port 2222", "TG_PORT=1111")
case("env-over-default", "", "TG_PORT=1111")
case("multi-env", "", "TG_PORT=1111;TG_HOST=::;TG_WS_ROUTING=hedged")

Path(sys.argv[1]).write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg1_config_trace -- "$TEMP/cases.tsv" \
    > "$TEMP/r2o.out"

DONOR_CRATE="$DONOR_ROOT/platform/openwrt/tg-proxy"
cp -a "$DONOR_CRATE" "$TEMP/donor"
# R2O использует vendored rustls; для offline-сборки донора подставляем его.
printf '\n[patch.crates-io]\nrustls = { path = "%s" }\n' "$ROOT/vendor/rustls" \
    >> "$TEMP/donor/Cargo.toml"
mkdir -p "$TEMP/donor/examples"
sed 's/r2o_telegram/z2kow_tg_transparent/g' \
    "$ROOT/crates/r2o-telegram/examples/tg1_config_trace.rs" \
    > "$TEMP/donor/examples/tg1_config_trace.rs"
CARGO_TARGET_DIR="$TEMP/target-donor" \
    "$CARGO" run --manifest-path "$TEMP/donor/Cargo.toml" --offline \
    -q --example tg1_config_trace -- "$TEMP/cases.tsv" > "$TEMP/donor.out"

if ! diff -u "$TEMP/donor.out" "$TEMP/r2o.out"; then
    printf 'FAIL: z2kOW config interface differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c 'ok=' "$TEMP/r2o.out" || true)"
grep '^all-flags ' "$TEMP/r2o.out" | cut -c1-240
printf 'PASS: z2kOW shared CLI/env/defaults interface matches %s\n' "$ACTUAL_SHA"
