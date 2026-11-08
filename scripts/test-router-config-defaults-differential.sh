#!/bin/sh
# B1: paired C/Rust differential config defaults, MODE fallback and
# KEENETIC_POLICY -> mark.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-b1-config.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
D2O_SERVICE="$D2O_ROOT/files/S99d2k"
R2O_SERVICE="$ROOT/router/S99r2o"

# C-исходник хранится с CRLF; \r ломает разбор функций в dash.
sed -n '/^policy_mark() {/,/^}/p' "$D2O_SERVICE" | tr -d '\r' >"$TEMP/c-policy.sh"
[ -s "$TEMP/c-policy.sh" ] || {
    echo "C policy_mark не найден" >&2
    exit 1
}

mkdir -p "$TEMP/bin" "$TEMP/fixtures"
cat >"$TEMP/bin/ndmc" <<'EOF'
#!/bin/sh
cat "$NDMC_FIXTURE"
EOF
chmod 0755 "$TEMP/bin/ndmc"

cat >"$TEMP/fixtures/basic" <<'EOF'
policy, name = Policy0, description = Guest:
    mark: 1234
policy, name = Policy1, description = Office:
    mark: 00ff
EOF
cat >"$TEMP/fixtures/no-description" <<'EOF'
policy, name = D2Ktest:
    mark: 0abc
EOF
printf '\033[0mpolicy, name = Ansi, description = Guest:\033[0m\n    mark: 77\n' \
    >"$TEMP/fixtures/ansi"
cat >"$TEMP/fixtures/multiple-mark" <<'EOF'
policy, name = Multi, description = Desc:
    mark: 1111
    mark: 2222
EOF

run_policy() {
    impl=$1
    want=$2
    (
        PATH="$TEMP/bin:$PATH"
        export PATH
        if [ "$impl" = c ]; then
            . "$TEMP/c-policy.sh"
            policy_mark "$want"
        else
            . "$ROOT/router/r2o-policy-mark.sh"
            r2o_keenetic_policy_mark "$want"
        fi
    )
}

checks=0
for fixture in basic no-description ansi multiple-mark; do
    NDMC_FIXTURE="$TEMP/fixtures/$fixture"
    export NDMC_FIXTURE
    for want in Policy0 Guest Policy1 Office D2Ktest Ansi Multi Desc Missing; do
        c_mark=$(run_policy c "$want" || true)
        r_mark=$(run_policy r "$want" || true)
        if [ "$c_mark" != "$r_mark" ]; then
            printf 'FAIL: KEENETIC_POLICY %s/%s: C=%s Rust=%s\n' \
                "$fixture" "$want" "$c_mark" "$r_mark" >&2
            exit 1
        fi
        checks=$((checks + 1))
    done
done

normalize_mark() {
    case "$1" in
        0x*|0X*) printf '%d' "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}

c_mark=$(sed -n 's/^MARK=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_mark=$(sed -n 's/^MARK=${MARK:-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$(normalize_mark "$c_mark")" = "$(normalize_mark "$r_mark")" ] || {
    printf 'FAIL: MARK default C=%s Rust=%s\n' "$c_mark" "$r_mark" >&2
    exit 1
}

c_probe=$(sed -n 's/^PROBE_MARK=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_probe=$(sed -n 's/^PROBE_MARK=${PROBE_MARK:-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$(normalize_mark "$c_probe")" = "$(normalize_mark "$r_probe")" ] || {
    printf 'FAIL: PROBE_MARK default C=%s Rust=%s\n' "$c_probe" "$r_probe" >&2
    exit 1
}

c_queue=$(sed -n 's/^QUEUE_NUM=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_queue=$(sed -n 's/^QUEUE4=${QUEUE_NUM:-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$c_queue" = "$r_queue" ] || {
    printf 'FAIL: QUEUE default C=%s Rust=%s\n' "$c_queue" "$r_queue" >&2
    exit 1
}

c_panel=$(sed -n 's/^PANEL_LISTEN=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_panel=$(sed -n 's/^PANEL_LISTEN=${PANEL_LISTEN-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$c_panel" = "$r_panel" ] || {
    printf 'FAIL: PANEL_LISTEN default C=%s Rust=%s\n' "$c_panel" "$r_panel" >&2
    exit 1
}

c_flows=$(sed -n 's/^FLOWS=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_flows=$(sed -n 's/^R2O_FLOW_CAPACITY=${R2O_FLOW_CAPACITY:-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$c_flows" = "$r_flows" ] || {
    printf 'FAIL: FLOWS default C=%s Rust=%s\n' "$c_flows" "$r_flows" >&2
    exit 1
}

c_mode=$(sed -n 's/^MODE=//p' "$D2O_SERVICE" | head -1 | tr -d '\r')
r_mode=$(sed -n 's/^MODE=${MODE:-\([^}]*\)}$/\1/p' "$R2O_SERVICE" | head -1 | tr -d '\r')
[ "$c_mode" = "$r_mode" ] || {
    printf 'FAIL: MODE fallback C=%s Rust=%s\n' "$c_mode" "$r_mode" >&2
    exit 1
}
# Явное значение MODE перекрывает fallback Rust; при отсутствии — apply.
r_mode_line=$(grep -m1 '^MODE=${MODE:-apply}$' "$R2O_SERVICE" | tr -d '\r')
r_mode_unset=$(sh -c 'unset MODE; eval "$1"; printf "%s" "$MODE"' sh "$r_mode_line")
r_mode_explicit=$(MODE=off sh -c 'eval "$1"; printf "%s" "$MODE"' sh "$r_mode_line")
[ "$r_mode_unset" = apply ] && [ "$r_mode_explicit" = off ] || {
    printf 'FAIL: MODE fallback semantics unset=%s explicit=%s\n' \
        "$r_mode_unset" "$r_mode_explicit" >&2
    exit 1
}

printf 'policy-cases=%s\n' "$checks"
printf 'defaults MARK=%s PROBE_MARK=%s QUEUE=%s PANEL_LISTEN=%s FLOWS=%s MODE=%s\n' \
    "$c_mark" "$c_probe" "$c_queue" "$c_panel" "$c_flows" "$c_mode"
printf 'PASS: C/Rust config defaults, MODE fallback and KEENETIC_POLICY match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
