#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-fastnat.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed -n '/^FASTNAT=/,/^policy_mark() {/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' |
    sed '$d; s|^FASTNAT=/proc/sys/net/netfilter/nf_conntrack_fastnat$|FASTNAT=$FASTNAT_PATH|' > "$TEMP/d2o.sh"
sed -n '/^FASTNAT=/,/^flowoffload_restore() {/p' "$ROOT/router/S99r2o" |
    tr -d '\r' |
    sed '$d; s|^FASTNAT=/proc/sys/net/netfilter/nf_conntrack_fastnat$|FASTNAT=$FASTNAT_PATH|' > "$TEMP/r2o.sh"
[ -s "$TEMP/d2o.sh" ] || { echo "could not extract D2O fastnat lifecycle" >&2; exit 2; }

cat > "$TEMP/step.sh" <<'STEP'
#!/bin/sh
set -eu
functions=$1
step=$2
say() { :; }
. "$functions"
case "$step" in
    start)
        if command -v fastnat_off >/dev/null 2>&1; then fastnat_off; fi
        ;;
    restart)
        if command -v fastnat_restore >/dev/null 2>&1; then fastnat_restore; fi
        if command -v fastnat_off >/dev/null 2>&1; then fastnat_off; fi
        ;;
    stop)
        if command -v fastnat_restore >/dev/null 2>&1; then fastnat_restore; fi
        ;;
esac
saved=absent
[ ! -f "$RUN/fastnat.saved" ] || saved=$(cat "$RUN/fastnat.saved")
printf '%s setting=%s saved=%s\n' "$step" "$(cat "$FASTNAT_PATH")" "$saved"
STEP
chmod 0755 "$TEMP/step.sh"

run_case() {
    implementation=$1
    initial=$2
    run="$TEMP/$implementation-$initial"
    mkdir -p "$run"
    printf '%s\n' "$initial" > "$run/fastnat"
    chmod 0600 "$run/fastnat"
    functions=$TEMP/$implementation.sh
    [ "$implementation" != r2o ] || [ -s "$functions" ] || : > "$run/empty.sh"
    [ "$implementation" != r2o ] || [ -s "$functions" ] || functions=$run/empty.sh
    for step in start restart stop; do
        RUN="$run" RUNTIME="$run" FASTNAT_PATH="$run/fastnat" \
            sh "$TEMP/step.sh" "$functions" "$step"
    done
}

for initial in 1 0; do
    if ! run_case d2o "$initial" > "$TEMP/d2o.out"; then exit 2; fi
    if ! run_case r2o "$initial" > "$TEMP/r2o.out"; then exit 2; fi
    if ! cmp -s "$TEMP/d2o.out" "$TEMP/r2o.out"; then
        echo "D2O/R2O fastnat lifecycle differs from initial value $initial" >&2
        diff -u "$TEMP/d2o.out" "$TEMP/r2o.out" >&2 || true
        exit 1
    fi
done

grep -A 90 '^engine_start() {' "$ROOT/router/S99r2o" | grep -q 'fastnat_off' || {
    echo "R2O engine_start does not disable fastnat" >&2
    exit 1
}
grep -A 15 '^engine_stop() {' "$ROOT/router/S99r2o" | grep -q 'fastnat_restore' || {
    echo "R2O engine_stop does not restore fastnat" >&2
    exit 1
}

echo "test-router-fastnat-lifecycle-differential: start/restart/stop state matches D2O"
