#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

R2O_BIN=${R2O_TELEGRAM_BIN:-$ROOT/target/release/r2o-telegram}
[ -x "$R2O_BIN" ] || { echo "R2O Telegram binary not found: $R2O_BIN" >&2; exit 2; }
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-meta-dns-remove.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/d2o/state" "$TEMP/r2o/state"

cat > "$TEMP/bin/ndmc" <<'NDMC'
#!/bin/sh
command=$2
printf '%s\n' "$*" >> "$NDMC_CALLS"
case "$command" in
    'show running-config') cat "$NDMC_STATE" ;;
    'no ip host '*)
        set -- $command
        host=$4
        address=$5
        awk -v h="$host" -v ip="$address" \
            '!($1 == "ip" && $2 == "host" && $3 == h && $4 == ip)' \
            "$NDMC_STATE" > "$NDMC_STATE.new"
        mv "$NDMC_STATE.new" "$NDMC_STATE"
        ;;
    'system configuration save') printf 'saved\n' >> "$NDMC_SAVES" ;;
    *) printf 'unexpected ndmc command: %s\n' "$command" >&2; exit 2 ;;
esac
NDMC
chmod 0700 "$TEMP/bin/ndmc"

cat > "$TEMP/initial-config" <<'CONFIG'
system name test-router
ip host instagram.com 157.240.9.174
ip host instagram.com 157.240.9.175
ip host web.whatsapp.com 57.144.245.32
ip host unrelated.example 192.0.2.7
CONFIG
cp "$TEMP/initial-config" "$TEMP/d2o-running-config"
cp "$TEMP/initial-config" "$TEMP/r2o-running-config"
for root in d2o r2o; do
    cat > "$TEMP/$root/state/owned.tsv" <<'MANIFEST'
instagram.com 157.240.9.174
web.whatsapp.com 57.144.245.32
unrelated.example 192.0.2.7
MANIFEST
done

env PATH="$TEMP/bin:/usr/bin:/bin" D2K_STUB_PATH="$TEMP/bin" D2K_DIR="$TEMP/d2o" \
    D2K_INSTAGRAM_MANIFEST="$TEMP/d2o/state/owned.tsv" \
    D2K_INSTAGRAM_LOG="$TEMP/d2o/remove.log" NDMC_STATE="$TEMP/d2o-running-config" \
    NDMC_CALLS="$TEMP/d2o-ndmc.calls" NDMC_SAVES="$TEMP/d2o-saves" \
    sh "$D2O_ROOT/files/d2k-instagram-dns.sh" remove

env PATH="$TEMP/bin:/usr/bin:/bin" R2O_DIR="$TEMP/r2o" \
    R2O_INSTAGRAM_MANIFEST="$TEMP/r2o/state/owned.tsv" \
    R2O_INSTAGRAM_LOG="$TEMP/r2o/remove.log" NDMC_STATE="$TEMP/r2o-running-config" \
    NDMC_CALLS="$TEMP/r2o-ndmc.calls" NDMC_SAVES="$TEMP/r2o-saves" \
    "$R2O_BIN" --remove-meta-dns

cmp -s "$TEMP/d2o-running-config" "$TEMP/r2o-running-config" || {
    echo 'D2O/R2O removed different DNS records' >&2
    diff -u "$TEMP/d2o-running-config" "$TEMP/r2o-running-config" >&2 || true
    exit 1
}
cmp -s "$TEMP/d2o-ndmc.calls" "$TEMP/r2o-ndmc.calls" || {
    echo 'D2O/R2O ndmc cleanup command traces differ' >&2
    diff -u "$TEMP/d2o-ndmc.calls" "$TEMP/r2o-ndmc.calls" >&2 || true
    exit 1
}
cmp -s "$TEMP/d2o-saves" "$TEMP/r2o-saves" || {
    echo 'D2O/R2O NDM save counts differ' >&2
    exit 1
}
for root in d2o r2o; do
    [ ! -e "$TEMP/$root/state/owned.tsv" ] || {
        printf '%s kept its ownership manifest after successful cleanup\n' "$root" >&2
        exit 1
    }
done
grep -q '^ip host instagram.com 157.240.9.175$' "$TEMP/r2o-running-config" || {
    echo 'cleanup removed an identical user-owned DNS record' >&2
    exit 1
}
grep -q '^ip host unrelated.example 192.0.2.7$' "$TEMP/r2o-running-config" || {
    echo 'cleanup removed an unrelated DNS record' >&2
    exit 1
}

printf 'D2O %s and the R2O production binary remove the same owned DNS records with identical ndmc traces.\n' "$ACTUAL_D2O_SHA"
