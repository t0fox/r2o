#!/bin/sh
# Ошибки восстановления не стирают сохранённое состояние прежнего выпуска.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
R2O_DATAPATH_BIN=${R2O_DATAPATH_BIN:-$ROOT/target/release/r2o-datapath}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
export WORK R2O_DIR="$WORK" R2O_RUN_DIR="$WORK/run" R2O_PROC_DIR="$WORK/proc"
export R2O_FW4="$WORK/bin/fw4" R2O_FIREWALL_INIT="$WORK/bin/fw4"
export PATH="$WORK/bin:$PATH"
mkdir -p "$WORK/run" "$WORK/bin" "$WORK/proc/sys/net/netfilter"
FASTNAT="$R2O_PROC_DIR/sys/net/netfilter/nf_conntrack_fastnat"
RESTORE="$R2O_RUN_DIR/flow-offloading.saved"

cat > "$WORK/bin/uci" <<'SCRIPT'
#!/bin/sh
set -eu
case "$1" in
    -q) cat "$WORK/uci-value" ;;
    changes)
        if [ -e "$WORK/uci-pending" ]; then
            printf "%s\n" "firewall.@defaults[0].flow_offloading='1'"
        fi
        ;;
    set)
        [ "${FAIL:-}" != set ] || exit 23
        printf '1\n' > "$WORK/uci-value"
        : > "$WORK/uci-pending"
        ;;
    commit)
        [ "${FAIL:-}" != commit ] || exit 23
        rm -f "$WORK/uci-pending"
        ;;
    *) exit 2 ;;
esac
SCRIPT
cat > "$WORK/bin/fw4" <<'SCRIPT'
#!/bin/sh
[ "${FAIL:-}" != reload ] || exit 23
SCRIPT
chmod +x "$WORK/bin/uci" "$WORK/bin/fw4"

printf '1\n' > "$RESTORE"
printf '0\n' > "$WORK/uci-value"
if FAIL='set' "$R2O_DATAPATH_BIN" --platform flowoffload-restore; then exit 1; fi
test -f "$RESTORE"
if FAIL=commit "$R2O_DATAPATH_BIN" --platform flowoffload-restore; then exit 1; fi
test -f "$RESTORE"
if FAIL=reload "$R2O_DATAPATH_BIN" --platform flowoffload-restore; then exit 1; fi
test -f "$RESTORE"
"$R2O_DATAPATH_BIN" --platform flowoffload-restore
test ! -e "$RESTORE"

printf '1\n' > "$R2O_RUN_DIR/fastnat.saved"
if "$R2O_DATAPATH_BIN" --platform flowoffload-restore; then exit 1; fi
test -f "$R2O_RUN_DIR/fastnat.saved"
printf '0\n' > "$FASTNAT"
"$R2O_DATAPATH_BIN" --platform flowoffload-restore
test "$(cat "$FASTNAT")" = 1
test ! -e "$R2O_RUN_DIR/fastnat.saved"
printf '%s\n' 'Повтор восстанавливает FastNAT и fw4 после ошибок записи, commit и reload'
