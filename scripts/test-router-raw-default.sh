#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# Execute the real launcher setup without starting or stopping router services.
sed '/^export R2O_GITHUB_MIRRORS$/q' "$ROOT/router/S99r2o" >"$WORK/setup"
cat >>"$WORK/setup" <<'EOF'
sh -c 'printf "%s\\n" "$R2O_RAW_DISCOVERY"'
EOF

check() (
    inherited=$1
    setting=$2
    expected=$3
    case "$inherited" in
        unset) unset R2O_RAW_DISCOVERY ;;
        *) export R2O_RAW_DISCOVERY="$inherited" ;;
    esac
    case "$setting" in
        missing) rm -f "$WORK/config" ;;
        old) printf '%s\n' 'MODE=apply' >"$WORK/config" ;;
        *) printf "R2O_RAW_DISCOVERY='%s'\n" "$setting" >"$WORK/config" ;;
    esac
    actual=$(R2O_CONFIG="$WORK/config" R2O_DIR="$WORK" sh "$WORK/setup")
    if [ "$actual" != "$expected" ]; then
        printf 'RAW launcher: env=%s config=%s expected=%s actual=%s\n' \
            "$inherited" "$setting" "$expected" "$actual" >&2
        exit 1
    fi
)

check unset missing 1
check unset old 1
check unset '' 1
check unset 0 0
check unset 1 1
check unset invalid invalid
check '' old 1
check 0 old 0
check 1 0 0
check 0 1 1
printf '%s\n' 'RAW launcher: 10 configuration cases passed'
