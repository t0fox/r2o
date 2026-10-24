#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
SERVICE=$TEMP/S99r2o
EVENTS=$TEMP/events
cat > "$SERVICE" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$EVENTS"
EOF
chmod 0755 "$SERVICE"

table=nat R2O_INIT="$SERVICE" sh "$ROOT/router/001-r2o.sh"
table=mangle R2O_INIT="$SERVICE" sh "$ROOT/router/001-r2o.sh"
table=filter R2O_INIT="$SERVICE" sh "$ROOT/router/001-r2o.sh"
table=raw R2O_INIT="$SERVICE" sh "$ROOT/router/001-r2o.sh"
expected=$TEMP/expected
printf 'heal\nheal\n' > "$expected"
cmp "$expected" "$EVENTS"
echo "NDM hook запускает восстановление R2O только после nat/mangle"
