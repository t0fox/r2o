#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    [ -z "${worker:-}" ] || { kill -TERM "$worker" 2>/dev/null || true; wait "$worker" 2>/dev/null || true; }
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

install_root=$TEMP/install
mkdir -p "$install_root/log" "$install_root/state" "$TEMP/runtime"
cat > "$install_root/config" <<'EOF'
MODE=observe
LOGMAX=2048
LOGKEEP=1024
LOG_EVERY=1
EOF

head -c 4096 /dev/zero | tr '\000' x > "$install_root/log/panel.log"
printf 'retained-tail\n' >> "$install_root/log/panel.log"
head -c 4096 /dev/zero | tr '\000' y > "$install_root/log/unowned.log"
head -c 4096 /dev/zero | tr '\000' z > "$install_root/log/telegram.log.target"
ln -s telegram.log.target "$install_root/log/telegram.log"

before_inode=$(stat -c %i "$install_root/log/panel.log")
before_unowned=$(wc -c < "$install_root/log/unowned.log")
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" sh "$ROOT/router/S99r2o" log-tick

[ "$(wc -c < "$install_root/log/panel.log")" -eq 1024 ]
tail -c 14 "$install_root/log/panel.log" | grep -qx 'retained-tail'
[ "$(stat -c %i "$install_root/log/panel.log")" = "$before_inode" ]
[ "$(wc -c < "$install_root/log/unowned.log")" -eq "$before_unowned" ]
[ -L "$install_root/log/telegram.log" ]
[ "$(wc -c < "$install_root/log/telegram.log.target")" -eq 4096 ]

exec 9>>"$install_root/log/panel.log"
printf 'open-writer-still-attached\n' >&9
exec 9>&-
grep -q '^open-writer-still-attached$' "$install_root/log/panel.log"

ln -s "$TEMP/runtime" "$TEMP/runtime-link"
if env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime-link" \
    sh "$ROOT/router/r2o-log-maintenance.sh" tick; then
    echo "ротация приняла символическую ссылку на runtime" >&2
    exit 1
fi

cat > "$install_root/config-invalid" <<'EOF'
LOGMAX=1024
LOGKEEP=2048
EOF
head -c 4096 /dev/zero | tr '\000' v > "$install_root/log/panel.log"
cp "$install_root/log/panel.log" "$TEMP/invalid-before"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config-invalid" \
    R2O_RUNTIME_DIR="$TEMP/runtime" sh "$ROOT/router/r2o-log-maintenance.sh" tick \
    2> "$TEMP/invalid-config.err"
cmp "$TEMP/invalid-before" "$install_root/log/panel.log"
grep -q 'invalid LOGMAX/LOGKEEP' "$TEMP/invalid-config.err"

mkdir -p "$TEMP/bin"
cat > "$TEMP/bin/tail" <<'EOF'
#!/bin/sh
printf partial
exit 1
EOF
chmod 0755 "$TEMP/bin/tail"
head -c 4096 /dev/zero | tr '\000' w > "$install_root/log/panel.log"
cp "$install_root/log/panel.log" "$TEMP/failed-tail-before"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-log-maintenance.sh" tick
cmp "$TEMP/failed-tail-before" "$install_root/log/panel.log"
[ -z "$(find "$TEMP/runtime" -name 'log-tail.*' -print -quit)" ]

cat > "$TEMP/bin/tail" <<'EOF'
#!/bin/sh
printf partial
EOF
chmod 0755 "$TEMP/bin/tail"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-log-maintenance.sh" tick
cmp "$TEMP/failed-tail-before" "$install_root/log/panel.log"

rm -f "$TEMP/bin/tail"
cat > "$TEMP/bin/stat" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 0755 "$TEMP/bin/stat"
cat > "$install_root/config-leading-zeroes" <<'EOF'
LOGMAX=00002048
LOGKEEP=00001024
EOF
head -c 3072 /dev/zero | tr '\000' s > "$install_root/log/panel.log"
head -c 1024 /dev/zero | tr '\000' t >> "$install_root/log/panel.log"
head -c 1024 /dev/zero | tr '\000' t > "$TEMP/fallback-tail"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config-leading-zeroes" \
    R2O_RUNTIME_DIR="$TEMP/runtime" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-log-maintenance.sh" tick
cmp "$TEMP/fallback-tail" "$install_root/log/panel.log"

cat > "$install_root/config-default" <<'EOF'
MODE=observe
EOF
head -c 2097152 /dev/zero | tr '\000' a > "$install_root/log/panel.log"
head -c 1048576 /dev/zero | tr '\000' z >> "$install_root/log/panel.log"
head -c 1048576 /dev/zero | tr '\000' z > "$TEMP/default-tail"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config-default" \
    R2O_RUNTIME_DIR="$TEMP/runtime" sh "$ROOT/router/r2o-log-maintenance.sh" tick
cmp "$TEMP/default-tail" "$install_root/log/panel.log"

wait_for_rotation() {
    attempt=0
    while [ "$(wc -c < "$install_root/log/panel.log")" -ne 1024 ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 50 ] || return 1
        sleep 0.1
    done
}
head -c 4096 /dev/zero | tr '\000' q > "$install_root/log/panel.log"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" \
    sh "$ROOT/router/r2o-log-maintenance.sh" run >/dev/null 2>&1 &
worker=$!
wait_for_rotation
head -c 4096 /dev/zero | tr '\000' r > "$install_root/log/panel.log"
wait_for_rotation
kill -TERM "$worker"
wait "$worker"
worker=
[ "$(wc -c < "$install_root/log/panel.log")" -eq 1024 ]

cat > "$TEMP/bin/sleep" <<'EOF'
#!/bin/sh
printf '%s\n' "$$" > "$SLEEP_PID_FILE"
exec /bin/sleep "$@"
EOF
chmod 0755 "$TEMP/bin/sleep"
rm -f "$TEMP/sleeper.pid"
env R2O_DIR="$install_root" R2O_CONFIG="$install_root/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" PATH="$TEMP/bin:$PATH" \
    SLEEP_PID_FILE="$TEMP/sleeper.pid" \
    sh "$ROOT/router/r2o-log-maintenance.sh" run >/dev/null 2>&1 &
worker=$!
attempt=0
while [ ! -s "$TEMP/sleeper.pid" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || { echo "worker не перешёл к ожиданию" >&2; exit 1; }
    sleep 0.1
done
sleeper=$(cat "$TEMP/sleeper.pid")
kill -TERM "$worker"
wait "$worker"
worker=
if kill -0 "$sleeper" 2>/dev/null; then
    echo "остановка worker оставила дочерний sleep" >&2
    exit 1
fi

echo "Проверены лимиты и отказы ротации, inode, периодический worker и остановка sleep"
