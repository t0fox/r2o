#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-panel-bind.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
BUNDLE=$TEMP/bundle
BIN=$TEMP/bin
mkdir -p "$BUNDLE/builds" "$BUNDLE/router" "$BIN"

cp "$ROOT/router/install.sh" "$BUNDLE/router/install.sh"
cp "$ROOT/router/config.default" "$BUNDLE/router/config.default"
cp "$ROOT/router/select-panel-ip.sh" "$BUNDLE/router/select-panel-ip.sh"
cp "$ROOT/router/001-r2o.sh" "$BUNDLE/router/001-r2o.sh"
cp "$ROOT/router/r2o-ppe-deoffload.sh" "$BUNDLE/router/r2o-ppe-deoffload.sh"
printf '#!/bin/sh\nexit 0\n' > "$BUNDLE/router/S99r2o.shim"
printf '#!/bin/sh\nexit 0\n' > "$BUNDLE/router/S99r2o"

cat > "$BUNDLE/builds/r2o-manager-linux-testhost" <<'MANAGER'
#!/bin/sh
set -eu
command=$1
shift
root= bundle= release= architecture= defaults=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) root=$2; shift 2 ;;
        --bundle) bundle=$2; shift 2 ;;
        --release-id) release=$2; shift 2 ;;
        --architecture) architecture=$2; shift 2 ;;
        --defaults) defaults=$2; shift 2 ;;
        --donor-config) shift 2 ;;
        --component) shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
case "$command" in
    install-local)
        mkdir -p "$root/releases/$release"
        cp -R "$bundle/." "$root/releases/$release/"
        printf '%s\n' "$architecture" > "$root/releases/$release/release-architecture"
        printf 'R2O-RELEASE-SLOTS-1\n%s\n' "$release" > "$root/release-slots"
        ;;
    config-init)
        mkdir -p "$root"
        [ -f "$root/config" ] || cp "$defaults" "$root/config"
        chmod 0600 "$root/config"
        printf '{"state_dir":"%s/state","donor_state_dir":"%s/state"}\n' "$root" "$root"
        ;;
    exec) exit 0 ;;
    *) echo "unexpected manager command: $command" >&2; exit 2 ;;
esac
MANAGER
chmod 0755 "$BUNDLE/builds/r2o-manager-linux-testhost"

cat > "$BIN/ip" <<'IP'
#!/bin/sh
[ "$*" = '-4 -o addr show scope global' ] || exit 2
if [ "${R2O_TEST_IP_PUBLIC_ONLY:-0}" = 1 ]; then
    echo '9: ppp0 inet 198.51.100.11/24 scope global ppp0'
else
    printf '%s\n' \
        '9: ppp0 inet 198.51.100.11/24 scope global ppp0' \
        '10: br1 inet 10.1.30.1/24 scope global br1' \
        '11: br0 inet 192.168.1.1/24 scope global br0'
fi
IP
chmod 0755 "$BIN/ip"

run_install() {
    root=$1
    shift
    PATH="$BIN:$PATH" \
    R2O_DIR="$root" \
    R2O_INIT_DIR="$TEMP/init" \
    R2O_NDM_DIR="$TEMP/no-ndm" \
    R2O_OPENWRT_INIT_DIR="$TEMP/no-openwrt" \
    R2O_DONOR_CONFIG="$TEMP/no-donor-config" \
    R2O_PLATFORM=local \
        sh "$BUNDLE/router/install.sh" "$BUNDLE" test-release testhost "$@"
}

run_install "$TEMP/lan-root" > "$TEMP/lan-install.log"
grep -qx 'PANEL_LISTEN=192.168.1.1:8090' "$TEMP/lan-root/config" || {
    cat "$TEMP/lan-install.log" >&2
    echo "fresh install did not bind the selected private LAN address" >&2
    exit 1
}

sed 's/^PANEL_LISTEN=.*/PANEL_LISTEN=0.0.0.0:8090/' \
    "$TEMP/lan-root/config" > "$TEMP/manual-config"
mv "$TEMP/manual-config" "$TEMP/lan-root/config"
run_install "$TEMP/lan-root" > "$TEMP/upgrade.log"
grep -qx 'PANEL_LISTEN=0.0.0.0:8090' "$TEMP/lan-root/config" || {
    cat "$TEMP/upgrade.log" >&2
    echo "upgrade changed an explicit owner-managed panel bind" >&2
    exit 1
}

if R2O_TEST_IP_PUBLIC_ONLY=1 run_install "$TEMP/public-only-root" > "$TEMP/public-only.log" 2>&1; then
    echo "installer accepted a public-only interface for the panel" >&2
    exit 1
fi
grep -q 'не найден частный LAN IPv4-адрес' "$TEMP/public-only.log" || {
    cat "$TEMP/public-only.log" >&2
    echo "installer did not fail closed without a private LAN address" >&2
    exit 1
}

echo "router panel bind install lifecycle passed"
