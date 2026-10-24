#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
FIXTURE=$TEMP/fixture
MOCK=$TEMP/mockbin
mkdir -p "$FIXTURE/builds" "$FIXTURE/router" "$MOCK" "$TEMP/tmp"

fail() { echo "OpenWrt bootstrap test: $*" >&2; exit 1; }

openssl genpkey -algorithm Ed25519 -out "$TEMP/test-key.pem" 2>/dev/null
PUBLIC_KEY_B64=$(openssl pkey -in "$TEMP/test-key.pem" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')

cat > "$MOCK/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--max-filesize|--connect-timeout|--max-time|--proto|--proto-redir)
            [ "$#" -ge 2 ] || exit 2
            if [ "$1" = -o ]; then output=$2; fi
            shift 2
            ;;
        -* ) shift ;;
        * ) url=$1; shift ;;
    esac
done
[ -n "$url" ] && [ -n "$output" ] || exit 2
printf '%s\t%s\n' "$url" "$output" >> "$R2O_TEST_FETCH_LOG"
case "$url" in
    */latest.json.sig) source=$R2O_TEST_FIXTURES/latest.json.sig ;;
    */latest.json) source=$R2O_TEST_FIXTURES/latest.json ;;
    https://api.github.com/repos/t0fox/r2o/releases/tags/*) source=$R2O_TEST_FIXTURES/release-api.json ;;
    */r2o-mipsel-openwrt-musl.tar.gz) source=$R2O_TEST_FIXTURES/r2o-mipsel-openwrt-musl.tar.gz ;;
    *) echo "unexpected fetch URL: $url" >&2; exit 22 ;;
esac
cp "$source" "$output"
EOF
cat > "$MOCK/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
EOF
cat > "$MOCK/uname" <<'EOF'
#!/bin/sh
[ "${1:-}" = -m ] && { echo aarch64; exit 0; }
exec /usr/bin/uname "$@"
EOF
cat > "$MOCK/df" <<'EOF'
#!/bin/sh
set -eu
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'mock 200000 %s %s 1%% /mock\n' "$((200000 - R2O_TEST_FREE_KB))" "$R2O_TEST_FREE_KB"
EOF
for tool in start-stop-daemon ip nft; do
    printf '#!/bin/sh\nexit 0\n' > "$MOCK/$tool"
done
chmod 0755 "$MOCK/curl" "$MOCK/id" "$MOCK/uname" "$MOCK/df" "$MOCK/start-stop-daemon" "$MOCK/ip" "$MOCK/nft"

cat > "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl" <<'EOF'
#!/bin/sh
set -eu
command_name=$1
shift
case "$command_name" in
    install-local)
        root= bundle= release= architecture=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --root) root=$2; shift 2 ;;
                --bundle) bundle=$2; shift 2 ;;
                --release-id) release=$2; shift 2 ;;
                --architecture) architecture=$2; shift 2 ;;
                *) exit 2 ;;
            esac
        done
        printf 'install-local %s\n' "$release" >> "$R2O_TEST_MANAGER_LOG"
        previous=$(sed -n '2p' "$root/release-slots" 2>/dev/null || true)
        mkdir -p "$root/releases/$release"
        cp -R "$bundle/." "$root/releases/$release/"
        [ "${R2O_TEST_FAIL_DURING_INSTALL:-0}" != 1 ] || exit 1
        printf '%s\n' "$architecture" > "$root/releases/$release/release-architecture"
        { printf 'R2O-RELEASE-SLOTS-1\n%s\n' "$release"; [ -z "$previous" ] || printf '%s\n' "$previous"; } > "$root/release-slots.new"
        mv -f "$root/release-slots.new" "$root/release-slots"
        cp "$root/releases/$release/builds/r2o-manager-linux-$architecture" "$root/r2o-manager"
        if [ "${R2O_TEST_INSTALL_WAIT:-0}" = 1 ]; then
            printf '%s\n' "$$" > "$R2O_TEST_INSTALL_PID"
            : > "$R2O_TEST_INSTALL_READY"
            while [ ! -e "$R2O_TEST_INSTALL_RELEASE" ]; do sleep 0.1; done
        fi
        ;;
    config-init)
        root= defaults=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --root) root=$2; shift 2 ;;
                --defaults) defaults=$2; shift 2 ;;
                --donor-config) shift 2 ;;
                *) exit 2 ;;
            esac
        done
        [ -f "$root/config" ] || cp "$defaults" "$root/config"
        printf '{"state_dir":"%s/state","donor_state_dir":"%s/state"}\n' "$root" "$root"
        ;;
    rollback)
        root=$2
        current=$(sed -n '2p' "$root/release-slots")
        previous=$(sed -n '3p' "$root/release-slots")
        [ -n "$previous" ] || exit 1
        printf 'rollback %s -> %s\n' "$current" "$previous" >> "$R2O_TEST_MANAGER_LOG"
        { printf 'R2O-RELEASE-SLOTS-1\n%s\n%s\n' "$previous" "$current"; } > "$root/release-slots.new"
        mv -f "$root/release-slots.new" "$root/release-slots"
        ;;
    exec) exit 0 ;;
    *) echo "unexpected manager command: $command_name" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl"
cp "$ROOT/router/install.sh" "$FIXTURE/router/install.sh"
cp "$ROOT/router/uninstall.sh" "$FIXTURE/router/uninstall.sh"
printf '#!/bin/sh\ncase "${1:-}" in start) [ "${R2O_TEST_START_FAIL:-0}" != 1 ] ;; *) exit 0 ;; esac\n' > "$FIXTURE/router/S99r2o.shim"
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/S99r2o"
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/001-r2o.sh"
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/r2o-ppe-deoffload.sh"
printf '#!/bin/sh\n# OpenWrt host-side waiter\nexit 0\n' > "$FIXTURE/router/openwrt-init"
printf 'MODE=apply\nTG_ENABLED=1\n' > "$FIXTURE/router/config.default"
chmod 0755 "$FIXTURE/router/"*.sh "$FIXTURE/router/S99r2o" "$FIXTURE/router/S99r2o.shim" "$FIXTURE/router/openwrt-init"

tar -czf "$FIXTURE/r2o-mipsel-openwrt-musl.tar.gz" -C "$FIXTURE" builds router
ARCHIVE_SHA=$(sha256sum "$FIXTURE/r2o-mipsel-openwrt-musl.tar.gz" | awk '{print $1}')
printf '{"release_id":"r2o-bootstrap-test","version":"1","notes":"","assets":{"mipsel-openwrt-musl":{"sha256":"%s"}}}\n' \
    "$ARCHIVE_SHA" > "$FIXTURE/latest.json"
openssl pkeyutl -sign -inkey "$TEMP/test-key.pem" -rawin -in "$FIXTURE/latest.json" \
    -out "$FIXTURE/latest.json.sig" 2>/dev/null
printf '%s\n' '-----BEGIN PUBLIC KEY-----' "$PUBLIC_KEY_B64" '-----END PUBLIC KEY-----' > "$TEMP/test-public.pem"
openssl pkeyutl -verify -pubin -inkey "$TEMP/test-public.pem" -rawin \
    -in "$FIXTURE/latest.json" -sigfile "$FIXTURE/latest.json.sig" >/dev/null 2>&1 ||
    fail 'test manifest fixture does not verify with its generated key'
ARCHIVE_SIZE=$(wc -c < "$FIXTURE/r2o-mipsel-openwrt-musl.tar.gz" | tr -d ' ')
printf '{\n  "assets": [\n    {\n      "name": "r2o-mipsel-openwrt-musl.tar.gz",\n      "size": %s\n    }\n  ]\n}\n' \
    "$ARCHIVE_SIZE" > "$FIXTURE/release-api.json"

sed -e "s|^PATH=.*|PATH=$MOCK:/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/usr/bin:/usr/sbin:/bin:/sbin|" \
    -e "s|PUBLIC_KEY_B64='[^']*'|PUBLIC_KEY_B64='$PUBLIC_KEY_B64'|" "$ROOT/scripts/install.sh" \
    > "$TEMP/install.sh" || fail 'scripts/install.sh is missing'
grep -Fqx "PUBLIC_KEY_B64='$PUBLIC_KEY_B64'" "$TEMP/install.sh" || fail 'test public key was not pinned in the bootstrap copy'

new_case() {
    CASE=$TEMP/$1
    mkdir -p "$CASE/tmp" "$CASE/etc" "$CASE/opt/etc/init.d" "$CASE/opt/etc/ndm/netfilter.d" "$CASE/etc/init.d" "$CASE/fixtures"
    printf 'DISTRIB_ID="OpenWrt"\nDISTRIB_ARCH="mipsel_24kc"\n' > "$CASE/openwrt_release"
    printf 'MemTotal: 131072 kB\nMemAvailable: 131072 kB\nMemFree: 120000 kB\nBuffers: 1000 kB\nCached: 5000 kB\nShmem: 500 kB\n' > "$CASE/meminfo"
    cp -R "$FIXTURE/." "$CASE/fixtures/"
    : > "$CASE/fetch.log"
    : > "$CASE/manager.log"
}

run_install() {
    R2O_OPENWRT_RELEASE="${TEST_OPENWRT_RELEASE:-$CASE/openwrt_release}" \
    R2O_MEMINFO_FILE="$CASE/meminfo" \
    R2O_DIR="$CASE/opt/r2o" \
    R2O_INIT_DIR="$CASE/opt/etc/init.d" \
    R2O_NDM_DIR="$CASE/opt/etc/ndm/netfilter.d" \
    R2O_OPENWRT_INIT_DIR="$CASE/etc/init.d" \
    R2O_RUNTIME_DIR="$CASE/tmp/r2o" \
    R2O_TEST_FIXTURES="$CASE/fixtures" \
    R2O_TEST_FETCH_LOG="$CASE/fetch.log" \
    R2O_TEST_MANAGER_LOG="$CASE/manager.log" \
    R2O_TEST_FREE_KB="${TEST_FREE_KB:-200000}" \
    TMPDIR="$CASE/tmp" PATH="$MOCK:$PATH" \
        sh "$TEMP/install.sh"
}

new_case damaged-signature
printf x | dd of="$CASE/fixtures/latest.json.sig" bs=1 seek=0 conv=notrunc 2>/dev/null
if run_install > "$CASE/out" 2>&1; then fail 'damaged Ed25519 signature was accepted'; fi
grep -q 'подпись' "$CASE/out" || fail 'bad signature was not rejected at signature verification'
grep -q 'r2o-mipsel-openwrt-musl.tar.gz' "$CASE/fetch.log" && fail 'archive downloaded before signature verification'
[ ! -e "$CASE/opt/r2o" ] || fail 'bad signature created the installation root'

new_case damaged-archive
printf x | dd of="$CASE/fixtures/r2o-mipsel-openwrt-musl.tar.gz" bs=1 seek=0 conv=notrunc 2>/dev/null
if run_install > "$CASE/out" 2>&1; then fail 'archive with a hash mismatch was accepted'; fi
grep -q 'SHA-256' "$CASE/out" || { cat "$CASE/out" >&2; cat "$CASE/fetch.log" >&2; fail 'archive hash mismatch was not rejected'; }
[ ! -s "$CASE/manager.log" ] || fail 'archive code ran before its SHA-256 was verified'
[ ! -e "$CASE/opt/r2o" ] || fail 'bad archive created the installation root'

new_case unsupported-abi
sed 's/mipsel_24kc/mips_24kc/' "$CASE/openwrt_release" > "$CASE/openwrt_release.new"
mv "$CASE/openwrt_release.new" "$CASE/openwrt_release"
if run_install > "$CASE/out" 2>&1; then fail 'unsupported big-endian MIPS ABI was accepted'; fi
grep -q 'неподдерживаем' "$CASE/out" || { cat "$CASE/out" >&2; fail 'unsupported ABI failure was not explained'; }
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for an unsupported ABI'

new_case unsupported-openwrt-mips1
sed 's/mipsel_24kc/mipsel_4kc/' "$CASE/openwrt_release" > "$CASE/openwrt_release.new"
mv "$CASE/openwrt_release.new" "$CASE/openwrt_release"
if run_install > "$CASE/out" 2>&1; then fail 'MIPS-I OpenWrt architecture was mapped to an incompatible MIPS32r2 ABI'; fi
grep -q 'неподдерживаем' "$CASE/out" || fail 'unsupported MIPS-I ABI failure was not explained'
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for an unsupported MIPS-I ABI'

new_case unsupported-keenetic-softfloat
cat > "$MOCK/opkg" <<'EOF'
#!/bin/sh
[ "${1:-}" = print-architecture ] || exit 2
printf 'arch all 1\narch armv7sf-k3.2 100\n'
EOF
chmod 0755 "$MOCK/opkg"
TEST_OPENWRT_RELEASE="$CASE/no-openwrt-release" run_install > "$CASE/out" 2>&1 && fail 'Keenetic soft-float ABI was mapped to hard-float R2O'
rm -f "$MOCK/opkg"
grep -q 'неподдерживаем' "$CASE/out" || fail 'incompatible Keenetic ABI failure was not explained'
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for incompatible Keenetic ABI'

new_case insufficient-flash
TEST_FREE_KB=100 run_install > "$CASE/out" 2>&1 && fail 'install continued with insufficient flash'
grep -q 'места' "$CASE/out" || fail 'low flash failure was not explained'
grep -q 'r2o-mipsel-openwrt-musl.tar.gz' "$CASE/fetch.log" && fail 'large archive downloaded without flash preflight'
[ ! -e "$CASE/opt/r2o" ] || fail 'low flash created the installation root'

new_case low-ram-disk-staging
sed -e '/^MemAvailable:/d' \
    -e 's/MemFree: 120000 kB/MemFree: 16384 kB/' \
    -e 's/Buffers: 1000 kB/Buffers: 0 kB/' \
    -e 's/Cached: 5000 kB/Cached: 0 kB/' \
    -e 's/Shmem: 500 kB/Shmem: 0 kB/' "$CASE/meminfo" > "$CASE/meminfo.new"
mv "$CASE/meminfo.new" "$CASE/meminfo"
TEST_FREE_KB=200000 run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'low-RAM flash staging did not install'; }
archive_output=$(awk -F '\t' '/r2o-mipsel-openwrt-musl.tar.gz/ { print $2 }' "$CASE/fetch.log")
case "$archive_output" in "$CASE/tmp"/*) fail 'compressed archive was staged in tmpfs without enough available RAM' ;; esac

new_case foreign-init
printf '#!/bin/sh\necho another owner\n' > "$CASE/opt/etc/init.d/S99r2o"
if run_install > "$CASE/out" 2>&1; then fail 'foreign init script was overwritten'; fi
grep -q 'чужой файл' "$CASE/out" || fail 'foreign init conflict was not explained'
[ ! -s "$CASE/manager.log" ] || fail 'foreign init conflict was checked after manager activation'

new_case foreign-openwrt-service
printf '#!/bin/sh\necho another service\n' > "$CASE/etc/init.d/r2o"
if run_install > "$CASE/out" 2>&1; then fail 'foreign OpenWrt service was overwritten'; fi
grep -q 'чужой файл' "$CASE/out" || fail 'foreign OpenWrt service conflict was not explained'
grep -qx 'echo another service' "$CASE/etc/init.d/r2o" || fail 'foreign OpenWrt service was modified'
[ ! -s "$CASE/manager.log" ] || fail 'foreign OpenWrt service conflict was checked after manager activation'

new_case rollback
mkdir -p "$CASE/opt/r2o/releases/r2o-old/router" "$CASE/opt/etc/init.d"
cp -R "$FIXTURE/router/." "$CASE/opt/r2o/releases/r2o-old/router/"
printf '%s\n' mipsel-openwrt-musl > "$CASE/opt/r2o/releases/r2o-old/release-architecture"
cp "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl" "$CASE/opt/r2o/r2o-manager"
printf 'R2O-RELEASE-SLOTS-1\nr2o-old\n' > "$CASE/opt/r2o/release-slots"
printf 'owner=kept\n' > "$CASE/opt/r2o/config"
cp "$FIXTURE/router/S99r2o.shim" "$CASE/opt/etc/init.d/S99r2o"
TEST_FREE_KB=200000 R2O_TEST_START_FAIL=1 run_install > "$CASE/out" 2>&1 && fail 'failed service start was accepted'
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-old ] || fail 'failed activation did not restore the previous release'
grep -q '^rollback r2o-bootstrap-test -> r2o-old$' "$CASE/manager.log" || fail 'manager rollback was not used'
grep -qx 'owner=kept' "$CASE/opt/r2o/config" || fail 'rollback damaged the existing configuration'

new_case failed-first-install
if R2O_TEST_FAIL_DURING_INSTALL=1 run_install > "$CASE/out" 2>&1; then
    fail 'incomplete first install was accepted'
fi
[ ! -e "$CASE/opt/r2o" ] || fail 'incomplete first install left release files behind'
[ ! -e "$CASE/opt/etc/init.d/S99r2o" ] || fail 'incomplete first install left its startup shim behind'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'incomplete first install left its OpenWrt service behind'

new_case interrupted-install
mkdir -p "$CASE/opt/r2o/releases/r2o-old/router" "$CASE/opt/etc/init.d"
cp -R "$FIXTURE/router/." "$CASE/opt/r2o/releases/r2o-old/router/"
printf '%s\n' mipsel-openwrt-musl > "$CASE/opt/r2o/releases/r2o-old/release-architecture"
cp "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl" "$CASE/opt/r2o/r2o-manager"
printf 'R2O-RELEASE-SLOTS-1\nr2o-old\n' > "$CASE/opt/r2o/release-slots"
printf 'owner=kept\n' > "$CASE/opt/r2o/config"
cp "$FIXTURE/router/S99r2o.shim" "$CASE/opt/etc/init.d/S99r2o"
R2O_OPENWRT_RELEASE="$CASE/openwrt_release" \
R2O_MEMINFO_FILE="$CASE/meminfo" \
R2O_DIR="$CASE/opt/r2o" \
R2O_INIT_DIR="$CASE/opt/etc/init.d" \
R2O_NDM_DIR="$CASE/opt/etc/ndm/netfilter.d" \
R2O_OPENWRT_INIT_DIR="$CASE/etc/init.d" \
R2O_RUNTIME_DIR="$CASE/tmp/r2o" \
R2O_TEST_FIXTURES="$CASE/fixtures" \
R2O_TEST_FETCH_LOG="$CASE/fetch.log" \
R2O_TEST_MANAGER_LOG="$CASE/manager.log" \
R2O_TEST_FREE_KB=200000 \
R2O_TEST_INSTALL_WAIT=1 \
R2O_TEST_INSTALL_PID="$CASE/manager.pid" \
R2O_TEST_INSTALL_READY="$CASE/manager.ready" \
R2O_TEST_INSTALL_RELEASE="$CASE/manager.release" \
TMPDIR="$CASE/tmp" PATH="$MOCK:$PATH" \
    sh "$TEMP/install.sh" > "$CASE/out" 2>&1 &
installer_pid=$!
attempt=0
while [ ! -f "$CASE/manager.ready" ] && [ "$attempt" -lt 100 ]; do
    sleep 0.05
    attempt=$((attempt + 1))
done
[ -f "$CASE/manager.ready" ] || { cat "$CASE/out" >&2; fail 'interruption fixture never reached manager activation'; }
kill -TERM "$installer_pid" 2>/dev/null || true
manager_pid=$(cat "$CASE/manager.pid")
kill -TERM "$manager_pid" 2>/dev/null || true
: > "$CASE/manager.release"
if wait "$installer_pid"; then fail 'terminated install unexpectedly succeeded'; fi
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-old ] || fail 'interrupted activation did not roll back'
grep -q '^rollback r2o-bootstrap-test -> r2o-old$' "$CASE/manager.log" || fail 'interruption did not invoke manager rollback'
grep -qx 'owner=kept' "$CASE/opt/r2o/config" || fail 'interrupted rollback damaged existing configuration'

new_case install-repeat
run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'valid signed release did not install'; }
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-bootstrap-test ] || fail 'release manager did not activate the signed release'
grep -qx 'MODE=apply' "$CASE/opt/r2o/config" || fail 'first install did not initialize configuration'
install_count=$(grep -c '^install-local ' "$CASE/manager.log")
run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'repeat install did not complete'; }
[ "$(grep -c '^install-local ' "$CASE/manager.log")" -eq "$install_count" ] || fail 'repeat install reactivated an already current release'
R2O_OPENWRT_RELEASE="$CASE/openwrt_release" \
R2O_DIR="$CASE/opt/r2o" \
R2O_INIT_DIR="$CASE/opt/etc/init.d" \
R2O_NDM_DIR="$CASE/opt/etc/ndm/netfilter.d" \
R2O_OPENWRT_INIT_DIR="$CASE/etc/init.d" \
R2O_RUNTIME_DIR="$CASE/tmp/r2o" R2O_PLATFORM=openwrt \
    sh "$CASE/opt/r2o/releases/r2o-bootstrap-test/router/uninstall.sh" --yes \
    > "$CASE/uninstall.out" 2>&1 || { cat "$CASE/uninstall.out" >&2; fail 'owned installation did not uninstall'; }
[ ! -e "$CASE/opt/r2o" ] || fail 'uninstall left the R2O release root behind'
[ ! -e "$CASE/opt/etc/init.d/S99r2o" ] || fail 'uninstall left the R2O init shim behind'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'uninstall left the owned OpenWrt service behind'
[ ! -e "$CASE/opt/etc/ndm/netfilter.d/001-r2o.sh" ] || fail 'uninstall left the owned NDM hook behind'
echo 'Проверены подпись и SHA-256, ABI, runtime dependencies, flash/RAM preflight, установка, повторный запуск и удаление, чужие hooks, сохранение config и откат при ошибке/прерывании'
