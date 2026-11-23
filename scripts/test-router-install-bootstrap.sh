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
head=0
if [ "${1:-}" = --version ]; then
    [ "${TEST_MISSING_BOOTSTRAP:-0}" = 0 ] || [ -e "$R2O_TEST_INSTALLED/curl" ]
    exit $?
fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--max-filesize|--connect-timeout|--max-time|--proto|--proto-redir|--retry|--retry-delay)
            [ "$#" -ge 2 ] || exit 2
            if [ "$1" = -o ]; then output=$2; fi
            shift 2
            ;;
        -I|--head) head=1; shift ;;
        --progress-bar) shift ;;
        -* ) shift ;;
        * ) url=$1; shift ;;
    esac
done
[ -n "$url" ] || exit 2
original_url=$url
case "$url" in
    https://partial.test/*) exit 28 ;;
    https://bad-signature.test/*)
        case "$url" in
            */latest.json.sig) dd if=/dev/zero of="$output" bs=64 count=1 2>/dev/null; exit 0 ;;
            */latest.json) url=${url#https://bad-signature.test/} ;;
            *) exit 22 ;;
        esac
        ;;
    https://bad-archive.test/*)
        case "$url" in
            */r2o-*.tar.gz) printf 'broken archive' > "$output"; exit 0 ;;
            *) exit 22 ;;
        esac
        ;;
    https://mirror.test/get?url=*)
        url=$(printf '%s' "${url#*?url=}" | sed 's/%3A/:/g; s!%2F!/!g') ;;
    *) [ "${R2O_TEST_MIRROR_ONLY:-0}" != 1 ] || exit 28 ;;
esac
if [ "$head" -eq 1 ]; then
    [ "${R2O_TEST_FAIL_HEAD:-0}" = 1 ] && exit 22
    case "$url" in
        */r2o-mipsel-openwrt-musl.tar.gz)
            archive_size=$(wc -c < "$R2O_TEST_FIXTURES/r2o-mipsel-openwrt-musl.tar.gz" | tr -d ' ')
            printf 'HTTP/2 302\r\ncontent-length: 0\r\n\r\nHTTP/2 200\r\ncontent-length: %s\r\n' \
                "$archive_size"
            exit 0
            ;;
        *) exit 22 ;;
    esac
fi
[ -n "$output" ] || exit 2
printf '%s\t%s\n' "$original_url" "$output" >> "$R2O_TEST_FETCH_LOG"
case "$url" in
    */latest.json.sig) source=$R2O_TEST_FIXTURES/latest.json.sig ;;
    */latest.json) source=$R2O_TEST_FIXTURES/latest.json ;;
    https://api.github.com/repos/t0fox/r2o/releases/tags/*)
        [ "${R2O_TEST_FAIL_API:-0}" = 1 ] && exit 22
        source=$R2O_TEST_FIXTURES/release-api.json
        ;;
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
cat > "$MOCK/apk" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = -U ]; then shift; fi
case "${1:-}" in
    update) printf 'update\n' >> "$R2O_TEST_PACKAGE_LOG" ;;
    add)
        shift
        printf '%s\n' "$*" >> "$R2O_TEST_PACKAGE_LOG"
        for pkg do
            case "$pkg" in --*) ;; *) touch "$R2O_TEST_INSTALLED/$pkg" ;; esac
        done ;;
    del) printf 'del %s\n' "$2" >> "$R2O_TEST_PACKAGE_LOG" ;;
    *) exit 2 ;;
esac
EOF
cat > "$MOCK/modprobe" <<'EOF'
#!/bin/sh
set -eu
module=${1:?}
printf '%s\n' "$module" >> "$R2O_TEST_MODULE_LOG"
case "$module" in
    nfnetlink_queue)
        [ "${TEST_NO_NFQUEUE:-0}" = 0 ]
        [ -e "$R2O_TEST_INSTALLED/kmod-nfnetlink-queue" ] || [ "${TEST_ENTWARE_KERNEL:-0}" = 1 ]
        : > "$R2O_NFQUEUE_STATUS_FILE" ;;
    nft_queue) [ -e "$R2O_TEST_INSTALLED/kmod-nft-queue" ] ;;
    nf_conntrack_netlink)
        [ -e "$R2O_TEST_INSTALLED/kmod-nf-conntrack-netlink" ] || [ "${TEST_ENTWARE_KERNEL:-0}" = 1 ] ;;
    xt_NFQUEUE)
        printf 'NFQUEUE\n' > "$R2O_PROC_DIR/net/ip_tables_targets" ;;
esac
mkdir -p "$R2O_SYS_MODULE_DIR/$module"
EOF
cat > "$MOCK/nft" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
    --version) exit 0 ;;
    '-c -f -')
        grep -q 'queue num 65535 bypass' || exit 2
        [ -d "$R2O_SYS_MODULE_DIR/nft_queue" ] ;;
    *) exit 88 ;;
esac
EOF
cat > "$MOCK/conntrack" <<'EOF'
#!/bin/sh
case "$1" in
    -V) exit 0 ;;
    -C) [ -d "$R2O_SYS_MODULE_DIR/nf_conntrack_netlink" ] ;;
    *) exit 88 ;;
esac
EOF
cat > "$MOCK/openssl" <<'EOF'
#!/bin/sh
if [ "$1" = version ] && [ "${TEST_MISSING_BOOTSTRAP:-0}" = 1 ] &&
    [ ! -e "$R2O_TEST_INSTALLED/openssl-util" ]; then exit 1; fi
exec /usr/bin/openssl "$@"
EOF
cat > "$MOCK/start-stop-daemon" <<'EOF'
#!/bin/sh
case " $* " in *' -t '*) exit 88 ;; esac
executable=
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    case "$1" in -x) executable=$2; shift ;; esac
    shift
done
shift
exec "$executable" "$@"
EOF
cat > "$MOCK/sh" <<'EOF'
#!/bin/sh
exec /bin/sh "$@"
EOF
cat > "$MOCK/opkg" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    print-architecture) printf 'arch all 1\narch %s 100\n' "${TEST_ENTWARE_ARCH:-mipsel-3.4_kn}" ;;
    update) printf 'opkg update\n' >> "$R2O_TEST_PACKAGE_LOG" ;;
    install)
        shift
        printf 'opkg %s\n' "$*" >> "$R2O_TEST_PACKAGE_LOG"
        for pkg do
            case "$pkg" in kmod*) [ "${TEST_OPENWRT_OPKG:-0}" = 1 ] || exit 89 ;; esac
            touch "$R2O_TEST_INSTALLED/$pkg"
        done ;;
    *) exit 2 ;;
esac
EOF
cat > "$MOCK/iptables" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
    -V|'-t mangle -S PREROUTING'|'-t nat -S OUTPUT')
        [ "${TEST_NEED_IPTABLES:-0}" = 0 ] || [ -e "$R2O_TEST_INSTALLED/iptables" ] ;;
    '-j NFQUEUE --queue-num 65535 --queue-bypass --help')
        [ "${TEST_NEED_IPT_QUEUE:-0}" = 0 ] || [ -e "$R2O_TEST_INSTALLED/iptables-mod-nfqueue" ] ;;
    *) exit 88 ;;
esac
EOF
cat > "$MOCK/ip6tables" <<'EOF'
#!/bin/sh
printf 'IPv6\n' >> "$R2O_TEST_PROBES"
[ "$*" != '-t nat -S OUTPUT' ] || exit 88
[ "${TEST_DISABLE_IP6TABLES:-0}" = 0 ]
EOF
cat > "$MOCK/ipset" <<'EOF'
#!/bin/sh
set -eu
[ "$*" = --version ] || [ "$*" = 'list -n' ] || exit 88
[ "${TEST_NEED_IPSET:-0}" = 0 ] || [ -e "$R2O_TEST_INSTALLED/ipset" ]
EOF
printf '#!/bin/sh\nexit 0\n' > "$MOCK/ip"
cat > "$MOCK/dmesg" <<'EOF'
#!/bin/sh
[ "${TEST_KERNEL_FAILURE:-0}" = 1 ] || exit 1
printf '%s\n' 'unrelated kernel record' 'Out of memory: Killed process 1234 (r2o-datapath)'
EOF
chmod 0755 "$MOCK/"*

cat > "$FIXTURE/builds/r2o-datapath-linux-mipsel-openwrt-musl" <<'EOF'
#!/bin/sh
case "$1" in
    --help) printf '  --runtime-preflight\n' ;;
    --offline-self-check)
        if [ "${TEST_DATAPATH_FAIL:-0}" != 0 ]; then
            printf '%s\n' 'R2O_TEST_DATAPATH_CHILD_STDERR' >&2
            exit "$TEST_DATAPATH_FAIL"
        fi ;;
    --runtime-preflight) printf '%s %s\n' "$2" "$3" >> "$R2O_TEST_PROBES" ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 "$FIXTURE/builds/r2o-datapath-linux-mipsel-openwrt-musl"

cat > "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl" <<'EOF'
#!/bin/sh
set -eu
command_name=$1
shift
case "$command_name" in
    --version) exit 0 ;;
    update-install)
        printf 'update-install %s\nmirrors %s\n' "$*" "${R2O_GITHUB_MIRRORS:-}" >> "$R2O_TEST_MANAGER_LOG"
        ;;
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
        if [ "${R2O_TEST_FAIL_DURING_INSTALL:-0}" = 1 ]; then
            mkdir -p "$root/log"
            printf '%s\n' 'R2O_TEST_DATAPATH_FAILURE_BEFORE_ROLLBACK' > "$root/log/r2o-datapath.log"
            printf '%s\n' 'R2O_TEST_SPLIT_FAILURE_BEFORE_ROLLBACK' > "$root/log/r2o-datapath4.log"
            exit 1
        fi
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
cp "$ROOT/router/select-panel-ip.sh" "$FIXTURE/router/select-panel-ip.sh"
cp "$ROOT/router/r2o-firewall-fw3-include.sh" "$FIXTURE/router/r2o-firewall-fw3-include.sh"
cat > "$FIXTURE/router/S99r2o.shim" <<'EOF'
#!/bin/sh
if [ "${1:-}" = start ] && [ "${R2O_TEST_START_FAIL:-0}" = 1 ]; then
    if [ "${TEST_KERNEL_FAILURE:-0}" = 0 ]; then
        mkdir -p "$R2O_DIR/log"
        printf '%s\n' 'R2O_TEST_SERVICE_STDERR' > "$R2O_DIR/log/r2o-datapath.log"
        printf '%s\n' 'R2O_TEST_CONTROLLER_STDERR' > "$R2O_DIR/log/r2o-controller4.log"
    fi
    exit 37
fi
EOF
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/S99r2o"
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/001-r2o.sh"
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/router/r2o-ppe-deoffload.sh"
printf '#!/bin/sh\n[ -z "${R2O_TEST_SERVICE_LOG:-}" ] || printf "%%s\\n" "$*" >> "$R2O_TEST_SERVICE_LOG"\n' > "$FIXTURE/router/openwrt-init"
printf 'MODE=apply\nTG_ENABLED=1\n' > "$FIXTURE/router/config.default"
printf 'R2O-STATE-1\n' > "$FIXTURE/router/update-schema"
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
    -e "s|^SYSTEM_PATH=.*|SYSTEM_PATH=$MOCK:/usr/sbin:/usr/bin:/sbin:/bin|" \
    -e "s|PUBLIC_KEY_B64='[^']*'|PUBLIC_KEY_B64='$PUBLIC_KEY_B64'|" "$ROOT/scripts/install.sh" \
    > "$TEMP/install.sh" || fail 'scripts/install.sh is missing'
grep -Fqx "PUBLIC_KEY_B64='$PUBLIC_KEY_B64'" "$TEMP/install.sh" || fail 'test public key was not pinned in the bootstrap copy'

new_case() {
    CASE=$TEMP/$1
    mkdir -p "$CASE/tmp" "$CASE/etc" "$CASE/opt/etc/init.d" "$CASE/opt/etc/ndm/netfilter.d" \
        "$CASE/etc/init.d" "$CASE/fixtures" "$CASE/proc/net/netfilter" "$CASE/sys/module"
    printf 'DISTRIB_ID="OpenWrt"\nDISTRIB_ARCH="mipsel_24kc"\n' > "$CASE/openwrt_release"
    printf 'MemTotal: 131072 kB\nMemAvailable: 131072 kB\nMemFree: 120000 kB\nBuffers: 1000 kB\nCached: 5000 kB\nShmem: 500 kB\n' > "$CASE/meminfo"
    cp -R "$FIXTURE/." "$CASE/fixtures/"
    : > "$CASE/fetch.log"
    : > "$CASE/manager.log"
    : > "$CASE/packages.log"
    : > "$CASE/probes.log"
    mkdir "$CASE/installed"
}

run_install() {
    R2O_OPENWRT_RELEASE="${TEST_OPENWRT_RELEASE:-$CASE/openwrt_release}" \
    R2O_MEMINFO_FILE="$CASE/meminfo" \
    R2O_ENTWARE_OPKG="$MOCK/opkg" \
    R2O_NDM_PLATFORM_DIR="${TEST_NDM_MARKER:-$CASE/no-ndm}" \
    R2O_PROC_DIR="$CASE/proc" \
    R2O_TEST_PROBES="$CASE/probes.log" \
    R2O_TEST_INSTALLED="$CASE/installed" \
    R2O_DIR="$CASE/opt/r2o" \
    R2O_INIT_DIR="$CASE/opt/etc/init.d" \
    R2O_NDM_DIR="$CASE/opt/etc/ndm/netfilter.d" \
    R2O_OPENWRT_INIT_DIR="$CASE/etc/init.d" \
    R2O_RUNTIME_DIR="$CASE/tmp/r2o" \
    R2O_TEST_FIXTURES="$CASE/fixtures" \
    R2O_TEST_FETCH_LOG="$CASE/fetch.log" \
    R2O_TEST_MANAGER_LOG="$CASE/manager.log" \
    R2O_TEST_PACKAGE_LOG="$CASE/packages.log" \
    R2O_TEST_MODULE_LOG="$CASE/modules.log" \
    R2O_TEST_SERVICE_LOG="$CASE/services.log" \
    R2O_NFQUEUE_STATUS_FILE="$CASE/proc/net/netfilter/nfnetlink_queue" \
    R2O_SYS_MODULE_DIR="$CASE/sys/module" \
    R2O_TEST_FREE_KB="${TEST_FREE_KB:-200000}" \
    TMPDIR="$CASE/tmp" PATH="$MOCK:$PATH" \
        sh "$TEMP/install.sh"
}

new_case damaged-signature
# Детерминированно портим подпись: 64 нулевых байта вместо валидной
# Ed25519. Замена одного байта на 'x' иногда не меняла файл (если первый
# байт подписи уже был 0x78), и CI падал с «damaged signature was accepted».
dd if=/dev/zero of="$CASE/fixtures/latest.json.sig" bs=64 count=1 2>/dev/null
[ "$(wc -c < "$CASE/fixtures/latest.json.sig" | tr -d ' ')" = 64 ] ||
    fail 'damaged signature fixture is not 64 bytes'
cmp -s "$CASE/fixtures/latest.json.sig" "$FIXTURE/latest.json.sig" &&
    fail 'signature fixture was not actually damaged'
if run_install > "$CASE/out" 2>&1; then fail 'damaged Ed25519 signature was accepted'; fi
grep -q 'подпись' "$CASE/out" || fail 'bad signature was not rejected at signature verification'
grep -q 'r2o-mipsel-openwrt-musl.tar.gz' "$CASE/fetch.log" && fail 'archive downloaded before signature verification'
[ ! -e "$CASE/opt/r2o" ] || fail 'bad signature created the installation root'

new_case damaged-archive
printf x | dd of="$CASE/fixtures/r2o-mipsel-openwrt-musl.tar.gz" bs=1 seek=0 conv=notrunc 2>/dev/null
cmp -s "$CASE/fixtures/r2o-mipsel-openwrt-musl.tar.gz" "$FIXTURE/r2o-mipsel-openwrt-musl.tar.gz" &&
    fail 'archive fixture was not actually damaged'
if run_install > "$CASE/out" 2>&1; then fail 'archive with a hash mismatch was accepted'; fi
grep -q 'SHA-256' "$CASE/out" || { cat "$CASE/out" >&2; cat "$CASE/fetch.log" >&2; fail 'archive hash mismatch was not rejected'; }
[ ! -s "$CASE/manager.log" ] || fail 'archive code ran before its SHA-256 was verified'
[ ! -e "$CASE/opt/r2o" ] || fail 'bad archive created the installation root'

new_case api-without-size
# GitHub API вернул ответ без размера актива (кэш/прокси). Размер должен быть
# взят из Content-Length загрузки на github.com.
printf '{"message":"API rate limit exceeded"}\n' > "$CASE/fixtures/release-api.json"
run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'install failed when the GitHub API had no asset size'; }
grep -q 'по заголовкам загрузки' "$CASE/out" || fail 'HEAD size fallback was not reported'
[ -s "$CASE/manager.log" ] || fail 'manager was not activated after the HEAD size fallback'

new_case api-unreachable
# API недоступен целиком; выпуск и его подпись на github.com доступны.
R2O_TEST_FAIL_API=1 run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'install failed when the GitHub API was unreachable'; }
grep -q 'по заголовкам загрузки' "$CASE/out" || fail 'unreachable API did not use the HEAD size fallback'
[ -s "$CASE/manager.log" ] || fail 'manager was not activated after the unreachable API fallback'

new_case verified-configured-mirror
printf '{"release_id":"r2o-bootstrap-test","version":"1","notes":"","assets":{"mipsel-openwrt-musl":{"sha256":"%s","bytes":%s}}}\n' \
    "$ARCHIVE_SHA" "$ARCHIVE_SIZE" > "$CASE/fixtures/latest.json"
openssl pkeyutl -sign -inkey "$TEMP/test-key.pem" -rawin -in "$CASE/fixtures/latest.json" \
    -out "$CASE/fixtures/latest.json.sig"
R2O_TEST_MIRROR_ONLY=1 R2O_GITHUB_MIRRORS='https://partial.test/ https://bad-signature.test/ https://bad-archive.test/ https://mirror.test/get?url={encoded_url}' \
    run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'clean install did not switch to the verified mirror'; }
grep -q '^https://mirror.test/get?url=https%3A%2F%2Fgithub.com.*latest.json.sig' "$CASE/fetch.log" ||
    fail 'the valid signature was not loaded through the encoded mirror'
grep -q '^https://mirror.test/get?url=https%3A%2F%2Fgithub.com.*r2o-mipsel-openwrt-musl.tar.gz' "$CASE/fetch.log" ||
    fail 'the valid archive was not loaded through the encoded mirror'
[ -s "$CASE/manager.log" ] || fail 'the verified release did not run'

new_case api-and-head-unavailable
# API и заголовки недоступны (wget без -S, прокси): архив скачивается с
# верхним лимитом, измеряется фактический размер и установка продолжается.
R2O_TEST_FAIL_API=1 R2O_TEST_FAIL_HEAD=1 run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'install failed when neither API nor HEAD reported the size'; }
grep -q 'проверяю фактический размер' "$CASE/out" || fail 'bounded download fallback was not reported'
[ -s "$CASE/manager.log" ] || fail 'manager was not activated after the bounded download fallback'

new_case unsupported-abi
sed 's/mipsel_24kc/mips_4kc/' "$CASE/openwrt_release" > "$CASE/openwrt_release.new"
mv "$CASE/openwrt_release.new" "$CASE/openwrt_release"
if run_install > "$CASE/out" 2>&1; then fail 'unsupported MIPS-I big-endian ABI was accepted'; fi
grep -q 'неподдерживаем' "$CASE/out" || { cat "$CASE/out" >&2; fail 'unsupported ABI failure was not explained'; }
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for an unsupported ABI'

new_case unsupported-openwrt-mips1
sed 's/mipsel_24kc/mipsel_4kc/' "$CASE/openwrt_release" > "$CASE/openwrt_release.new"
mv "$CASE/openwrt_release.new" "$CASE/openwrt_release"
if run_install > "$CASE/out" 2>&1; then fail 'MIPS-I OpenWrt architecture was mapped to an incompatible MIPS32r2 ABI'; fi
grep -q 'неподдерживаем' "$CASE/out" || fail 'unsupported MIPS-I ABI failure was not explained'
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for an unsupported MIPS-I ABI'

new_case missing-nfqueue-modules
run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'NFQUEUE dependency install fixture failed'; }
grep -q 'kmod-nft-queue' "$CASE/packages.log" || fail 'nft NFQUEUE package was not installed'
grep -q 'kmod-nfnetlink-queue' "$CASE/packages.log" || fail 'NFQUEUE core package was not installed'
grep -qx nfnetlink_queue "$CASE/modules.log" || fail 'nfnetlink_queue module was not loaded'
grep -qx nft_queue "$CASE/modules.log" || fail 'nft_queue module was not loaded'
[ -f "$CASE/proc/net/netfilter/nfnetlink_queue" ] || fail 'NFQUEUE status did not appear after module load'

for outcome in success failure; do
    new_case "temporary-apk-$outcome"
    if [ "$outcome" = success ]; then
        TEST_MISSING_BOOTSTRAP=1 run_install > "$CASE/out" 2>&1 ||
            { cat "$CASE/out" >&2; fail 'bootstrap with temporary APK dependencies failed'; }
    else
        dd if=/dev/zero of="$CASE/fixtures/latest.json.sig" bs=64 count=1 2>/dev/null
        if TEST_MISSING_BOOTSTRAP=1 run_install > "$CASE/out" 2>&1; then fail 'damaged signature was accepted'; fi
    fi
    helper=$(awk '$1 == "--virtual" && $3 == "openssl-util" && $4 == "curl" { print $2 }' "$CASE/packages.log")
    case "$helper" in .r2o-bootstrap-*) ;; *) fail 'bootstrap dependencies are not temporary' ;; esac
    grep -Fqx "del $helper" "$CASE/packages.log" || fail 'temporary APK group was left installed'
    if [ "$outcome" = success ]; then
        grep -Eq '^kmod-nfnetlink-queue ' "$CASE/packages.log" || fail 'runtime modules are not separate'
    else
        ! grep -q 'kmod-' "$CASE/packages.log" || fail 'runtime dependencies installed before signature verification'
    fi
done

new_case unsupported-keenetic-softfloat
if TEST_ENTWARE_ARCH=armv7sf-k3.2 TEST_OPENWRT_RELEASE="$CASE/no-openwrt-release" run_install > "$CASE/out" 2>&1; then
    fail 'Keenetic soft-float ABI was mapped to hard-float R2O'
fi
grep -q 'неподдерживаем' "$CASE/out" || fail 'incompatible Keenetic ABI failure was not explained'
[ ! -s "$CASE/fetch.log" ] || fail 'release network was touched for incompatible Keenetic ABI'

prepare_entware_fixture() {
    for component in manager datapath; do
        mv "$CASE/fixtures/builds/r2o-$component-linux-mipsel-openwrt-musl" "$CASE/fixtures/builds/r2o-$component-linux-mipsel"
    done
    sign_fixture mipsel
}

sign_fixture() {
    signed="$CASE/fixtures/r2o-$1.tar.gz"
    tar -czf "$signed" -C "$CASE/fixtures" builds router
    signed_sha=$(sha256sum "$signed" | awk '{print $1}')
    printf '{"release_id":"r2o-bootstrap-test","version":"1","notes":"","assets":{"%s":{"sha256":"%s"}}}\n' \
        "$1" "$signed_sha" > "$CASE/fixtures/latest.json"
    openssl pkeyutl -sign -inkey "$TEMP/test-key.pem" -rawin -in "$CASE/fixtures/latest.json" -out "$CASE/fixtures/latest.json.sig"
}

run_entware() {
    R2O_LOCAL_MANIFEST="$CASE/fixtures/latest.json" \
    R2O_LOCAL_ARCHIVE="$CASE/fixtures/r2o-mipsel.tar.gz" \
        run_install
}

new_case clean-openwrt-opkg
mv "$MOCK/apk" "$TEMP/apk"
TEST_OPENWRT_OPKG=1 run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'clean OpenWrt failed with native opkg'; }
mv "$TEMP/apk" "$MOCK/apk"
grep -q '^opkg .*kmod-nfnetlink-queue' "$CASE/packages.log" || fail 'OpenWrt opkg did not install kernel dependencies'
grep -Fxq 'apply 1' "$CASE/probes.log" || fail 'datapath did not check IPv6-enabled configuration'

new_case openwrt-missing-iptables-nfqueue-extension
printf '%s\n' 'FW_BACKEND=iptables' >> "$CASE/fixtures/router/config.default"
sign_fixture mipsel-openwrt-musl
TEST_NEED_IPT_QUEUE=1 R2O_LOCAL_MANIFEST="$CASE/fixtures/latest.json" \
    R2O_LOCAL_ARCHIVE="$CASE/fixtures/r2o-mipsel-openwrt-musl.tar.gz" run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'OpenWrt could not install its NFQUEUE extension'; }
grep -q '^iptables-mod-nfqueue$' "$CASE/packages.log" || fail 'OpenWrt did not repair its iptables NFQUEUE extension'

new_case clean-keenetic
prepare_entware_fixture
TEST_OPENWRT_RELEASE="$CASE/no-openwrt-release" TEST_ENTWARE_KERNEL=1 run_entware > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'clean Keenetic installation did not start'; }
[ -f "$CASE/opt/etc/ndm/netfilter.d/001-r2o.sh" ] || fail 'Keenetic did not install the NDM hook'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'Keenetic installed an OpenWrt init script'
grep -Fxq 'apply 1' "$CASE/probes.log" || fail 'Keenetic failed to check IPv6 without optional NAT6'

new_case clean-keenetic-ported-with-ipv4-only
mkdir "$CASE/ndm"
printf '%s\n' "  IPV6_ENABLED='0' # Только IPv4" >> "$CASE/fixtures/router/config.default"
prepare_entware_fixture
TEST_NDM_MARKER="$CASE/ndm" TEST_ENTWARE_KERNEL=1 TEST_NEED_IPTABLES=1 TEST_NEED_IPSET=1 \
    TEST_DISABLE_IP6TABLES=1 run_entware > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'clean Keenetic Ported install did not repair partial dependencies'; }
grep -q 'платформа: keenetic; ABI: mipsel-3.4_kn -> mipsel' "$CASE/out" || fail 'Keenetic Ported used OpenWrt platform'
grep -q '^opkg .*ipset' "$CASE/packages.log" || fail 'Entware did not install ipset'
grep -q '^opkg .*iptables' "$CASE/packages.log" || fail 'Entware did not install iptables'
! grep -q 'kmod' "$CASE/packages.log" || fail 'Entware tried to install kernel modules'
grep -Fxq 'apply 0' "$CASE/probes.log" || fail 'datapath did not check IPv4-only'
! grep -q IPv6 "$CASE/probes.log" || fail 'IPv4-only configuration touched ip6tables'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'Keenetic Ported installed an OpenWrt init script'

new_case keenetic-without-nfqueue
prepare_entware_fixture
if TEST_OPENWRT_RELEASE="$CASE/no-openwrt-release" TEST_NO_NFQUEUE=1 run_entware > "$CASE/out" 2>&1; then
    fail 'Keenetic without NFQUEUE was activated'
fi
grep -q 'NFQUEUE недоступен.*modprobe nfnetlink_queue' "$CASE/out" || fail 'missing NFQUEUE did not show the firmware command'
[ ! -s "$CASE/manager.log" ] || fail 'missing NFQUEUE was checked after activation'
! grep -q 'kmod' "$CASE/packages.log" || fail 'Entware tried to repair firmware with kernel packages'

new_case insufficient-memory
sed -i 's/^MemAvailable:.*/MemAvailable: 7000 kB/' "$CASE/meminfo"
if run_install > "$CASE/out" 2>&1; then fail 'low-memory installation continued'; fi
grep -q 'освободите память' "$CASE/out" || fail 'missing memory diagnostics'
[ ! -s "$CASE/packages.log" ] && [ ! -s "$CASE/fetch.log" ] || fail 'packages were touched before the memory check'

new_case datapath-failed-to-start
if TEST_DATAPATH_FAIL=7 run_install > "$CASE/out" 2>&1; then fail 'broken datapath was activated'; fi
grep -q 'datapath не запустился через start-stop-daemon.*код 7' "$CASE/out" || fail 'launcher failure status was not shown'
grep -qx 'R2O_TEST_DATAPATH_CHILD_STDERR' "$CASE/out" || fail 'datapath stderr was not printed'
[ ! -s "$CASE/manager.log" ] || fail 'broken datapath was checked after activation'
[ -z "$(ls -A "$CASE/tmp")" ] || fail 'broken datapath left temporary logs on the router'

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

new_case legacy-refused
mkdir -p "$CASE/opt/r2o/releases/r2o-old/router" "$CASE/opt/etc/init.d"
cp "$FIXTURE/router/config.default" "$CASE/opt/r2o/releases/r2o-old/router/"
printf '%s\n' mipsel-openwrt-musl > "$CASE/opt/r2o/releases/r2o-old/release-architecture"
cp "$FIXTURE/builds/r2o-manager-linux-mipsel-openwrt-musl" "$CASE/opt/r2o/r2o-manager"
printf 'R2O-RELEASE-SLOTS-1\nr2o-old\n' > "$CASE/opt/r2o/release-slots"
printf 'owner=kept\n' > "$CASE/opt/r2o/config"
cp "$FIXTURE/router/S99r2o.shim" "$CASE/opt/etc/init.d/S99r2o"
run_install > "$CASE/out" 2>&1 && fail 'legacy install was accepted'
grep -q 'legacy-установка' "$CASE/out" || fail 'legacy rejection was not explained'
[ ! -s "$CASE/manager.log" ] && [ ! -s "$CASE/fetch.log" ] || fail 'legacy update was attempted'
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-old ] || fail 'legacy slot was modified'
grep -qx 'owner=kept' "$CASE/opt/r2o/config" || fail 'legacy configuration was modified'

new_case failed-first-install
if R2O_TEST_FAIL_DURING_INSTALL=1 run_install > "$CASE/out" 2>&1; then
    fail 'incomplete first install was accepted'
fi
grep -Fq 'R2O_TEST_DATAPATH_FAILURE_BEFORE_ROLLBACK' "$CASE/out" ||
    fail 'merged datapath diagnostics disappeared before rollback'
grep -Fq 'R2O_TEST_SPLIT_FAILURE_BEFORE_ROLLBACK' "$CASE/out" ||
    fail 'split datapath diagnostics disappeared before rollback'
[ ! -e "$CASE/opt/r2o" ] || fail 'incomplete first install left release files behind'
[ ! -e "$CASE/opt/etc/init.d/S99r2o" ] || fail 'incomplete first install left its startup shim behind'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'incomplete first install left its OpenWrt service behind'
grep -q 'kmod-nft-queue' "$CASE/packages.log" || fail 'failed install removed or skipped its system NFQUEUE dependency'
grep -q 'kmod-nfnetlink-queue' "$CASE/packages.log" || fail 'failed install removed or skipped its NFQUEUE core package'

new_case failed-service-start-after-activation
if R2O_TEST_START_FAIL=1 run_install > "$CASE/out" 2>&1; then
    fail 'a failed service start was accepted'
fi
grep -q 'установщик выпуска завершился ошибкой (код 37)' "$CASE/out" || fail 'service exit status was not shown'
grep -qx 'R2O_TEST_SERVICE_STDERR' "$CASE/out" || fail 'datapath startup stderr was not shown'
grep -qx 'R2O_TEST_CONTROLLER_STDERR' "$CASE/out" || fail 'controller startup stderr was not shown'
[ ! -e "$CASE/opt/r2o" ] || fail 'service startup failure did not remove the new installation'
[ -z "$(ls -A "$CASE/tmp")" ] || fail 'service startup failure left temporary logs'

new_case kernel-killed-the-service-before-it-could-log
if R2O_TEST_START_FAIL=1 TEST_KERNEL_FAILURE=1 run_install > "$CASE/out" 2>&1; then
    fail 'a service killed before logging was accepted'
fi
grep -Fq 'Out of memory: Killed process 1234 (r2o-datapath)' "$CASE/out" || fail 'kernel cause was not shown'
! grep -Fq 'unrelated kernel record' "$CASE/out" || fail 'unrelated kernel messages were shown'
[ ! -e "$CASE/opt/r2o" ] || fail 'failed first install left an active slot'

new_case interrupted-install
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
R2O_TEST_PACKAGE_LOG="$CASE/packages.log" \
R2O_TEST_INSTALLED="$CASE/installed" \
R2O_TEST_PROBES="$CASE/probes.log" \
R2O_PROC_DIR="$CASE/proc" \
R2O_TEST_MODULE_LOG="$CASE/modules.log" \
R2O_TEST_SERVICE_LOG="$CASE/services.log" \
R2O_NFQUEUE_STATUS_FILE="$CASE/proc/net/netfilter/nfnetlink_queue" \
R2O_SYS_MODULE_DIR="$CASE/sys/module" \
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
[ ! -e "$CASE/opt/r2o/release-slots" ] || fail 'interrupted bootstrap left an active slot'
[ ! -e "$CASE/opt/etc/init.d/S99r2o" ] || fail 'interrupted bootstrap left an init shim'

new_case local-signed-install
# Локальный подписанный манифест/архив: установка не должна обращаться к сети.
mkdir -p "$CASE/opt/.r2o-install.stale"
touch -d '2 hours ago' "$CASE/opt/.r2o-install.stale"
R2O_LOCAL_MANIFEST="$CASE/fixtures/latest.json" \
R2O_LOCAL_SIGNATURE="$CASE/fixtures/latest.json.sig" \
R2O_LOCAL_ARCHIVE="$CASE/fixtures/r2o-mipsel-openwrt-musl.tar.gz" \
    run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'local signed install failed'; }
grep -q 'использую локальный подписанный манифест' "$CASE/out" ||
    fail 'local manifest mode was not reported'
grep -q 'использую локальный архив' "$CASE/out" ||
    fail 'local archive mode was not reported'
[ ! -s "$CASE/fetch.log" ] || fail 'local install still contacted the network'
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-bootstrap-test ] ||
    fail 'local signed release was not activated'
[ ! -e "$CASE/opt/.r2o-install.stale" ] ||
    fail 'stale bootstrap staging was not removed'

new_case install-repeat
run_install > "$CASE/out" 2>&1 || { cat "$CASE/out" >&2; fail 'valid signed release did not install'; }
[ -z "$(find "$CASE/tmp" -maxdepth 1 -name 'r2o-install.*' -print -quit)" ] ||
    fail 'installer left its temporary directory'
[ -z "$(find "$CASE/opt/r2o" -maxdepth 1 -name '.r2o-install.*' -print -quit)" ] ||
    fail 'installer left staging on flash'
[ "$(sed -n '2p' "$CASE/opt/r2o/release-slots")" = r2o-bootstrap-test ] || fail 'release manager did not activate the signed release'
grep -qx 'MODE=apply' "$CASE/opt/r2o/config" || fail 'first install did not initialize configuration'
mkdir -p "$CASE/opt/r2o/state"
printf '%s\n' '{"schema":1,"boxes":[{"id":"kept"}]}' > "$CASE/opt/r2o/state/catalog.json"
install_count=$(grep -c '^install-local ' "$CASE/manager.log")
printf '#!/bin/sh\nexit 31\n' > "$CASE/opt/r2o/releases/r2o-bootstrap-test/router/install.sh"
chmod 0755 "$CASE/opt/r2o/releases/r2o-bootstrap-test/router/install.sh"
fetch_count=$(wc -l < "$CASE/fetch.log")
TEST_DATAPATH_FAIL=7 R2O_GITHUB_MIRRORS=https://example.test/ run_install > "$CASE/out" 2>&1 ||
    { cat "$CASE/out" >&2; fail 'repeat install did not reach the updater with a broken old datapath'; }
[ "$(wc -l < "$CASE/fetch.log")" -eq "$fetch_count" ] || fail 'bootstrap downloaded before calling the Rust updater'
grep -q '^update-install --root .* --service ' "$CASE/manager.log" || fail 'Rust updater was not invoked'
grep -Fxq 'mirrors https://example.test/' "$CASE/manager.log" || fail 'Rust updater did not inherit the mirror'
[ "$(grep -c '^install-local ' "$CASE/manager.log")" -eq "$install_count" ] || fail 'repeat install reactivated an already current release'
printf '%s\n' '{"schema":1,"boxes":[{"id":"kept"}]}' > "$CASE/expected-catalog.json"
cmp -s "$CASE/opt/r2o/state/catalog.json" "$CASE/expected-catalog.json" ||
    fail 'repeat install changed the state catalog'
R2O_OPENWRT_RELEASE="$CASE/openwrt_release" \
R2O_DIR="$CASE/opt/r2o" \
R2O_INIT_DIR="$CASE/opt/etc/init.d" \
R2O_NDM_DIR="$CASE/opt/etc/ndm/netfilter.d" \
R2O_OPENWRT_INIT_DIR="$CASE/etc/init.d" \
R2O_RUNTIME_DIR="$CASE/tmp/r2o" R2O_PLATFORM=openwrt \
    sh "$ROOT/scripts/uninstall.sh" --yes \
    > "$CASE/uninstall.out" 2>&1 || { cat "$CASE/uninstall.out" >&2; fail 'owned installation did not uninstall'; }
[ ! -e "$CASE/opt/r2o" ] || fail 'uninstall left the R2O release root behind'
[ ! -e "$CASE/opt/etc/init.d/S99r2o" ] || fail 'uninstall left the R2O init shim behind'
[ ! -e "$CASE/etc/init.d/r2o" ] || fail 'uninstall left the owned OpenWrt service behind'
[ ! -e "$CASE/opt/etc/ndm/netfilter.d/001-r2o.sh" ] || fail 'uninstall left the owned NDM hook behind'
echo 'Проверены подпись и SHA-256, ABI, runtime dependencies, flash/RAM preflight, установка, повторный запуск и удаление, чужие hooks, сохранение config и откат при ошибке/прерывании'
