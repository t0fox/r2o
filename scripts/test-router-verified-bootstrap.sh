#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/scripts" "$work/bin"
cp "$ROOT/scripts/bootstrap.sh" "$ROOT/scripts/bootstrap-pins.py" "$work/scripts/"
cat > "$work/scripts/install.sh" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$R2O_BOOTSTRAP_TEST/ran"
SH
printf '%s\n' '#!/bin/sh' 'echo не_должно_запуститься >&2' 'exit 95' > "$work/bad"
ref=0123456789abcdef0123456789abcdef01234567
python3 "$work/scripts/bootstrap-pins.py" --write
python3 "$work/scripts/bootstrap-pins.py" --pages "$ref" "$work/get"
cat > "$work/bin/curl" <<'SH'
#!/bin/sh
set -eu
while [ "$#" -gt 1 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        *) shift ;;
    esac
done
case "$1" in
    https://t0fox.github.io/r2o/get)
        cat "$R2O_BOOTSTRAP_TEST/get"
        exit
        ;;
    https://raw.githubusercontent.com/*)
        [ "${R2O_TEST_OFFLINE:-0}" = 0 ] || exit 28
        url=$1 ;;
    https://bad.test/*)
        cp "$R2O_BOOTSTRAP_TEST/bad" "${output:?}"
        exit
        ;;
    https://bad-installer.test/*)
        case "$1" in
            */install.sh) cp "$R2O_BOOTSTRAP_TEST/bad" "${output:?}"; exit ;;
        esac
        url=${1#https://bad-installer.test/} ;;
    https://timeout.test/*) exit 28 ;;
    https://mirror.test/raw/https://*)
        url=${1#https://mirror.test/raw/} ;;
    https://encoded.test/get?url=*)
        url=$(printf '%s' "${1#*?url=}" | sed 's/%3A/:/g; s!%2F!/!g') ;;
    *) exit 22 ;;
esac
case "$url" in
    */0123456789abcdef0123456789abcdef01234567/scripts/bootstrap.sh) cp "$R2O_BOOTSTRAP_TEST/scripts/bootstrap.sh" "${output:?}" ;;
    */0123456789abcdef0123456789abcdef01234567/scripts/install.sh) cp "$R2O_BOOTSTRAP_TEST/scripts/install.sh" "${output:?}" ;;
    *) exit 22 ;;
esac
SH
cat > "$work/bin/apk" <<'SH'
#!/bin/sh
printf 'apk %s\n' "$*" >> "$R2O_BOOTSTRAP_TEST/packages"
[ "${R2O_TEST_OPENWRT:-0}" = 1 ]
SH
cat > "$work/bin/opkg" <<'SH'
#!/bin/sh
printf 'opkg %s\n' "$*" >> "$R2O_BOOTSTRAP_TEST/packages"
SH
chmod 755 "$work/bin/"*
export PATH="$work/bin:$PATH" R2O_BOOTSTRAP_TEST="$work"
sh "$work/get" direct
R2O_TEST_OFFLINE=1 R2O_GITHUB_MIRRORS='https://timeout.test/ https://bad.test/ https://mirror.test/raw/{url}' sh "$work/get" raw
R2O_TEST_OFFLINE=1 R2O_GITHUB_MIRRORS='https://bad.test/ https://encoded.test/get?url={encoded_url}' sh "$work/get" encoded
if R2O_TEST_OFFLINE=1 R2O_GITHUB_MIRRORS='https://bad.test/' sh "$work/get" invalid; then
    echo 'запуск с неверной суммой оказался успешным' >&2
    exit 1
fi
if R2O_TEST_OFFLINE=1 R2O_GITHUB_MIRRORS='https://bad-installer.test/' sh "$work/get" invalid; then
    echo 'установщик с неверной суммой оказался запущен' >&2
    exit 1
fi
entry=$(awk '/^\(apk .*t0fox\.github\.io\/r2o\/get/{print; exit}' "$ROOT/README.md")
[ -n "$entry" ]
R2O_TEST_OPENWRT=1 sh -c "$entry"
sh -c "$entry"
[ "$(wc -l < "$work/ran")" -eq 5 ]
[ "$(sed -n '1,3p' "$work/ran")" = "$(printf 'direct\nraw\nencoded\n')" ]
grep -q '^apk -U add curl ca-bundle$' "$work/packages"
grep -q '^opkg install curl ca-bundle$' "$work/packages"
printf '%s\n' 'проверены команда README, обе платформы, две закреплённые суммы и резервные источники'
