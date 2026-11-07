#!/bin/sh
# B53: KEENETIC_POLICY -> ndmc policy mark -> --only-mark.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP/bin"
cat > "$TEMP/bin/ndmc" <<'EOF'
#!/bin/sh
cat <<'OUT'
policy, name = Policy0, description = Guest:
    mark: 1234
policy, name = Policy1, description = Office:
    mark: 00ff
OUT
EOF
chmod 0755 "$TEMP/bin/ndmc"
PATH="$TEMP/bin:$PATH"
export PATH
. "$ROOT/router/r2o-policy-mark.sh"

mark=$(r2o_keenetic_policy_mark Policy0)
[ "$mark" = 1234 ] || { echo "Policy0 mark: $mark" >&2; exit 1; }
mark=$(r2o_keenetic_policy_mark Guest)
[ "$mark" = 1234 ] || { echo "Guest mark: $mark" >&2; exit 1; }
mark=$(r2o_keenetic_policy_mark Office)
[ "$mark" = 00ff ] || { echo "Office mark: $mark" >&2; exit 1; }
[ -z "$(r2o_keenetic_policy_mark Missing)" ] || { echo "missing policy returned a mark" >&2; exit 1; }

# Та же трансляция, что в S99r2o: найдено -> 0xMARK/0xffffffff, не найдено -> none.
case "$(r2o_keenetic_policy_mark Policy0)" in
    ''|*[!0-9a-fA-F]*) echo "valid policy rejected" >&2; exit 1 ;;
    *) only_mark="0x$(r2o_keenetic_policy_mark Policy0)/0xffffffff" ;;
esac
[ "$only_mark" = "0x1234/0xffffffff" ] || { echo "only-mark: $only_mark" >&2; exit 1; }
echo "KEENETIC_POLICY извлекает метку политики и формирует --only-mark"
