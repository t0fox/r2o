#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TG_FW=$ROOT/router/r2o-tg-firewall.sh
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

mkdir -p "$TEMP/bin" "$TEMP/nft"
printf "DISTRIB_ID='OpenWrt'\n" > "$TEMP/openwrt_release"
cat > "$TEMP/bin/nft" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$NFT_STATE/calls"
case "$1 ${2:-}" in
    "-f -")
        cat > "$NFT_STATE/transaction"
        [ "${NFT_FAIL_TRANSACTION:-0}" = 0 ] || exit 1
        mv "$NFT_STATE/transaction" "$NFT_STATE/last-transaction" ;;
    "-f "*)
        while read -r first second family table _; do
            [ "$first $second" = "delete table" ] || continue
            [ -e "$NFT_STATE/${family}_${table}" ] || exit 1
        done < "$2"
        while read -r first second family table _; do
            [ "$first $second" = "delete table" ] && rm -f "$NFT_STATE/${family}_${table}"
        done < "$2"
        awk -v dir="$NFT_STATE" '
            /^table / { out = dir "/" $2 "_" $3; printf "" > out }
            out { print >> out }
            /^}/ { out = "" }' "$2" ;;
    "list table") cat "$NFT_STATE/${3}_$4" 2>/dev/null || exit 1 ;;
    "list set")
        [ -f "$NFT_STATE/last-transaction" ] || exit 1
        elements=$(awk -v set="$5" '$1 == "add" && $2 == "element" && $5 == set { line=$0; sub(/^add element [^ ]+ [^ ]+ [^ ]+ [^ ]+ [{][[:space:]]*/, "", line); sub(/[[:space:]]*[}][[:space:]]*$/, "", line); print line }' "$NFT_STATE/last-transaction")
        [ -n "$elements" ] || exit 1
        printf 'set %s { elements = { %s }; }\n' "$5" "$elements" ;;
    "delete table") [ -e "$NFT_STATE/${3}_$4" ] || exit 1; rm -f "$NFT_STATE/${3}_$4" ;;
    *) exit 0 ;;
esac
EOF
chmod 0755 "$TEMP/bin/nft"
for tool in iptables ip6tables ipset conntrack; do
    printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/$tool"
    chmod 0755 "$TEMP/bin/$tool"
done

run_tg() {
    env PATH="$TEMP/bin:/usr/bin:/bin" NFT_STATE="$TEMP/nft" \
        R2O_OPENWRT_RELEASE="$TEMP/openwrt_release" R2O_RUNTIME_DIR="$TEMP/nft-runtime" "$@"
}
table() { cat "$TEMP/nft/inet_r2o_tg" 2>/dev/null; }

run_tg sh "$TG_FW" start || fail "не удалось запустить nftables"
rules=$(table)
[ -n "$rules" ] || fail "таблица Telegram для nftables не установлена"
printf '%s\n' "$rules" | grep -qF 'comment "r2o-managed"' || fail "ownership marker missing"
printf '%s\n' "$rules" | grep -qF 'meta mark 0x31 return' || fail "D2O-метка исходящих пакетов r2o-telegram не исключена"
for rule in \
    'ip daddr @tg4 tcp dport 443 redirect to :1443' \
    'ip daddr @tg4 tcp dport 5222 redirect to :1443' \
    'ip6 daddr @tg6 tcp dport 443 redirect to :1443' \
    'ip6 daddr @tg6 tcp dport 5222 redirect to :1443' \
    'ip daddr . tcp dport @tg4_pairs counter redirect to :1443' \
    'ip6 daddr . tcp dport @tg6_pairs counter redirect to :1443'; do
    printf '%s\n' "$rules" | grep -qF "$rule" || fail "отсутствует перенаправление: $rule"
done
[ "$(printf '%s\n' "$rules" | grep -c 'redirect to :1443')" -eq 12 ] || fail "число правил перенаправления не равно 12"

MANIFEST=$TEMP/telegram-dc-endpoints.tsv
printf 'r2o-tg-dc-options-v1 1 2\n149.154.175.52 443\n2001:67c:4e8::1 5222\n' > "$MANIFEST"
run_tg env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map || fail "синхронизация проверенной карты DC завершилась ошибкой"
: > "$TEMP/nft/calls"
run_tg env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map || fail "повторная синхронизация карты DC завершилась ошибкой"
! grep -q '^-f -$' "$TEMP/nft/calls" || fail "неизменённые пары DC повторно применены через nft"
grep -qF 'flush set inet r2o_tg tg4_pairs' "$TEMP/nft/last-transaction" || fail "пакет не очищает набор IPv4 пар"
grep -qF 'flush set inet r2o_tg tg6_pairs' "$TEMP/nft/last-transaction" || fail "пакет не очищает набор IPv6 пар"
grep -qF 'add element inet r2o_tg tg4_pairs { 149.154.175.52 . 443 }' "$TEMP/nft/last-transaction" || fail "IPv4-пара не добавлена"
grep -qF 'add element inet r2o_tg tg6_pairs { 2001:67c:4e8::1 . 5222 }' "$TEMP/nft/last-transaction" || fail "IPv6-пара не добавлена"
cp "$TEMP/nft/last-transaction" "$TEMP/nft/expected-transaction"

printf 'r2o-tg-dc-options-v1 1 2\n149.154.175.52 81\n' > "$MANIFEST"
if run_tg env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map >/dev/null 2>&1; then
    fail "повреждённая карта DC принята"
fi
cmp -s "$TEMP/nft/expected-transaction" "$TEMP/nft/last-transaction" || fail "ошибка проверки изменила рабочие nft-наборы"

printf 'r2o-tg-dc-options-v1 1 3\n149.154.175.53 443\n2001:67c:4e8::2 5222\n' > "$MANIFEST"
if run_tg env NFT_FAIL_TRANSACTION=1 R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map >/dev/null 2>&1; then
    fail "отказ nft-транзакции не был передан вызывающему коду"
fi
cmp -s "$TEMP/nft/expected-transaction" "$TEMP/nft/last-transaction" || fail "отказ nft-транзакции удалил прежние пары"

: > "$TEMP/nft/calls"
run_tg sh "$TG_FW" heal || fail "проверка действующей таблицы завершилась ошибкой"
! grep -q '^-f' "$TEMP/nft/calls" || fail "heal replaced an intact table"

printf 'table inet r2o_tg {\n\tchain foreign { }\n}\n' > "$TEMP/nft/inet_r2o_tg"
if run_tg sh "$TG_FW" start >/dev/null 2>&1; then
    fail "запуск заменил чужую таблицу"
fi
grep -q 'chain foreign' "$TEMP/nft/inet_r2o_tg" || fail "чужая таблица была изменена"

rm -f "$TEMP/nft/inet_r2o_tg"
run_tg sh "$TG_FW" heal || fail "не удалось восстановить отсутствующую таблицу"
run_tg sh "$TG_FW" stop || fail "не удалось остановить firewall"
[ ! -e "$TEMP/nft/inet_r2o_tg" ] || fail "после остановки осталась таблица Telegram"
run_tg sh "$TG_FW" stop || fail "повторная остановка не является идемпотентной"

mkdir -p "$TEMP/iptables-bin" "$TEMP/iptables-state"
for tool in iptables ip6tables; do
    cat > "$TEMP/iptables-bin/$tool" <<'EOF'
#!/bin/sh
[ "$1" = -t ] && [ "$3" = -S ] || exit 2
[ "$2" = nat ] || exit 0
if [ "${0##*/}" = ip6tables ] && [ "${NO_IPV6_NAT:-0}" = 1 ]; then
    echo 'Table does not exist' >&2
    exit 3
fi
cat "$IPT_STATE/${0##*/}"
EOF
    chmod +x "$TEMP/iptables-bin/$tool"
    printf '%s
' '-N FOREIGN' '-A OUTPUT -d 203.0.113.3/32 -j FOREIGN' > "$TEMP/iptables-state/$tool"
done
cat > "$TEMP/iptables-bin/restore" <<'EOF'
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

assert sys.argv[1:] == ["--noflush"]
tool = Path(sys.argv[0]).name.removesuffix("-restore")
path = Path(os.environ["IPT_STATE"]) / tool
rules = path.read_text().splitlines()
lines = sys.stdin.read().splitlines()
assert lines[0] == "*nat" and lines[-1] == "COMMIT"
for line in lines[1:-1]:
    op, chain, *args = line.split()
    if op.startswith(":"):
        assert "-N " + op[1:] not in rules
        rules.insert(0, "-N " + op[1:])
    elif op == "-X":
        rules.remove("-N " + chain)
    elif op == "-F":
        rules = [rule for rule in rules if not rule.startswith(f"-A {chain} ")]
    elif op == "-I":
        assert args.pop(0) == "1"
        rules.insert(0, " ".join(["-A", chain, *args]))
    elif op == "-D":
        rules.remove("-A " + line[3:])
    else:
        assert op == "-A"
        rules.append(line)
if os.getenv("REJECT_RESTORE") == tool:
    print("restore rejected", file=sys.stderr)
    sys.exit(2)
order = ["-N", "-A PREROUTING", "-A OUTPUT", "-A R2O_TG"]
rules.sort(key=lambda rule: next(i for i, prefix in enumerate(order) if rule.startswith(prefix)))
path.write_text("\n".join(rules) + "\n")
EOF
chmod +x "$TEMP/iptables-bin/restore"
ln -s restore "$TEMP/iptables-bin/iptables-restore"
ln -s restore "$TEMP/iptables-bin/ip6tables-restore"
printf '#!/bin/sh
exit 1
' > "$TEMP/iptables-bin/ipset"
chmod +x "$TEMP/iptables-bin/ipset"
run_iptables() {
    env PATH="$TEMP/iptables-bin:/usr/bin:/bin" IPT_STATE="$TEMP/iptables-state" \
        R2O_RUNTIME_DIR="$TEMP/iptables-runtime" R2O_FW=iptables \
        R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" "$@"
}
v4=$TEMP/iptables-state/iptables
v6=$TEMP/iptables-state/ip6tables
export NO_IPV6_NAT=1
printf 'r2o-tg-dc-options-v1 1 2
149.154.175.52 5222
2001:67c:4e8::1 443
' > "$MANIFEST"
run_iptables sync-dc-map
! grep -q REDIRECT "$v4" || fail "синхронизация карты создала правила без активного перехвата"
run_iptables start
grep -qF -- '-d 149.154.175.52/32 -p tcp -m tcp --dport 5222 -j REDIRECT --to-ports 1443' "$v4"
if grep -qF -- '-d 149.154.175.52/32 -p tcp -m tcp --dport 443' "$v4"; then
    fail "несовпадающий порт динамического адреса перехвачен"
fi
if grep -q REDIRECT "$v6"; then fail "IPv6 перенаправление без IPv6 NAT"; fi
grep -q 'exit=3' "$TEMP/iptables-runtime/telegram-firewall.ipv6"
grep -qE '^active ' "$TEMP/iptables-runtime/telegram-firewall.ipv4"
export NO_IPV6_NAT=0
run_iptables heal
grep -qF -- '-d 2001:67c:4e8::1/128 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 1443' "$v6"
grep -qF -- '! --mark 0x31' "$v4"
cp "$v6" "$TEMP/last-good"
printf 'r2o-tg-dc-options-v1 1 3
149.154.175.53 443
2001:67c:4e8::2 5222
' > "$MANIFEST"
export REJECT_RESTORE=ip6tables
run_iptables sync-dc-map
unset REJECT_RESTORE
cmp "$v6" "$TEMP/last-good"
grep -qF -- '-d 149.154.175.53/32 -p tcp -m tcp --dport 443' "$v4"
grep -qF 'restore rejected' "$TEMP/iptables-runtime/telegram-firewall.ipv6"
run_iptables heal
run_iptables stop
run_iptables stop
for listing in "$v4" "$v6"; do
    grep -qF -- '-A OUTPUT -d 203.0.113.3/32 -j FOREIGN' "$listing"
    if grep -q R2O_TG "$listing"; then fail "после stop остались правила Telegram"; fi
done
[ ! -e "$TEMP/iptables-runtime/telegram-firewall.lock" ]
echo "Проверки транзакций nftables и iptables для Telegram прошли"
