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
        R2O_OPENWRT_RELEASE="$TEMP/openwrt_release" "$@"
}
table() { cat "$TEMP/nft/inet_r2o_tg" 2>/dev/null; }

run_tg sh "$TG_FW" start || fail "не удалось запустить nftables"
rules=$(table)
[ -n "$rules" ] || fail "таблица Telegram для nftables не установлена"
printf '%s\n' "$rules" | grep -qF 'comment "r2o-managed"' || fail "ownership marker missing"
printf '%s\n' "$rules" | grep -qF 'meta mark 0x40000000 return' || fail "метка исходящих пакетов r2o-telegram не исключена"
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
tool=${0##*/}
state="$IPT_STATE/$tool"
[ "${1:-}" = -w ] && shift
table=filter
if [ "${1:-}" = -t ]; then table=$2; shift 2; fi
op=$1; shift
case "$op" in
    -C)
        chain=$1; shift
        grep -Fqx -- "$table $chain $*" "$state" 2>/dev/null ;;
    -I)
        chain=$1; shift
        [ "${1:-}" = 1 ] && shift
        printf '%s %s %s\n' "$table" "$chain" "$*" >> "$state" ;;
    -D)
        chain=$1; shift
        [ -f "$state" ] || exit 1
        grep -Fvx -- "$table $chain $*" "$state" > "$state.tmp" || true
        mv "$state.tmp" "$state" ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 "$TEMP/iptables-bin/$tool"
done
cat > "$TEMP/iptables-bin/ipset" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$IPT_STATE/ipset-calls"
mkdir -p "$IPT_STATE/ipsets"
case "$1" in
    create) [ -f "$IPT_STATE/ipsets/$2" ] || : > "$IPT_STATE/ipsets/$2" ;;
    flush) : > "$IPT_STATE/ipsets/$2" ;;
    add) printf '%s\n' "$3" >> "$IPT_STATE/ipsets/$2" ;;
    swap)
        [ "${IPSET_FAIL_SWAP:-}" != "$3" ] || exit 1
        mv "$IPT_STATE/ipsets/$2" "$IPT_STATE/ipsets/.swap"
        mv "$IPT_STATE/ipsets/$3" "$IPT_STATE/ipsets/$2"
        mv "$IPT_STATE/ipsets/.swap" "$IPT_STATE/ipsets/$3" ;;
    destroy)
        shift
        [ "$#" -eq 1 ] || exit 1
        for set in "$@"; do rm -f "$IPT_STATE/ipsets/$set"; done ;;
    list) [ -f "$IPT_STATE/ipsets/$2" ] || exit 1 ;;
    save)
        [ -f "$IPT_STATE/ipsets/$2" ] || exit 1
        while IFS= read -r entry; do printf 'add %s %s\n' "$2" "$entry"; done < "$IPT_STATE/ipsets/$2" ;;
    *) exit 1 ;;
esac
EOF
printf '#!/bin/sh\nexit 0\n' > "$TEMP/iptables-bin/conntrack"
chmod 0755 "$TEMP/iptables-bin/ipset" "$TEMP/iptables-bin/conntrack"
run_iptables() {
    env PATH="$TEMP/iptables-bin:/usr/bin:/bin" IPT_STATE="$TEMP/iptables-state" \
        R2O_FW=iptables R2O_CONFIG=/dev/null R2O_DIR="$TEMP/root" "$@"
}
run_iptables sh "$TG_FW" start || fail "не удалось запустить iptables"
[ "$(grep -c 'REDIRECT --to-port 1443' "$TEMP/iptables-state/iptables")" -eq 6 ] || fail "правила перенаправления IPv4 неполны"
[ "$(grep -c 'REDIRECT --to-port 1443' "$TEMP/iptables-state/ip6tables")" -eq 6 ] || fail "правила перенаправления IPv6 неполны"
grep -qF -- '--mark 0x40000000' "$TEMP/iptables-state/iptables" || fail "не установлено исключение для исходящих пакетов IPv4"
grep -qF -- '--mark 0x40000000' "$TEMP/iptables-state/ip6tables" || fail "не установлено исключение для исходящих пакетов IPv6"
MANIFEST=$TEMP/telegram-dc-endpoints.tsv
printf 'r2o-tg-dc-options-v1 1 2\n149.154.175.52 443\n2001:67c:4e8::1 5222\n' > "$MANIFEST"
run_iptables env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map || fail "синхронизация точных пар в ipset завершилась ошибкой"
grep -Eq 'add r2o_tg_pair4_next_[0-9]+ 149\.154\.175\.52,tcp:443 -exist' "$TEMP/iptables-state/ipset-calls" || fail "IPv4-пара не добавлена в ipset"
grep -Eq 'add r2o_tg_pair6_next_[0-9]+ 2001:67c:4e8::1,tcp:5222 -exist' "$TEMP/iptables-state/ipset-calls" || fail "IPv6-пара не добавлена в ipset"
: > "$TEMP/iptables-state/ipset-calls"
run_iptables env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map || fail "повторная синхронизация карты DC в ipset завершилась ошибкой"
! grep -q '^swap ' "$TEMP/iptables-state/ipset-calls" || fail "неизменённые пары DC повторно применены через ipset"
if find "$TEMP/iptables-state/ipsets" -name 'r2o_tg_pair*_next_*' -print -quit | grep -q .; then
    fail "после синхронизации остались временные ipset"
fi
cp "$TEMP/iptables-state/ipsets/r2o_tg_pair4" "$TEMP/iptables-state/pair4-before-failure"
cp "$TEMP/iptables-state/ipsets/r2o_tg_pair6" "$TEMP/iptables-state/pair6-before-failure"
printf 'r2o-tg-dc-options-v1 1 3\n149.154.175.53 443\n2001:67c:4e8::2 5222\n' > "$MANIFEST"
if run_iptables env IPSET_FAIL_SWAP=r2o_tg_pair6 R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map >/dev/null 2>&1; then
    fail "ошибка замены IPv6-набора не передана вызывающему коду"
fi
cmp -s "$TEMP/iptables-state/pair4-before-failure" "$TEMP/iptables-state/ipsets/r2o_tg_pair4" || fail "отказ IPv6-замены не откатил IPv4-набор"
cmp -s "$TEMP/iptables-state/pair6-before-failure" "$TEMP/iptables-state/ipsets/r2o_tg_pair6" || fail "отказ IPv6-замены изменил прежние IPv6-пары"
if find "$TEMP/iptables-state/ipsets" -name 'r2o_tg_pair*_next_*' -print -quit | grep -q .; then
    fail "после отката остались временные ipset"
fi
before=$(wc -l < "$TEMP/iptables-state/ipset-calls")
printf 'r2o-tg-dc-options-v1 1 2\n149.154.175.52 81\n' > "$MANIFEST"
if run_iptables env R2O_TG_DC_MAP_ENDPOINTS_PATH="$MANIFEST" sh "$TG_FW" sync-dc-map >/dev/null 2>&1; then
    fail "повреждённая карта DC принята для ipset"
fi
[ "$(wc -l < "$TEMP/iptables-state/ipset-calls")" -eq "$before" ] || fail "проверка карты DC изменила ipset до валидации"
run_iptables sh "$TG_FW" stop || fail "не удалось остановить iptables"
[ ! -s "$TEMP/iptables-state/iptables" ] || fail "IPv4 rules remain after stop"
[ ! -s "$TEMP/iptables-state/ip6tables" ] || fail "IPv6 rules remain after stop"

echo "Проверки жизненного цикла nftables и iptables для Telegram прошли"
