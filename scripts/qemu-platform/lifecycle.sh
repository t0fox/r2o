#!/opt/bin/sh
set -eu
LAB=${LAB:-/opt/lab}
export LAB
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_LIBRARY_PATH
. "$LAB/settings"
ROOT=/opt/r2o
INIT=/opt/etc/init.d/S99r2o

firewall() {
    "$ROOT/releases/$(slot)/router/r2o-firewall.sh" "$@"
}
slot() { sed -n '2p' "$ROOT/release-slots"; }
ready() {
    attempt=0
    until firewall status >/tmp/r2o-lab-status 2>&1; do
        attempt=$((attempt+1))
        if [ "$attempt" -ge 25 ]; then
            cat /tmp/r2o-lab-status
            tail -50 "$ROOT"/log/*.log 2>/dev/null || true
            return 1
        fi
        sleep 1
    done
    cat /tmp/r2o-lab-status
    grep -q 'queue=2000' /tmp/r2o-lab-status
    grep -q 'queue=2001' /tmp/r2o-lab-status
    "$LAB/network.sh" client
}
accounting_path() {
    if [ -r /proc/sys/net/netfilter/nf_conntrack_acct ]; then
        echo /proc/sys/net/netfilter/nf_conntrack_acct
    else
        echo /sys/module/nf_conntrack/parameters/acct
    fi
}
original() {
    cat "$(accounting_path)" >"$LAB/accounting.before"
    if [ "$LAB_ARCH" = mipsel ]; then
        iptables-save >"$LAB/fw-v4.before"
        ip6tables-save >"$LAB/fw-v6.before"
        cat /proc/sys/net/netfilter/nf_conntrack_fastnat >"$LAB/fastnat.before"
    else
        uci export firewall >"$LAB/fw-uci.before"
        uci export dhcp >"$LAB/dhcp-uci.before"
        nft -s list ruleset >"$LAB/fw-nft.before"
    fi
    (sha256sum /etc/resolv.conf 2>/dev/null || true) >"$LAB/resolv.before"
}
rules_without_counters() {
    sed '/^#/d; s/ \[[0-9]*:[0-9]*\]$//'
}
install_slot() {
    source=$1
    tag=$2
    if [ ! -e "$ROOT/config" ]; then
        mkdir -p "$ROOT"
        cp "$LAB/config" "$ROOT/config"
    fi
    if ! sh "$source/router/install.sh" "$source" "$tag" "$LAB_ARCH" >/tmp/r2o-lab-install 2>&1; then
        cat /tmp/r2o-lab-install
        return 1
    fi
    cat /tmp/r2o-lab-install
    [ "$(slot)" = "$tag" ]
}
remove_slot() {
    if ! sh "$ROOT/releases/$(slot)/router/uninstall.sh" --yes >/tmp/r2o-lab-uninstall 2>&1; then
        cat /tmp/r2o-lab-uninstall
        return 1
    fi
    cat /tmp/r2o-lab-uninstall
    test ! -e "$ROOT" && test ! -e "$INIT"
    test ! -e /opt/etc/ndm/netfilter.d/001-r2o.sh
    test ! -e /etc/init.d/r2o
    awk '$1==2000 || $1==2001 {bad=1} END {exit bad}' /proc/net/netfilter/nfnetlink_queue
    if [ "$LAB_ARCH" = mipsel ]; then
        for family in 4 6; do
            command=iptables-save
            [ "$family" = 4 ] || command=ip6tables-save
            rules_without_counters <"$LAB/fw-v$family.before" >/tmp/r2o-fw.before
            "$command" | rules_without_counters >/tmp/r2o-fw.after
            if ! cmp -s /tmp/r2o-fw.before /tmp/r2o-fw.after; then
                diff -u /tmp/r2o-fw.before /tmp/r2o-fw.after
                return 1
            fi
        done
        cmp "$LAB/fastnat.before" /proc/sys/net/netfilter/nf_conntrack_fastnat
    else
        uci export firewall | cmp - "$LAB/fw-uci.before"
        uci export dhcp | cmp - "$LAB/dhcp-uci.before"
        services=$(ubus call service list '{"name":"r2o"}')
        if printf '%s\n' "$services" | grep -q '"r2o"'; then
            printf 'OPENWRT_PROCD_RESIDUE=%s\n' "$services"
            return 1
        fi
        nft -s list ruleset >"$LAB/fw-nft.after"
        if ! cmp -s "$LAB/fw-nft.after" "$LAB/fw-nft.before"; then
            diff -u "$LAB/fw-nft.before" "$LAB/fw-nft.after"
            return 1
        fi
    fi
    (sha256sum /etc/resolv.conf 2>/dev/null || true) | cmp - "$LAB/resolv.before"
    "$LAB/network.sh" client
    if ! cmp "$LAB/accounting.before" "$(accounting_path)"; then
        echo "ACCOUNTING_RESTORE_FAIL before=$(cat "$LAB/accounting.before") after=$(cat "$(accounting_path)")"
        return 1
    fi
    echo UNINSTALL_PASS
}

case "${1:-}" in
    prepare)
        "$LAB/network.sh" start
        original
        if [ ! -d "$LAB/published/router" ]; then
            mkdir -p "$LAB/published"
            tar -xzf "$LAB/published.tar.gz" -C "$LAB/published"
        fi
        echo PREPARE_PASS
        ;;
    clean)
        test ! -e "$ROOT"
        install_slot "$LAB/bundle" "$LAB_CANDIDATE"
        ready
        echo CLEAN_INSTALL_PASS
        ;;
    upgrade)
        test ! -e "$ROOT"
        install_slot "$LAB/published" "$LAB_PUBLISHED"
        "$LAB/network.sh" client
        cp "$ROOT/config" "$LAB/config.before"
        mkdir -p "$ROOT/state"
        printf 'acceptance persistent file\n' >"$ROOT/state/acceptance-sentinel"
        # Локальный пакет проходит ту же остановку службы, что и online updater.
        "$INIT" update-stop >/tmp/r2o-update-stop.log 2>&1 || { cat /tmp/r2o-update-stop.log; exit 1; }
        awk '$1==2000 || $1==2001 {bad=1} END {exit bad}' /proc/net/netfilter/nfnetlink_queue
        install_slot "$LAB/bundle" "$LAB_CANDIDATE"
        # Менеджер очищает предыдущий выпуск после подтверждения новой службы.
        case "$(sed -n '3p' "$ROOT/release-slots")" in "$LAB_PUBLISHED"|-) ;; *) exit 1 ;; esac
        cmp "$ROOT/config" "$LAB/config.before"
        grep -Fxq 'acceptance persistent file' "$ROOT/state/acceptance-sentinel"
        ready
        "$INIT" update-health
        echo PUBLISHED_UPGRADE_PASS
        ;;
    reboot-network) "$LAB/network.sh" start ;;
    rebooted)
        [ "$(slot)" = "$LAB_CANDIDATE" ]
        attempt=0
        until "$INIT" update-health >/tmp/r2o-boot-health.log 2>&1; do
            attempt=$((attempt+1))
            if [ "$attempt" -ge 25 ]; then
                cat /tmp/r2o-boot-health.log
                exit 1
            fi
            sleep 1
        done
        ready
        echo AUTOBOOT_PASS
        ;;
    soak-start)
        "$LAB/soak.sh" "${2:-600}" >/dev/null 2>&1 </dev/null &
        echo SOAK_STARTED
        ;;
    soak-status)
        if [ -r /tmp/r2o-soak.log ]; then tail -1 /tmp/r2o-soak.log; fi
        ;;
    uninstall) remove_slot ;;
    *) exit 2 ;;
esac
