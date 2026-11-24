#!/bin/sh
# Вызывать в TLS-стенде с уже запущенными datapath и controller.
# Аргументы: case host address state-dir controller-log controller-pid datapath-pid.

discovery_clock_cs() {
    IFS=' ' read -r timestamp rest </proc/uptime
    fraction=${timestamp#*.}
    printf '%s\n' "$(( ${timestamp%.*} * 100 + 1$fraction - 100 ))"
}

discovery_catalog_has() {
    grep -Fq "\"target\":\"$1\"" "$2/catalog.json" 2>/dev/null
}

measure_discovery() (
    name=$1
    host=$2
    address=$3
    measure_root=$4
    measure_log=$5
    watcher=$6
    daemon=$7
    ! discovery_catalog_has "$host" "$measure_root" || exit 1
    started=$(discovery_clock_cs)
    deadline=$((started + 9500))
    (
        while ! discovery_catalog_has "$host" "$measure_root"; do
            [ "$(discovery_clock_cs)" -lt "$deadline" ] || exit 1
            sleep 1
        done
        printf '%s\n' "$(discovery_clock_cs)" >"$measure_root/$name.persisted"
    ) &
    observer=$!
    trap 'kill "$observer" 2>/dev/null || true; wait "$observer" 2>/dev/null || true' EXIT
    request "$name-trigger" "$host" "$address" || true
    if application "$name-trigger"; then
        echo "DISCOVERY_MEASURE_FAIL уже доступен $host"
        exit 1
    fi
    until grep -Fq "синхронизация каталога поставлена в очередь для $host (" "$measure_log"; do
        kill -0 "$watcher" "$daemon" || exit 1
        [ "$(discovery_clock_cs)" -lt "$deadline" ] || exit 1
        sleep 1
    done
    selected=$(discovery_clock_cs)
    until request "$name-response" "$host" "$address" && application "$name-response"; do
        # OpenSSL может получить всё тело перед разрывом TLS-соединения.
        application "$name-response" && break
        kill -0 "$watcher" "$daemon" || exit 1
        [ "$(discovery_clock_cs)" -lt "$deadline" ] || exit 1
        sleep 1
    done
    delivered=$(discovery_clock_cs)
    wait "$observer" || exit 1
    persisted=$(cat "$measure_root/$name.persisted")
    printf 'DISCOVERY_MEASURE_PASS case=%s target=%s selected_cs=%s response_cs=%s saved_cs=%s\n' \
        "$name" "$host" "$((selected-started))" "$((delivered-started))" "$((persisted-started))"
)
