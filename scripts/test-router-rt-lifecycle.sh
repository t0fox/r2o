#!/bin/sh
# shellcheck disable=SC2034 # Переменные читают извлечённые функции S99r2o.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    if [ -n "${RT_TEST_DNS_BARRIER:-}" ] && [ -d "$RT_TEST_DNS_BARRIER" ]; then
        : > "$RT_TEST_DNS_BARRIER/release"
    fi
    if [ -f "$TEMP/workers.pids" ]; then
        while IFS= read -r fixture_pid; do
            if [ -r "/proc/$fixture_pid/cmdline" ] &&
                tr '\000' ' ' 2>/dev/null < "/proc/$fixture_pid/cmdline" | grep -Fq "$TEMP/worker"; then
                kill -TERM "$fixture_pid" 2>/dev/null || true
            fi
        done < "$TEMP/workers.pids"
    fi
    if [ -f "$TEMP/pids" ]; then
        while IFS= read -r fixture_pid; do
            if [ -r "/proc/$fixture_pid/cmdline" ] &&
                tr '\000' ' ' 2>/dev/null < "/proc/$fixture_pid/cmdline" | grep -Fq "$TEMP/"; then
                kill -TERM "$fixture_pid" 2>/dev/null || true
            fi
        done < "$TEMP/pids"
    fi
    rm -rf "$TEMP"
}
trap cleanup EXIT HUP INT TERM
fail() { printf 'RuTracker lifecycle: %s\n' "$*" >&2; exit 1; }
command -v start-stop-daemon >/dev/null || fail 'нужен настоящий start-stop-daemon'
command -v cc >/dev/null || fail 'нужен C-компилятор для ELF/listener fixture'

sed -n '/^service_pid_alive() {/,/^}/p; /^select_command_shell() {/,/^}/p; /^spawn_logged() {/,/^}/p; /^rt_[a-z_]*() {/,/^}/p' \
    "$REPO/router/S99r2o" > "$TEMP/functions.sh"
# shellcheck disable=SC1091 # Функции получены выше из проверяемого скрипта.
. "$TEMP/functions.sh"
say() { printf '%s\n' "$*"; }
prepare_dirs() { mkdir -p "$RUN" "$STATE" "$LOG" "$RUNTIME"; }

# Настоящий ELF сохраняет PID при exec, открывает TCP listener и пишет marker
# только после listen. Здесь проверяется lifecycle, а не протокол прокси.
cat > "$TEMP/runtime.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop_handler(int sig) { (void)sig; stopping = 1; }
static void event(const char *message) {
    const char *path = getenv("RT_TEST_EVENTS");
    FILE *out = path ? fopen(path, "a") : NULL;
    if (out) { fprintf(out, "process:%s pid=%ld\n", message, (long)getpid()); fclose(out); }
}
int main(int argc, char **argv) {
    unsigned port = 0;
    const char *health = NULL;
    int choose = argc == 2 && strcmp(argv[1], "--choose-port") == 0;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--listen=", 9) == 0) {
            const char *colon = strrchr(argv[i], ':');
            if (!colon) return 2;
            port = (unsigned)strtoul(colon + 1, NULL, 10);
        } else if (strcmp(argv[i], "--health-file") == 0 && i + 1 < argc) {
            health = argv[++i];
        }
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    int reuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) };
    if (!getenv("RT_TEST_NO_LISTEN") || choose) {
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 8) != 0) return 4;
    }
    socklen_t length = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &length) != 0) return 5;
    if (choose) { printf("%u\n", ntohs(addr.sin_port)); close(fd); return 0; }
    signal(SIGTERM, stop_handler);
    signal(SIGINT, stop_handler);
    const char *pids = getenv("RT_TEST_PIDS");
    FILE *out = pids ? fopen(pids, "a") : NULL;
    if (out) { fprintf(out, "%ld\n", (long)getpid()); fclose(out); }
    event("start");
    if (health && !getenv("RT_TEST_NO_HEALTH")) {
        out = fopen(health, "w");
        if (!out) return 6;
        fprintf(out, "R2ORT1 %ld 0.0.0.0:%u\n", (long)getpid(), port);
        fclose(out);
    }
    while (!stopping) {
        struct timespec pause_time = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&pause_time, NULL);
    }
    event("TERM");
    close(fd);
    return 0;
}
C
cc -std=c99 -O2 -Wall -Wextra -Werror "$TEMP/runtime.c" -o "$TEMP/runtime"
cp "$TEMP/runtime" "$TEMP/custom-proxy"
cat > "$TEMP/manager" <<'SH'
#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$#" -gt 0 ] || exit 2
shift
exec "$RT_TEST_RUNTIME" "$@"
SH
cat > "$TEMP/adapter" <<'SH'
#!/bin/sh
set -eu
kind=${0##*/}
alive=0
pid=$(cat "$RT_TEST_PIDFILE" 2>/dev/null || true)
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null &&
    awk '$3 != "Z" && $3 != "X" {ok=1} END {exit !ok}' "/proc/$pid/stat" 2>/dev/null; then alive=1; fi
fw=0
[ ! -f "$RT_TEST_STATE/fw" ] || fw=1
printf '%s:%s alive=%s fw=%s\n' "$kind" "$1" "$alive" "$fw" >> "$RT_TEST_EVENTS"
if [ "$kind" = dns ] && [ -n "${RT_TEST_DNS_BARRIER:-}" ] &&
    [ -d "$RT_TEST_STATE/dns-operation" ]; then
    printf 'dns:overlap action=%s\n' "$1" >> "$RT_TEST_EVENTS"
    exit 73
fi
case "$kind:$1" in
    fw:status|dns:status) [ -f "$RT_TEST_STATE/$kind" ] ;;
    fw:apply)
        : > "$RT_TEST_STATE/fw"
        [ "${RT_TEST_FW_FAIL:-0}" != 1 ] ;;
    fw:stop) rm -f "$RT_TEST_STATE/fw" ;;
    dns:apply)
        if [ -n "${RT_TEST_DNS_BARRIER:-}" ]; then
            mkdir "$RT_TEST_STATE/dns-operation" || exit 73
            : > "$RT_TEST_DNS_BARRIER/entered"
            dns_wait=0
            while [ ! -e "$RT_TEST_DNS_BARRIER/release" ]; do
                dns_wait=$((dns_wait + 1))
                [ "$dns_wait" -lt 200 ] || exit 74
                sleep 0.05
            done
            rmdir "$RT_TEST_STATE/dns-operation"
        fi
        : > "$RT_TEST_STATE/dns"
        : > "$RT_TEST_STATE/dns-attempt"
        [ "${RT_TEST_DNS_FAIL:-0}" != 1 ] ;;
    dns:clear)
        [ "${RT_TEST_CLEAR_FAIL:-0}" != 1 ] || exit 1
        if [ "${RT_TEST_CLEAR_AFTER_APPLY_FAIL:-0}" = 1 ] &&
            [ -f "$RT_TEST_STATE/dns-attempt" ]; then exit 1; fi
        rm -f "$RT_TEST_STATE/dns" ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$TEMP/manager" "$TEMP/adapter"
ln -s adapter "$TEMP/fw"
ln -s adapter "$TEMP/dns"

# Отдельные shell-процессы имеют разные $$, как start и firewall-watchdog.
# Обычный background вызов shell-функции сохранил бы $$ родителя.
cat > "$TEMP/worker" <<'SH'
#!/bin/sh
set -u
# shellcheck disable=SC1090 # Снимок извлечённых production-функций.
. "$RT_TEST_FUNCTIONS"
say() { printf '%s\n' "$*"; }
prepare_dirs() { mkdir -p "$RUN" "$STATE" "$LOG" "$RUNTIME"; }
printf '%s\n' "$$" > "$RT_TEST_STATE/worker.$2.pid"
case "$1" in
    start) rt_proxy_start ;;
    heal) rt_proxy_heal ;;
    health) rt_proxy_health ;;
    *) exit 2 ;;
esac
worker_result=$?
printf '%s\n' "$worker_result" > "$RT_TEST_STATE/worker.$2.result"
exit "$worker_result"
SH
chmod 0755 "$TEMP/worker"

RT_TEST_RUNTIME=$TEMP/runtime
RT_TEST_PIDS=$TEMP/pids
RT_TEST_FUNCTIONS=$TEMP/functions.sh
export RT_TEST_RUNTIME RT_TEST_PIDS RT_TEST_FUNCTIONS

new_case() {
    ROOT=$TEMP/$1
    RUN=$ROOT/run STATE=$ROOT/state LOG=$ROOT/log RUNTIME=$ROOT/runtime
    CONF=/dev/null PROC=/proc
    RT_PROXY_PID=$RUN/rt.pid RT_PROXY_HEALTH=$RUNTIME/rt.health RT_PROXY_LOG=$LOG/rt.log
    RT_FIREWALL=$TEMP/fw RT_DNS=$TEMP/dns MANAGER=$TEMP/manager
    RT_PROXY_ENABLED=1 RT_PROXY_BIN='' RT_PROXY_PORT=$($TEMP/runtime --choose-port)
    RT_SENTINEL=203.0.113.171 RT_DOMAINS=rutracker.org MARK=45 R2O_FW=iptables
    SUPERVISOR_DISABLED=$RUNTIME/supervisor-disabled
    RT_TEST_EVENTS=$ROOT/events RT_TEST_PIDFILE=$RT_PROXY_PID RT_TEST_STATE=$ROOT/fixture
    export RT_TEST_EVENTS RT_TEST_PIDFILE RT_TEST_STATE
    unset RT_TEST_FW_FAIL RT_TEST_DNS_FAIL RT_TEST_CLEAR_FAIL RT_TEST_CLEAR_AFTER_APPLY_FAIL
    unset RT_TEST_NO_HEALTH RT_TEST_NO_LISTEN
    unset RT_TEST_DNS_BARRIER
    mkdir -p "$RT_TEST_STATE"
    prepare_dirs
    : > "$RT_TEST_EVENTS"
}

assert_stopped() {
    [ ! -e "$RUN/rt-proxy.lock" ] || fail 'после операции остался RT lock'
    [ ! -e "$RT_PROXY_PID" ] && [ ! -e "$RT_PROXY_HEALTH" ] || fail 'после stop остались PID/health'
    [ ! -e "$RT_TEST_STATE/fw" ] && [ ! -e "$RT_TEST_STATE/dns" ] || fail 'после stop остались DNS/NAT'
    [ -z "${old_pid:-}" ] || ! service_pid_alive "$old_pid" || fail 'после stop остался процесс'
}

start_worker() {
    export ROOT RUN STATE LOG RUNTIME CONF PROC
    export RT_PROXY_PID RT_PROXY_HEALTH RT_PROXY_LOG RT_PROXY_ENABLED RT_PROXY_BIN RT_PROXY_PORT
    export RT_FIREWALL RT_DNS MANAGER RT_SENTINEL RT_DOMAINS MARK R2O_FW SUPERVISOR_DISABLED
    "$TEMP/worker" "$1" "$2" > "$ROOT/worker.$2.log" 2>&1 &
    worker_pid=$!
    printf '%s\n' "$worker_pid" >> "$TEMP/workers.pids"
}

wait_path() {
    wait_attempt=0
    while [ ! -e "$1" ]; do
        wait_attempt=$((wait_attempt + 1))
        [ "$wait_attempt" -lt 200 ] || {
            for worker_log in "$ROOT"/worker.*.log; do
                [ ! -f "$worker_log" ] || cat "$worker_log" >&2
            done
            fail "не дождались $1"
        }
        sleep 0.05
    done
}

new_case normal
rt_proxy_start || fail 'нормальный запуск'
old_pid=$(cat "$RT_PROXY_PID")
rt_proxy_health || fail 'готовый listener не прошёл health'
printf 'R2ORT1 %s 0.0.0.0:%s\n' "$$" "$RT_PROXY_PORT" > "$RT_PROXY_HEALTH"
! rt_proxy_ready || fail 'принят marker чужого PID'
printf 'R2ORT1 %s 0.0.0.0:%s\n' "$old_pid" "$((RT_PROXY_PORT + 1))" > "$RT_PROXY_HEALTH"
! rt_proxy_ready || fail 'принят marker другого порта'
printf 'R2ORT1 %s 0.0.0.0:%s\n' "$old_pid" "$RT_PROXY_PORT" > "$RT_PROXY_HEALTH"
mv "$RT_PROXY_HEALTH" "$RT_PROXY_HEALTH.real"
ln -s "$RT_PROXY_HEALTH.real" "$RT_PROXY_HEALTH"
! rt_proxy_ready || fail 'принят health symlink'
rm "$RT_PROXY_HEALTH"
mv "$RT_PROXY_HEALTH.real" "$RT_PROXY_HEALTH"
rt_proxy_ready || fail 'восстановленный marker не принят'
rt_proxy_start || fail 'повторный start'
[ "$(cat "$RT_PROXY_PID")" = "$old_pid" ] || fail 'повторный start заменил работающий процесс'
rm "$RT_TEST_STATE/fw" "$RT_TEST_STATE/dns"
rt_proxy_heal || fail 'heal после пропажи правил/DNS'
[ "$(cat "$RT_PROXY_PID")" = "$old_pid" ] || fail 'heal перезапустил исправный listener'
rt_proxy_health || fail 'heal не восстановил DNS/NAT'
: > "$RT_TEST_EVENTS"
RT_TEST_CLEAR_FAIL=1
export RT_TEST_CLEAR_FAIL
if rt_proxy_stop full; then fail 'ошибка DNS clear потеряна'; fi
[ ! -e "$RUN/rt-proxy.lock" ] || fail 'ошибка DNS clear оставила RT lock'
rt_proxy_running || fail 'при ошибке DNS clear потерян процесс'
[ "$(cat "$RT_PROXY_PID")" = "$old_pid" ] && [ -f "$RT_PROXY_HEALTH" ] || fail 'при ошибке clear удалены PID/health'
[ -f "$RT_TEST_STATE/fw" ] && [ -f "$RT_TEST_STATE/dns" ] || fail 'при ошибке clear сняты DNS/NAT'
! grep -Eq 'process:TERM|fw:stop' "$RT_TEST_EVENTS" || fail 'clear error не остановил teardown'
unset RT_TEST_CLEAR_FAIL
: > "$RT_TEST_EVENTS"
rt_proxy_stop full || fail 'повторная остановка после восстановления DNS'
assert_stopped
awk '
    NR == 1 && $0 == "dns:clear alive=1 fw=1" {clear=1}
    /^process:TERM / {if (!clear) exit 1; term=1}
    /^fw:stop alive=0 / {if (!term) exit 1; stopped=1}
    END {exit !(clear && term && stopped)}' "$RT_TEST_EVENTS" || fail 'нарушен порядок DNS clear → TERM → NAT stop'
rt_proxy_stop full || fail 'идемпотентный stop'

for failure in firewall dns; do
    new_case "failed-$failure"
    if [ "$failure" = firewall ]; then RT_TEST_FW_FAIL=1; export RT_TEST_FW_FAIL
    else RT_TEST_DNS_FAIL=1; export RT_TEST_DNS_FAIL; fi
    if rt_proxy_start; then fail "ошибка $failure apply потеряна"; fi
    old_pid=$(tail -n 1 "$RT_TEST_PIDS")
    assert_stopped
done

new_case failed-dns-clear
RT_TEST_DNS_FAIL=1 RT_TEST_CLEAR_AFTER_APPLY_FAIL=1
export RT_TEST_DNS_FAIL RT_TEST_CLEAR_AFTER_APPLY_FAIL
if rt_proxy_start; then fail 'частичный отказ DNS apply потерян'; fi
[ ! -e "$RUN/rt-proxy.lock" ] || fail 'ошибка rollback DNS оставила RT lock'
old_pid=$(cat "$RT_PROXY_PID")
rt_proxy_ready || fail 'при отказе rollback clear уничтожен готовый listener'
[ -f "$RT_TEST_STATE/fw" ] && [ -f "$RT_TEST_STATE/dns" ] || fail 'при отказе rollback clear снята работающая интеграция'
unset RT_TEST_DNS_FAIL RT_TEST_CLEAR_AFTER_APPLY_FAIL
rt_proxy_stop full || fail 'не выполнена отложенная очистка'
assert_stopped

new_case disabled
RT_PROXY_ENABLED=0
old_pid=
rt_proxy_start || fail 'остановленный disabled runtime'
rt_proxy_heal || fail 'disabled heal'
assert_stopped
! grep -q '^process:start ' "$RT_TEST_EVENTS" || fail 'disabled runtime был запущен'

new_case missing-marker
RT_TEST_NO_HEALTH=1
export RT_TEST_NO_HEALTH
if rt_proxy_start; then fail 'живой PID без marker принят за готовый listener'; fi
old_pid=$(tail -n 1 "$RT_TEST_PIDS")
assert_stopped

# Настоящий ELF с произвольным именем должен определяться по /proc/PID/exe.
new_case external
RT_PROXY_BIN=$TEMP/custom-proxy
rt_proxy_start || fail 'внешний ELF с пользовательским именем не запустился'
old_pid=$(cat "$RT_PROXY_PID")
rt_proxy_ready || fail 'внешний listener не опознан по inode сокета'
RT_PROXY_PORT=$((RT_PROXY_PORT + 1))
rt_proxy_running || fail 'смена порта скрыла прежний внешний PID'
! rt_proxy_ready || fail 'внешний listener принят на другом порту'
rt_proxy_stop full || fail 'не остановлен прежний внешний PID после смены порта'
assert_stopped

new_case misleading-argv
"$TEMP/runtime" --rt-proxy-extra --listen=:"$RT_PROXY_PORT" &
old_pid=$!
printf '%s\n' "$old_pid" > "$RT_PROXY_PID"
sleep 0.1
! rt_proxy_running || fail 'подстрока --rt-proxy-extra принята за режим --rt-proxy'
kill -TERM "$old_pid"
wait "$old_pid"
rm "$RT_PROXY_PID"

# DNS apply удерживается до запуска всех независимых конкурентов. Health
# должен дождаться готовности всей операции, а не увидеть промежуточный DNS.
new_case concurrent-start-heal-health
RT_TEST_DNS_BARRIER=$ROOT/barrier
export RT_TEST_DNS_BARRIER
mkdir "$RT_TEST_DNS_BARRIER"
start_worker start first
first_worker=$worker_pid
wait_path "$RT_TEST_DNS_BARRIER/entered"
[ "$(cat "$RUN/rt-proxy.lock/pid")" = "$first_worker" ] || fail 'RT lock не принадлежит первому worker'
start_worker start second
second_worker=$worker_pid
start_worker heal heal
heal_worker=$worker_pid
start_worker health health
health_worker=$worker_pid
for worker in second heal health; do wait_path "$RT_TEST_STATE/worker.$worker.pid"; done
[ "$(cat "$RT_TEST_STATE"/worker.*.pid | sort -u | wc -l)" -eq 4 ] || fail 'конкуренты не являются отдельными процессами'
sleep 0.2
for worker in first second heal health; do
    [ ! -e "$RT_TEST_STATE/worker.$worker.result" ] || fail "$worker завершился до освобождения DNS apply"
done
[ "$(grep -c '^process:start ' "$RT_TEST_EVENTS")" -eq 1 ] || fail 'параллельный запуск создал несколько ELF'
: > "$RT_TEST_DNS_BARRIER/release"
concurrent_failure=0
for worker in "$first_worker" "$second_worker" "$heal_worker" "$health_worker"; do
    wait "$worker" || concurrent_failure=1
done
if [ "$concurrent_failure" = 1 ]; then
    cat "$ROOT"/worker.*.log >&2
    fail 'параллельный start/heal/health вернул ошибку'
fi
for worker in first second heal health; do
    [ "$(cat "$RT_TEST_STATE/worker.$worker.result")" = 0 ] || fail "$worker вернул ненулевой результат"
done
[ "$(grep -c '^process:start ' "$RT_TEST_EVENTS")" -eq 1 ] || fail 'после снятия блокировки создан повторный ELF'
! grep -q '^dns:overlap ' "$RT_TEST_EVENTS" || fail 'операции DNS выполнились одновременно'
[ ! -e "$RUN/rt-proxy.lock" ] || fail 'успешные конкуренты оставили RT lock'
old_pid=$(cat "$RT_PROXY_PID")
rt_proxy_health || fail 'после параллельного запуска health не готов'
printf 'RT_LIFECYCLE_CONCURRENCY={"worker_pids":[%s,%s,%s,%s],"elf_pid":%s,"elf_starts":1,"results":[0,0,0,0],"dns_overlap":false,"lock_removed":true}\n' \
    "$first_worker" "$second_worker" "$heal_worker" "$health_worker" "$old_pid"
rt_proxy_stop full || fail 'остановка после параллельного запуска'
assert_stopped

# PID действительно существовал и был забран wait, это не выдуманный номер.
new_case stale-lock
"$TEMP/runtime" --choose-port > /dev/null &
stale_pid=$!
wait "$stale_pid"
! kill -0 "$stale_pid" 2>/dev/null || fail 'PID для stale lock всё ещё жив'
mkdir "$RUN/rt-proxy.lock"
printf '%s\n' "$stale_pid" > "$RUN/rt-proxy.lock/pid"
start_worker start recovered
recovered_worker=$worker_pid
if ! wait "$recovered_worker"; then
    cat "$ROOT/worker.recovered.log" >&2
    fail 'не восстановлен RT lock с завершённым PID'
fi
[ "$(cat "$RT_TEST_STATE/worker.recovered.result")" = 0 ] || fail 'восстановление stale lock вернуло ошибку'
[ ! -e "$RUN/rt-proxy.lock" ] || fail 'после восстановления остался RT lock'
[ "$(grep -c '^process:start ' "$RT_TEST_EVENTS")" -eq 1 ] || fail 'stale lock recovery неверно запустил ELF'
old_pid=$(cat "$RT_PROXY_PID")
rt_proxy_health || fail 'после stale lock recovery health не готов'
printf 'RT_LIFECYCLE_STALE_LOCK={"dead_pid":%s,"worker_pid":%s,"elf_pid":%s,"result":0,"lock_removed":true}\n' \
    "$stale_pid" "$recovered_worker" "$old_pid"
rt_proxy_stop full || fail 'остановка после stale lock recovery'
assert_stopped

printf '%s\n' 'RuTracker lifecycle: настоящий ELF/launcher/listener, readiness, безопасный rollback, disabled, external PID, параллельные start/heal/health и stale lock проверены'
