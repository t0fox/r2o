# Контракт `dns_services` актуального D2O main `7a5fab9`

Источник: `/mnt/e/d2o-current`, SHA `7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05`.
Pinned C/Rust differential-донор остаётся `a378e230...`; здесь описан
**новый** контракт, которого в `a378` нет и который нельзя закрыть пустым
массивом в `live.json`.

## 1. Модель данных

`runtime/d2k_dns_config.h`:

```c
#define D2K_DNS_SERVICE_MAX 32
typedef struct {
    char protocol[4];                     /* doh | dot | doq */
    char host[D2K_DNS_HOST_MAX];          /* 256 */
    char sni[D2K_DNS_HOST_MAX];
    char path[D2K_DNS_PATH_MAX];          /* 1024, DoH target, может содержать токен */
    char bootstrap_dns[D2K_DNS_BOOTSTRAP_MAX]; /* 256, numeric IPs через запятую */
    char source[D2K_DNS_SOURCE_MAX];      /* 32 */
    uint16_t port;
} d2k_dns_service;
```

`core/sched.c` добавляет:

```c
d2k_dns_service dns_services[D2K_DNS_SERVICE_MAX];
dns_service_live dns_service_live[D2K_DNS_SERVICE_MAX];
size_t dns_service_count;
uint64_t dns_service_generation;
```

`dns_service_live` (поля из `core/sched.c:1276-1305`):
`ip`, `state` (`DETECTED/CHECKING/DIRECT_OK/FAILED`), `generation`,
`reason`, `applied_plan_id`, `plan_applied(_ms)`, `checked_ms`,
`next_check_ms`, `attempts`, `tcp_reachable`, `tls_handshake`, `http_status`,
`dns_answer`.

## 2. Разбор URI (`d2k_dns_uri_parse`)

- Схемы: `https://` → `doh`/443, `tls://` → `dot`/853,
  `quic://` → `doq`/853. Регистр схемы не важен.
- Authority: userinfo до `@` отбрасывается; IPv6 в `[..]`; один `:port`;
  порт 1..65535, иначе отказ.
- `host`: только `isalnum`, `.`, `-`, `:`, `%`, нижний регистр; иначе отказ.
- `sni` = host, если host не IP (IPv4/IPv6 literals, scoped IPv6 без zone).
- DoH `path`: `/...` до `#`; `?query` превращается в `/?query`;
  пустой target → `/`; запрещены байты `<=32`, `\`, `"`, длина >= 1024.
- DoT/DoQ path = `/`.
- `source` копируется в 32 байта.

## 3. Чтение системных конфигураций

`d2k_dns_services_read_system`:

- `/etc/openwrt_release` есть → `doqd=/etc/doqd.conf`, иначе
  `/opt/etc/doqd.conf`;
- `doq-web` в `/usr/sbin` или `/opt/sbin` → source `keenetic-doq-web`,
  иначе `doqd`;
- `ndmc` ищется в `/usr/bin`, `/usr/sbin`, `/opt/bin`, `/opt/sbin`;
  `ndmc -c "show dns-proxy"` с таймаутом 250 мс, stderr в `/dev/null`,
  `LD_LIBRARY_PATH=""`; ошибка → чтение остальных источников не выполняется
  (`return -1`).

Парсеры:

| Источник | Файл/команда | Правила |
|---|---|---|
| `https-dns-proxy` | `/etc/config/https-dns-proxy` | секции `config https-dns-proxy`; `option enabled` (0 = выкл), `option bootstrap_dns`, `option resolver_url` (до 8 URL на секцию); flush при следующей секции и в конце |
| `dnsproxy` | `/etc/config/dnsproxy` | глобальная `enabled`; `config dnsproxy 'servers'`; `list bootstrap` (IP[:53], `[IPv6]:53`) и `list upstream`; bootstrap добавляется к upstream |
| `doqd` | `/etc/doqd.conf` или `/opt/etc/doqd.conf` | строки `upstream`/`fallback` + URI; source `doqd` или `keenetic-doq-web` |
| Keenetic | `ndmc -c "show dns-proxy"` | секции `proxy-tls:`/`proxy-https:`; `server-tls:`/`server-https:`; `address:`, `port:`, `sni:`, `uri:`; source `keenetic-system` |

Дедупликация: `protocol + host + port + sni + path`; пустой
`bootstrap_dns` заполняется из дубликата. Лимит 32 записи.

`d2k_sched_set_dns_services` сортирует записи и сохраняет matching-порядок;
`dns_service_generation` инкрементируется при смене.

## 4. Bootstrap DNS

`d2k_dns_resolve_bootstrap(host, servers, mark, ip, cap)`:

- если host — IP literal, вернуть его;
- иначе разобрать `servers` по запятым, максимум 2 сервера;
- UDP/53, `SO_MARK` при mark != 0, `SO_RCVTIMEO=400ms`;
- запрос A (`qtype=1`), затем AAAA (`qtype=28`);
- ID = pid ^ time ^ адрес буфера; проверка ответа: ID, QR, opcode 0, TC 0,
  rcode 0, QDCOUNT 1, вопрос совпал, до 128 answers, name compression до 16
  прыжков, ответ A/AAAA с class IN; иначе отказ.

## 5. Matching и события планировщика

`d2k_dns_service_match(items, count, name, ip, port, transport)`:

- transport только 6/17; port != 0;
- `doq` только UDP; `doh`/`dot` только TCP;
- port совпал;
- совпало `name` с `sni` (при непустом sni) или с `host`, либо `ip` с
  `host` (регистронезависимо).

`dns_service_observe(s, ev, name)`:

- только при `client_is_router_address(ev)` — поток с самого роутера;
- `server_of(ev)` даёт ip/port;
- при смене IP: новая generation, state `DETECTED`, сброс health-полей,
  `next_check_ms = s->now_ms`.

`dns_service_note_applied(s, ev)`:

- trial_id не должен быть нулевым (trial-кандидаты не считаются живым DNS);
- plan_id ненулевой;
- имя из `recall`/`ev->name`, router-source, matching;
- сохранить `applied_plan_id` hex, `plan_applied=1`, `plan_applied_ms`.

`d2k_sched_set_dns_services` вызывается из `d2kc.c:dns_services_refresh` на
старте и на тике; смена конфигурации пересобирает live-состояние.

## 6. `live.json` — секция `dns_services`

`write_live_dns_services` (`core/sched.c:6652-6745`) для каждой записи:

```
protocol, host, port, sni, path (без query), source,
state, status_reason, resolved_ip, checked_at (RFC3339|null),
direct_tcp_reachable, direct_tls_handshake, http_status,
check_attempts, known_plan_id, applied_plan_id,
plan_applied_at (RFC3339|null), plan_applied,
candidate_plan_applied, dns_answer_via_plan, dns_answer_confirmed
```

`state`:

- `bypass_ok` — плановый DoH-зонд получил корректный DNS-ответ;
- `checking` — идёт проверка/кандидат;
- `direct_ok` — прямое соединение подтверждено;
- `plan_applied` — датапат подтвердил план, DNS-ответ ещё нет;
- `no_bypass` — подбор завершён без плана;
- `failed` — проверка failed;
- `detected` — запись найдена, наблюдения ещё нет.

`known_plan_id` берётся из live-binding по `sni|host`, transport
(`doq`→17, иначе 6), family по `resolved_ip` (IPv6 если `:`).

## 7. Health-пробы (`core/verify.c` current main)

- DoT/DoQ: DNS-запрос `example.com A`, length-prefixed frame;
  DoQ stream 0, zero ID; DoT эхо ID соединения.
- DoH: HTTP/1.1 POST/GET на `path`, разбор status/headers/body,
  `Content-Type` DNS message; лимиты `DOH_HEADER_MAX=8192`,
  `DOH_BODY_MAX=4096`.
- Успех: `level=D2K_VER_APPLICATION`, `body_complete=1`, `dns_reply=1`,
  reason «<protocol>: получен корректный DNS-ответ».
- `quicprobe.c`: для `port == 853` пул = один intercepted IP.

## 8. Что нужно в R2O

1. Новый модуль `crates/r2k-core/src/dns_config.rs` (или отдельный crate):
   `DnsService`, `dns_uri_parse`, UCI/doqd/Keenetic parsers, dedup,
   `dns_service_match`, bootstrap resolver. Чистые функции + unit/C/Rust
   differential на фикстурах.
2. Controller state: `dns_services`, `dns_service_live`, generation,
   observe/note_applied; вызовы из обработки событий (router-source,
   non-trial APPLIED).
3. Health-пробы DoH/DoT/DoQ: переиспользовать существующие `https_probe`/
   `quic`/TLS-пути, но с DNS-запросом и разбором ответа; отдельный
   `DnsHealth` job и лимит попыток.
4. `live.json`: секция строго по полям выше; `path` без query.
5. Конфигурационные пути OpenWrt/Keenetic, `/etc/openwrt_release`,
   `doq-web`, `ndmc`, таймаут 250 мс.
6. C/Rust differential: `d2k_dns_uri_parse`, UCI/doqd/Keenetic fixtures,
   match, bootstrap DNS (loopback UDP), live JSON с dns_services.

Пока этот контракт не реализован, `d2k_sched_write_live` остаётся **P***:
против pinned `a378` full live-differential PASS, против current main —
секция `dns_services` отсутствует.
