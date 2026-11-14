# Сверка с актуальным D2O main (7a5fab9)

Дата: 2026-11-14. Источник: `https://github.com/t0fox/d2o.git`, отдельный
клон `/mnt/e/d2o-current`, HEAD:

```
7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
```

Pinned C/Rust differential-донор остаётся `a378e230...`; это отдельная
проверка совместимости, а не замена SHA в differential-скриптах.

## Файлы, важные для текущего паритета

| Файл | a378 → 7a5fab9 | Вывод |
|---|---|---|
| `datapath/session.c` | `diff -q` → 0 (байт-идентичен) | `handle_udp`, `session_packet`, `plan_handed_off`, `ct_*` и все текущие datapath differential не устарели |
| `core/tls12.c` | 0 | `d2k_tls12_resume`/`ch12_build` — тот же код; P не из-за смены донора |
| `core/httpsearch.c` | 0 | HTTP Search save/load и probe_run — тот же код |
| `detect/classify.c` | 0 | classifier-ветки и full-tree fixture — тот же код |
| `core/sched.c` | **diff** | Добавлена подсистема `dns_services`: 32 записи, `d2k_sched_set_dns_services`, `dns_service_observe`/`dns_service_note_applied`, `dns_service_live`, health-задачи, `write_live_dns_services` |
| `runtime/d2k_dns_config.c/.h` | новый файл | `doh/dot/doq` URI parse, чтение OpenWrt/Keenetic, bootstrap-resolve, `d2k_dns_service_match` |
| `core/d2kc.c` | diff | `dns_services_refresh` при старте и на тике; diagnostics IPC `diag_transport.h` |
| `core/verify.c` | **diff (+505)** | DoH/DoT/DoQ health-пробы: DNS-запрос `example.com A`, `dns_probe_reply`, `dns_read_frame`, DoQ stream 0, DoH HTTP-разбор; результат `dns_reply`/`D2K_VER_APPLICATION` |
| `core/quicprobe.c` | **diff** | для `port == 853` пул адресов = один intercepted IP, без `d2k_quic_build_pool` |
| `core/tls13core.c` | **diff** | `name_matches`: FQDN с точкой на конце нормализуется (pattern и host), wildcard считается после снятия точки |
| `core/d2kdiag.c`, `core/diag_transport.h`, `runtime/d2k_diag_ipc.h` | новые | diagnostics IPC panel↔core (event/limit/counts/madvise/memory) |
| `dnsprobe/` | новый каталог | отдельный DNS-health probe helper |
| `panel/*`, `telegram/*` | diff | изменения панели/Telegram вне текущей матрицы D2O→R2O |

## Следствия

- Все C/Rust differential, закреплённые на `a378e230`, для `session.c`,
  `tls12.c`, `httpsearch.c`, `classify.c` остаются применимыми к текущему
  main: исходники совпадают.
- **`live.json` не совпадает с текущим main:** в `7a5fab9` появилась секция
  `dns_services` (источники OpenWrt/Keenetic, DoH/DoT/DoQ, bootstrap DNS,
  health/observed-состояние). В R2O этой подсистемы нет; Controller-агент
  добавлять пустой массив отказался. Поэтому полная схема live.json против
  `a378` PASS, но против `7a5fab9` — **не закрыта**.
- Для `dns_services` нужен отдельный контракт: чтение конфигурации
  `/etc/config/https-dns-proxy`, `/etc/config/dnsproxy`, `doqd`, Keenetic
  `ndmc`, matching по наблюдаемому encrypted-DNS endpoint, health/observed
  поля и live-секция. Без него E по текущему main заявлять нельзя.
- **FQDN trailing dot (current main):** `core/tls13core.c:name_matches`
  снимает завершающие точки у pattern и host до сравнения, включая wildcard.
  R2O `response.rs:https_dns_name_bytes_match` этого не делает — нужен
  C/Rust differential на `example.test.`/`*.example.test.` и сертификат
  `example.test`; это отдельный текущий P, не входивший в pinned a378.
- **DoQ port 853 (current main):** `core/quicprobe.c` для DNS-резолвера
  использует intercepted IP как единственный адрес пула. R2O
  `quic_replay.rs:r2o_quic_address_pool` всегда строит пул; после появления
  dns_services это надо учесть в DNS health.
- **Diagnostics IPC (current main):** `core/d2kdiag.c`/`diag_transport.h`/
  `runtime/d2k_diag_ipc.h` добавляют panel↔core event/limit/counts/madvise/
  memory. В R2O есть `diagnostics.rs::Recorder`, но IPC-контракта нет;
  это отдельный блокер, не входящий в 1982-строчную матрицу.
- **`core/verify.c` health-пробы** относятся к dns_services; без подсистемы
  dns_services их нельзя считать закрытыми.

## Что уже сделано в R2O (2026-11-14)

- `crates/r2k-core/src/dns_config.rs`: `DnsService`, `dns_uri_parse`,
  `dns_service_match`, UCI/doqd/Keenetic readers (`parse_https_dns_proxy`,
  `parse_dnsproxy`, `parse_doqd`, `parse_keenetic`, `read_dns_services`).
  C/Rust differential `scripts/test-dns-config-differential.sh` PASS,
  **47 кейсов** (22 URI + 9 match + 16 reader/mixed) против current main
  `7a5fab9`.
- Unit: `cargo test -p r2k-core --lib dns_config` — 8 passed, 2 ignored.
- **FQDN trailing dot:** `https_dns_name_bytes_match` снимает завершающие
  точки с pattern/host, включая wildcard; C/Rust differential
  `test-tls-name-differential.sh` PASS **16/16** против current main.
- **DoQ port 853:** `r2o_quic_address_pool_for_port` для 853 возвращает
  только intercepted IP, resolver не вызывается; differential
  `test-quic-doq-pool-differential.sh` PASS (443 resolver=1, 853 resolver=0,
  IPv4/IPv6). Проводка main использует `primary.port()`, поэтому правило
  действует в production-пути.
- **TLS1.2:** `r2o_tls12_client_hello` повторяет donor `ch12_build`
  (8 случаев точных байт PASS), `r2o_tls12_connect`/`r2o_tls12_resume`
  проходят loopback handshake и downgrade TLS1.3→1.2 с HTTP 200.
  Ограничение: production HTTP/TLS остаётся rustls; P-384 C отвергает.
- **`dns_services` state 2026-11-14:** реализованы `dns_service_live`
  (`generation/ip/applied_plan_id/health-флаги/dns_answer/plan_applied/
  attempts/checked_at/next_check/plan_applied_at/reason`), состояния
  `Detected/Checking/DirectOk/Failed`, production `dns_service_observe`
  из `EVENT_HELLO` (router-source, `server_is_low`, sni/host/ip matching,
  generation++) и `dns_service_note_applied` из non-trial `EVENT_APPLIED`;
  `d2k_sched_set_dns_services` сохраняет live при неизменной конфигурации.
  C/Rust differential `test-dns-state-differential.sh` PASS (4 кейса).
- **Bootstrap/health 2026-11-14:** `dns_resolve_bootstrap` в
  `r2k-core::dns_config` (UDP A→AAAA, 2 сервера, 400 мс, SO_MARK;
  differential 18 vectors + loopback PASS) и `dns_health.rs` DoH/DoT/DoQ
  (`probe_dns_health`, DNS wire/parse, DoH framing; differential 15 PASS,
  loopback DoH/DoT/DoQ).
- Остаются: проводка health в тик `dns_services`, `T_DNS_HEALTH`,
  `bypass_ok`/`no_bypass`/`candidate_plan_applied`/`dns_answer_via_plan`.
  Поэтому `d2k_sched_write_live` — P*.

## Команды проверки

```sh
git clone --depth 1 --branch main https://github.com/t0fox/d2o.git /mnt/e/d2o-current
git -C /mnt/e/d2o-current rev-parse HEAD
diff -q /mnt/e/d2o-a378w/datapath/session.c /mnt/e/d2o-current/datapath/session.c
diff -q /mnt/e/d2o-a378w/core/tls12.c /mnt/e/d2o-current/core/tls12.c
diff -q /mnt/e/d2o-a378w/core/httpsearch.c /mnt/e/d2o-current/core/httpsearch.c
diff -q /mnt/e/d2o-a378w/detect/classify.c /mnt/e/d2o-current/detect/classify.c
```
