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
| `core/d2kc.c` | diff | `dns_services_refresh` при старте и на тике |

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

## Команды проверки

```sh
git clone --depth 1 --branch main https://github.com/t0fox/d2o.git /mnt/e/d2o-current
git -C /mnt/e/d2o-current rev-parse HEAD
diff -q /mnt/e/d2o-a378w/datapath/session.c /mnt/e/d2o-current/datapath/session.c
diff -q /mnt/e/d2o-a378w/core/tls12.c /mnt/e/d2o-current/core/tls12.c
diff -q /mnt/e/d2o-a378w/core/httpsearch.c /mnt/e/d2o-current/core/httpsearch.c
diff -q /mnt/e/d2o-a378w/detect/classify.c /mnt/e/d2o-current/detect/classify.c
```
