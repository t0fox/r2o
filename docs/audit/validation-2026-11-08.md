# Независимая валидация аудита D2O → R2O (2026-11-08)

Цель — проверить полноту самого аудита, а не повысить процент готовности. Production-код не изменялся.

## 1. Метод

- Заново извлечены все определения production C-функций лексическим сканером, который маскирует комментарии, строки и preprocessor-директивы и учитывает многострочные сигнатуры.
- Отдельно извлечены `static inline` функции из production-заголовков.
- Проверены все `file:line`-ссылки, имена скриптов и cited revisions.
- Каждая функция сверена с текстом аудиторских отчётов; для неназванных функций построен отдельный список.
- Уточнённая матрица пересчитана после добавления найденных пропущенных контрактов.

## 2. Полнота инвентаря функций

| Показатель | Прежний индекс | Независимая проверка |
|---|---:|---:|
| Production `.c`-функции | 2523 | 2523 |
| `static inline` в заголовках | 0 | **61** |
| Всего production-функций | 2523 | **2584** |

Прежний инвентарь не был полным:

- **3 ложных срабатывания:** `refusal` (`core/quicarms.c:59`, комментарий), `dead` (`relay-enroll/main.c:132`, комментарий), дубль `d2k_props_contact_on_family_tcp_profile` (`core/verify.c:1361`, вызов; определение — `core/compose.c:638`).
- **3 пропущенные `.c`-функции:** `monotonic_ms` (`panel/server.c:41`), `shared_lock` (`relay-enroll/main.c:133`), `now_ms` (`relay-gate/main.c:295`).
- **61 пропущенная header-inline функция:** HTTP reply/request/response, `d2k_ctl_binding_*`, `d2k_binding_*`, `d2k_key_equal`, `d2k_packet_parse`, `d2k_resource_*`, `d2k_diag_*`, `d2k_runtime_*`, `d2k_arm_segment`, `d2k_link_shape_*`, `d2k_quic_*` budget/stall/judge, `d2k_ip6frag_*`, `d2k_prop_majority`.

Исправленный полный индекс: `docs/audit/function-index.md` (2584 строки, каждая с Rust-владельцем, контрактом и статусом). Для функций, не названных в отчётах, статус `implemented-unproven` или `missing`, а не «equivalent»: 660 таких функций перечислены в `docs/audit/unmentioned-functions.md`.

### Что это доказывает

- Все 2584 production-функции имеют строку в индексе.
- Ни одна функция не осталась без Rust-владельца или явного статуса `missing`/`not-applicable`.
- Наличие строки не означает паритет: 1798 функций имеют `partial`, 675 — `implemented-unproven`, 16 — scoped `equivalent`, 23 — `missing`, 72 — `not-applicable`.

## 3. Полнота контрактов

Аудит 2026-11-07 содержал 97 контрактов / 132 балла. Валидация нашла 11 отсутствовавших контрактов и добавила их с 0 баллов:

| ID | Контракт | Вес | Почему отсутствовал |
|---|---|---:|---|
| D20 | TCP timestamp shape contexts 8–13 | 2 | `d2k_link_shape_tcp_context` используется `sched.c`; R2O знает только shapes 1–7 |
| D21 | Datapath scheduler due ordering/refusals/owned IDs | 1 | `datapath/sched.c` не имел отдельной строки |
| D22 | Journal ring/retention/dropped/added/format | 1 | `datapath/journal.c` не имел отдельной строки |
| S11 | Diagnostics records/snapshots/madvise | 1 | `core/diagnostics.c` не имел отдельной строки |
| P5 | Panel absolute response deadline и client IO resilience | 1 | P1–P4 не покрывали absolute deadline/IO |
| F11 | Router `clear-found`/`KEENETIC_POLICY`/log rotation/heal | 1 | F1–F10 не покрывали эти service-ветви |
| T7 | Telegram limits/memory budget/stats timeout/config validation | 1 | T1–T6 были слишком широкими |
| L6 | Install/bootstrap/uninstall lifecycle | 1 | L1–L5 не покрывали install/uninstall |
| Q8 | QUIC deny/recheck lifecycle | 1 | Q1–Q7 не покрывали qdeny/recheck |
| C16 | Detect/classifier CLI output/exit/JSON | 1 | C1–C15 не покрывали human/CLI-контракт |
| M8 | Production header-inline helpers inventory | 1 | 61 header-функция не была учтена |

Новый итог до нормализации: **108 контрактов / 144 балла**. Строгий счёт — **37/144 = 25,69 %**; carry-forward с `304ba893` — **89/144 = 61,81 %**; legacy-агрегат — 80/89 = 89,89 % (другой знаменатель). После нормализации 2026-11-08 итог другой — см. раздел 8.

### Что всё ещё не сведено

108 контрактов до нормализации — это coarse-слой. Детальные отчёты содержат:

- Panel: **26** подконтрактов A1–A26;
- Router: **54** подконтракта B1–B54;
- Telegram: **26** подконтрактов C1–C26;
- VPS: **4** `N/A (unported)`.

До нормализации эти подконтракты не были добавлены в scored-таблицу, потому что пересекаются с P/F/L/T-строками. Поэтому утверждение «108 контрактов полностью описывают все ветви» было **неверным**: полный function-level инвентарь есть, полная contract-level декомпозиция ещё не была сведена. Нормализация 2026-11-08 это исправила (раздел 8).

## 4. Проверка ссылок, ревизий и evidence

- Проверено **566** ссылок `file:line`; после исправления 3 ссылок с неверным путём (`r2k-core/control.rs` → `crates/r2k-core/src/control.rs`) разрешаются все **566**.
- **230** ссылок используют краткие имена (`main.rs`, `response.rs` и т.п.) и неоднозначны без контекста раздела; это ограничение читаемости, не отсутствие кода.
- Из **187** упомянутых `.sh`-скриптов отсутствует один: `test-router-flowoffload-selective-differential.sh`. Selective-схема удалена; примечания #20/#26/#28/#81–#96 устарели.
- Ревизии: `a378e23` и `8e2c981` присутствуют в локальном D2O git; **`a63d964` и `304ba893` отсутствуют**, `42c8111` (z2kOW) тоже отсутствует. Доказательства, закреплённые на них, в этом окружении не воспроизводятся.

## 5. Конкретные неучтённые ветви и побочные эффекты

- **TCP shape contexts 8–13:** C различает TLS-планы с TCP timestamps и без них; R2O использует только shapes 1–7. Это влияет на выбор плана и привязку клиента.
- **Runtime heartbeat/health:** `d2k_runtime_heartbeat`, `start_ticks`, `listener_ready`, `offline` не имеют Rust-аналога для datapath/controller; panel пишет другой формат `R2OH1`.
- **Diagnostics:** allocator/madvise и часть периодической RSS-сводки отсутствуют.
- **Panel:** absolute 5-секундный дедлайн ответа, устойчивость к IO-обрыву клиента, незакрытая кавычка в config; known-list уже исправлен.
- **Router:** `clear-found` оставляет `https-cache.json`/`measurements`; `KEENETIC_POLICY` не перенесён; логи Meta DNS не ротируются; `heal` может запустить остановленный Telegram; `engine-restart` при `MODE=off` делает лишний stop.
- **Telegram:** memory budget/лимит 64 соединений, таймаут чтения stats-сокета, `TG_PORT=1443`, `TG_DIAGNOSTIC_DIRECT_TCP`, валидация CF-доменов.
- **IPv6 raw fragments:** C использует `AF_PACKET` + ручной route/neighbor lookup (`d2k_f6_*`); R2O отправляет через `AF_INET6`/`IPV6_HDRINCL` и полагается на kernel. Поведение доставки не сравнивалось.
- **QUIC deny/recheck:** lifecycle не имеет paired C/Rust differential.
- **Install/uninstall:** bootstrap и uninstall fallback не проверены полностью.

## 6. Таймеры, состояния, ошибки и побочные эффекты

Ниже — выборочная, но конкретная проверка того, что аудит не потерял ключевые состояния. Полный перечень — в таблицах отчётов; здесь зафиксированы те, где доказательство неполное.

| Состояние/таймер/эффект | C-источник | R2O | Фактический статус |
|---|---|---|---|
| Session sweep 1 с, idle 120 с | `d2kd.c`, `session.c` | `main.rs`, `engine.rs` | scoped tests; полный процессный differential не заявлен |
| TCP silence 2 с/RTT, FIN retry | `session.c` | `engine.rs` | `test-tcp-silence-current-differential.sh`; FIN retry без полного differential |
| TCP hold 100 мс, revision change | `hold.c` | `hold.rs` | unit + EIO held TCP; HTTP hold не полностью |
| UDP hold 100 мс, follow window 5 мс | `udp_hold.c`, `udp_release.c` | `r2o_udp_hold.rs` | unit; все четыре исхода `udp_path` не paired |
| Capture TTL 5 с, overlap expiry | `capture.c` | `capture.rs` | unit + stats differential; process-level expiry открыт |
| Controller tick 3 с, save 60 с, live 2 с | `d2kc.c`, `sched.c` | `main.rs` | catalog/diagnostic tests; полный таймерный differential нет |
| Trial 10 мин, rest 2 мин, voice lease 120 с/renew 60 с | `sched.c` | `main.rs`, voice modules | helper-level; production restart/долгая RTC не проверены |
| Cooldowns 10/30/60 мин, dead address 30 мин, area ACK 5 с | `sched.c`, `link.c` | `main.rs`, `discovery.rs` | scheduler differentials; не все ветви |
| Panel header 5 с, action 60 с, response 5 с | `panel/server.c` | `server.rs` | header/action differentials; absolute response deadline — пробел |
| NFQUEUE EAGAIN/EINTR/ENOBUFS/lost/truncation | `nfq.c`, `nl.c` | `nfqueue.rs`, `netlink.rs` | EIO differential; ENOBUFS/malformed header injection — пробел |
| Telegram watchdog 15 с, 3/900 с | `d2k-tg-watchdog.sh` | `r2o-telegram-watchdog.sh` | source compare; live watchdog restart не проверен |
| Ошибки plan/D2KP/R2OP | `plan_parse.c` | `plan.rs` | контейнеры несовместимы; C-план отвергается |
| Ошибки panel IO/обрыв клиента | `server.c` | `server.rs` | R2O может завершить `serve`; differential нет |
| Ошибки router UCI/nft/iptables | `S99d2k` | `S99r2o`, `r2o-firewall.sh` | command fixtures; live kernel/rollback не проверены |
| Побочные эффекты: verdict/raw/ACK/journal | `d2kd.c`, `ctl*.c` | `main.rs`, `flow_journal.rs` | частично differential; полный набор счётчиков нет |
| Побочные эффекты: health/catalog/firewall files | `d2k*.c`, `panel` | `main.rs`, `S99r2o` | heartbeat/health gap; catalog/firewall fixture-level |

## 7. Паритет до нормализации

| Режим | Баллы | Процент |
|---|---:|---:|
| Строгий текущий (без 304) | 37/144 | **25,69 %** |
| Carry-forward (с 304ba893) | 89/144 | **61,81 %** |
| Legacy-агрегат | 80/89 | 89,89 % (не сопоставим) |

Строгий счёт валидации снизился с 28,03 % до 25,69 % не из-за регресса кода, а потому что валидация добавила 11 реально отсутствовавших контрактов и сохранила 0 баллов за непроверенные ветви.

## 8. Нормализация 2026-11-08

Детальные Panel A1–A26, Router B1–B54 и Telegram C1–C26 сведены в единую scored-матрицу. Coarse-строки `P*`, `F*`, `L*`, `T*` и `S7`/`S8` удалены; `R8` стал `G1`, Classifier `C*` — `CL*`, Telegram `C*` — `TG*`. Вне scored вынесены 6 строк: `B32`/`B45` (extension), `B54` (out-of-scope), `C2` (extension), `C25`/`C26` (дубли router-side).

| Режим | Баллы | Процент |
|---|---:|---:|
| Строгий текущий | **148/271** | **54,61 %** |
| Carry (только явно помеченные `304`) | **211/271** | **77,86 %** |
| Legacy-агрегат | 80/89 | 89,89 % (другой знаменатель) |

Рост строгого счёта с 25,69 % до 54,61 % — не новые доказательства: 84 детальных Router-контракта (59 strict) заменили 30 coarse-баллов `F*`/`L*`/`T*`/`P*` (18 strict), а 71 балл Panel/Telegram добавлен с нулём. Знаменатели 144 и 261 несопоставимы напрямую.

Статусы в нормализованной матрице: `verified` — 102 строки, `carry (304)` — 40, `partial` — 36, `missing` — 0, `extension` — 1. Дополнительно доказаны `M7a` (legacy `D2KP`), `M7b` (`tcp_ts_up`), `B9` (`clear-found` state), `B52` (Meta DNS log rotation), `B53` (`KEENETIC_POLICY`), `B42` (Telegram reapply), `B40` (uninstall fallback), `A26` (panel offline CLI), `A21` (Telegram stats absolute timeout), `A8` (panel response deadline), `A3` (panel config unquoted quote), `A25` (static asset missing/symlink 404), `A6` (32 KiB header boundary/431), `A9` (client disconnect recovery), `A10` (unknown route/method/version), `A19` (config write mode), `A15` (action exit 124 → timeout), `A13` (status snapshot structure), `A5` (D2O known config keys), `TG6` (MTProto splitter), `TG5` (obfuscated2/secret handshake), `TG3` (DC map persist/merge/validate), `TG4` (help.getConfig/dcOption/gzip), `TG21` (MTProto response observer), `TG10` (route DNS public-IP/fallback), `TG11` (Meta-edge TLS/SNI), `TG17` (official secret/DD), `TG16` (transparent policy ports/CIDR/self-dial), `TG13` (CF domain pool/cache), `TG7` (MTProto 2.0 encrypted decrypt), `TG15` (SO_ORIGINAL_DST decode), `TG19` (D2O stats schema/socket), `TG8` (resPQ probe fake DC), `TG14` (CF proxy DoH POST h1/h2), `TG9` (route plan/CF hostname/DC mapping), `B8` (`status --d2k` поля/коды), `B46` (Telegram watchdog health), `TG20` (stats socket timeout), `D20` (контроллерная эмиссия shape contexts 8–13), `D23` (plan table capacity/LRU), `D22` (journal ring/notes), `S12` (v22 ACK/D2KP codec), `S11` (diagnostics allocator/madvise/RSS), `S13` (live v22 datapath + real d2kc), `S14` (live v22 controller + real C ctlprobe), `S15` (legacy SUSPECT/EXCHANGE → Discovery) и `TG22` (connection/memory limits). Все 2584 C-функции в `docs/audit/function-index.md` ссылаются только на существующие ID нормализованной матрицы; проверка `check_contract_refs.py` даёт 0 отсутствующих ссылок.

## 9. Ограничения

- Валидация статическая: differential-тесты, QEMU, NFQUEUE/netns и физический роутер не перезапускались.
- `a63d964`/`304ba893` отсутствуют локально, поэтому соответствующие evidence не воспроизводимы без fetch.
- 660 функций имеют только module-level статус; это не индивидуальное доказательство.
- Нормализация не добавляет новых прогонов: она только переразбивает и дедуплицирует существующие доказательства.
