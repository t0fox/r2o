# Инвентарь поведенческих контрактов по оставшимся P

Дата: 2026-11-16. Это не перенос и не заявление паритета: 1982 C-функции
остаются справочным реестром, а P-строки сгруппированы в проверяемые
поведенческие контракты. Источник — канонические таблицы
`docs/audit/{core-net,core-state,datapath-core,datapath-plan,detect}.md`.

Строк P: **390**; контрактов: **27**; без контракта: **0**.

| Группа | P |
|---|---:|
| core-net | 185 |
| core-state | 187 |
| datapath-core | 6 |
| datapath-plan | 0 |
| detect | 12 |

## Контракты

| ID | Контракт | Наблюдаемое поведение | P | Текущее доказательство / следующий шаг |
|---|---|---|---:|---|
| `CN-QUIC-WIRE` | QUIC wire: long header, PN length, seal/open, packet ranges | Побайтовые операции над QUIC long-header/PN/AEAD/ranges. | 10 | quicwire: 10 P; pn_len — 14 значений C/Rust differential PASS; нужны vectors на ranges/seal/open. |
| `CN-QUIC-INITIAL` | QUIC Initial: snapshot, reseal, rename, split, assembly | Подготовка/перезапечатывание Initial, SNI/split, сборка датаграмм. | 14 | quichello/quicsnap/quicsnap_reseal/quic: 14 P; r2o-quic-hello и quic-* differential частичные. |
| `CN-QUIC-PROBE-SEND` | QUIC probe send: socket, prefix TTL, copies, fragments, refused | Открытие/маркировка сокета, приманка/хвост, TTL/copies/split/frag, ECONNREFUSED. | 21 | quicprobe send-функции: 21 P; r2o-quic-send-one PASS 10 кейсов, остаются longer/IPv6/real handshake. |
| `CN-QUIC-PROBE-RUN` | QUIC probe run: question ladder, budget, classify | Вопросы junk/frames/datagrams/bit/lowport/length, бюджет и итоговый verdict. | 12 | quicprobe run-функции: 12 P; нужны C/Rust differential полного вопроса и бюджета. |
| `CN-QUIC-ARM-STRATEGY` | QUIC arm strategy and plan text | Лестница TTL/clearance/split/udplen/frag/fallback и текст arm-плана. | 14 | quicarms + udpplan: 14 P; r2o-quic-plan-text частично, adaptive/порядок не сверены. |
| `CN-QUIC-CONNECTION` | QUIC connection/data stage | TLS-over-QUIC, transport params, ACK/frames, streams, RTT/close. | 31 | quicconn: 31 P; r2o_quic_http3/quinn; полный побайтовый differential не заявлен. |
| `CN-TLS-RECORD-IO` | TLS record I/O and helpers | Чтение/запись записей, EINTR/EAGAIN, nonce/AAD, dispose/free. | 14 | tls12/tls13 record-хелперы: 14 P; r2o-tls12-io PASS 13 кейсов, tls13 record layer — нет. |
| `CN-TLS13-HANDSHAKE` | TLS 1.3 handshake and keys | CH/SH, HKDF traffic keys, Finished, ECH, downgrade. | 7 | tls13/tls13core: 7 P; rustls; C/Rust побайтового handshake/ECH нет. |
| `CN-TLS-VERIFY` | TLS/HTTP verify and contact | Проверка TLS1.2/1.3/ECH, тела ответа, контакта по family. | 8 | verify.c TLS-часть: 8 P; verify-* differentials частичные. |
| `CN-QUIC-VERIFY` | QUIC/HTTP3 verify and replay | QUIC probe on/path/mark, replay, H3 headers/chunks, qb request/recv. | 10 | verify.c QUIC-часть + replay: 10 P; нужен e2e DoQ/HTTP3 differential. |
| `CN-HTTP-SEARCH` | HTTP search lifecycle and candidates | Задачи, кандидаты, judge, fallback, runner, diagnostics, persist. | 26 | httpsearch: 26 P; test-http-search-response PASS 13; diagnostic_end — event JSON differential PASS; переходы/таймеры/live — нет. |
| `CN-VOLUME` | Response volume probe | TLS/plain drain, rx volume, bounded connect, path probe. | 8 | volume: 8 P; budget volume differentials частичные, полный path — нет. |
| `CN-VOICE` | Voice/STUN discovery | STUN request, DNS/voice blob, prefix, local failure. | 10 | voice/voice_discovery/stun: 10 P; voice differentials частичные. |
| `CS-SCHED-TASK-LIFECYCLE` | Scheduler task/worker lifecycle | Слоты, worker permits, reset/done/fail/join, retire, queue wake, guards. | 31 | sched.c: worker/task/queue/guard; Rust R2oDiscoverySearches/Queue/Life; полная матрица T_* не доказана. |
| `CS-SCHED-SUSPECT-ADMISSION` | Scheduler suspect admission and refusal | on_suspect, cooldown, dead/refusal, shape/family, refused outcomes. | 32 | sched.c: admission/refusal; Rust queue/cooldown/family recovery; полный differential кодов/порядка. |
| `CS-SCHED-CANDIDATE-VERIFY` | Scheduler candidate verification | verify_confirm, partial_finish, ACK/APPLIED, own plan, exchange. | 21 | sched.c: verify/applied/exchange; production verify_confirm 30 cases, остальные ветви P. |
| `CS-SCHED-PLAN-GENERATION` | Scheduler plan generation | verdict_to_plans, own_first, area/resource path, plan identity, RX bootstrap. | 24 | sched.c: plans/area/resources/identity; signal_human — 9 кейсов C/Rust PASS; Rust candidates/compose; порядок и поля не сверены. |
| `CS-SCHED-VOLUME-VOICE` | Scheduler volume ladder and voice trials | volume bucket/ladder/room, rx pending, voice trial/observe/fail. | 18 | sched.c: volume/voice; volume_bucket — 28 кейсов C/Rust PASS; budget/voice differentials частичные, поля plan_boxes/rx queue иные. |
| `CS-SCHED-ECH-QUIC` | Scheduler ECH witness and QUIC initial/address control | ECH witness, quic own initial/address/multi. | 9 | sched.c: ECH/QUIC; Rust ech/quic initial; e2e DoQ и полный порядок не доказаны. |
| `CS-SCHED-DIAGNOSTICS` | Scheduler diagnostics/live output | progress/diagnostics/counts, live binding/phase, say/level/time/hex. | 12 | sched.c: diagnostics/helpers; live 12 states PASS, редкие counters/поля P. |
| `CS-CRYPTO-ECC` | ECC primitives P-256/X25519 | Полевая арифметика, point/scalar, public/keypair/ecdh. | 33 | p256/x25519: 33 P; ring/hpke/dalek; прямых C/Rust векторов нет. |
| `CS-CLI-TOOLS` | CLI tools d2kc/d2kask/d2kfetch/d2kvoice | Флаги, stdout/exit, snapshot wire, usage. | 2 | d2kc/d2kask/d2kfetch/d2kvoice: 2 P; d2kvoice main/usage PASS; snapshot_wire C-путь недостижим; diagnostic_limit/event/tick, http_search_portal и sched_say — C/Rust differential PASS; остальные CLI. |
| `CS-PROPS` | QUIC properties text | original/strategy measure and wire properties. | 5 | props: 5 P; quic props findings текстовый контракт не полный. |
| `DP-SESSION-LIFECYCLE` | Datapath session lifecycle | d2kd main/usage, session_new, UDP handle, session_packet. | 5 | session/d2kd: 5 P; session_packet/handle_udp live не сверены. |
| `DP-NFQ` | Datapath NFQUEUE error text | nfq say static helper. | 1 | nfq: 1 P; error text/ветви NFQUEUE. |
| `DT-BRIDGE` | Detect bridge scheduler | base/tcp/white/seeded/progress/stop bridge. | 9 | bridge: 9 P; bridge differential 8 cases, seeded/white ветви P. |
| `DT-RAW-HANDSHAKE` | Detect raw handshake/probe | flush pending, poison family, handshake_as. | 3 | raw: 3 P; raw probe live/ветви. |

## Правила

- Контракт описывает входы, выходы, ошибки, таймауты и побочные эффекты.
- Внутренние C-хелперы не являются обязательными единицами переноса.
- Для wire/NFQUEUE/TLV/сетевых форматов сохраняется побайтовая совместимость.
- Статус E/P в `docs/function-parity-audit.md` не меняется этим инвентарём.
- Карта «контракт → функция»: `p-contract-map.tsv`.

## Закрытые контракты

| ID | Контракт | Доказательство |
|---|---|---|
| `DT-CLI-OUTPUT` | Detect CLI JSON/human/usage/exit | 2026-11-16: `r2o-detect` добавлен в `package-release.sh` и release-артефакт; `r2o-manager` активирует его как необязательный компонент; `test-detect-release-artifact.sh` распаковывает архив и даёт `6 triggers / 19 exits / json=equal / human=equal` на packaged binary. `r2o-controller --classify` остаётся отдельным CLI-путём. |
| `CS-MEASUREMENT` | Measurement transport helpers | 2026-11-16: `connect_bounded` success/refused/badfd, `send_all` send-timeout/EINTR/10 ветвей, `d2k_arm_plan_measured` 28 кейсов, `nap_us` 20 мс/EINTR — все C/Rust differential PASS; production nap переведён на `libc::nanosleep` с C-семантикой. |
| `CS-CATALOG-TLV` | Catalog TLV plan encoding | 2026-11-16: `r2o-compose-tlv-differential.sh` — overlap/reorder/badsum/badsum_gap/checksum и `plan_tlv_stamp_ident` (id + stamped D2KP, guard'ы layout'а) совпали с C; оба ask-пути удостоверяют план по TLV. |
| `CS-LINK-IO` | Link/control I/O helpers | 2026-11-16: send_area_key 11, wait_readable 8, hex_decode 6, say 4+3 — все C/Rust differential PASS; `r2o_link_open` даёт те же тексты пустого/длинного/отсутствующего сокета. |
| `DP-TRACK` | Datapath flow table key hash | 2026-11-17: `test-datapath-tcp-capacity-differential.sh` PASS (capacity/refusal/reverse/duplicate/remove/expiry); `key_hash` осознанно заменён на `HashMap` RandomState — внутренний порядок коллизий не наблюдаем, HashDoS-устойчивость не ослаблена. |
| `CN-IP6FRAG` | IPv6 fragment probe helper | 2026-11-17: `test-datapath-ip6frag-sender-state-differential.sh` PASS (init/close/send-after-close, fd); production sender uses `Instant` for the same 1s cache and 200ms neighbor deadline. |
| `CS-VERDICT` | Classify verdict | 2026-11-17: C `d2k_classify` — обёртка `d2k_classify_cancelable(...,NULL)` без production-вызова в D2O; Rust `run` без отмены, дерево cancelable E* (`test-classifier-clear-confirm-differential.sh` + unit). Ограничение — отдельного differential обёртки нет. |

## Следующий шаг

`CS-LINK-IO`, `CS-MEASUREMENT` и `CS-CATALOG-TLV` закрыты;
`send_area_key` (11), `wait_readable` (8), `hex_decode` (6) и
`say` (4+3) сверены C/Rust differential. Следующий кандидат —
`CS-CLI-TOOLS` (`d2kask`/`d2kfetch`), отдельный CLI-контракт.

## Ограничение TTL-контракта

`quic-server-ttl-in` закрывает только приём TTL/hop limit
(`qp_recv_ttl`/`recv_with_ttl`) и не заявляет полный `d2k_quic_run`
qprops pipeline. Полная проводка `server_ttl_in` в verdict/props —
отдельный контракт `CN-QUIC-VERIFY`/`CS-PROPS`, а не закрытая часть
TTL receive-контракта.
