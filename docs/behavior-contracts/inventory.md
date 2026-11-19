# Инвентарь поведенческих контрактов по оставшимся P

Дата: 2026-11-18. Это не перенос и не заявление паритета: 1982 C-функции
остаются справочным реестром, а P-строки сгруппированы в проверяемые
поведенческие контракты. Источник — канонические таблицы
`docs/audit/{core-net,core-state,datapath-core,datapath-plan,detect}.md`.

Строк P: **146**; контрактов: **14**; без контракта: **0**.

| Группа | P |
|---|---:|
| core-net | 82 |
| core-state | 64 |
| datapath-core | 0 |
| datapath-plan | 0 |
| detect | 0 |

## Контракты

| ID | Контракт | Наблюдаемое поведение | P | Текущее доказательство / следующий шаг |
|---|---|---|---:|---|
| `CN-QUIC-WIRE` | QUIC wire: long header, PN length, seal/open, packet ranges | Побайтовые операции над QUIC long-header/PN/AEAD/ranges. | 0 | quicwire: 0 P; pn_len — 14 значений, long header — 27, hdr_parse — 120, ranges — 24, seal/open — 96 кейсов C/Rust PASS. |
| `CN-QUIC-INITIAL` | QUIC Initial: snapshot, reseal, rename, split, assembly | Подготовка/перезапечатывание Initial, SNI/split, сборка датаграмм. | 0 | quichello/quicsnap/quicsnap_reseal/quic: 0 P; prepare_target/rename — 8, hello_ask/split — 16, hello_incomplete — 10, profile/longer — 4, qsnap_recid+form — 15 строк, assembly — 17 шагов C/Rust PASS. |
| `CN-QUIC-PROBE-SEND` | QUIC probe send: socket, prefix TTL, copies, fragments, refused | Открытие/маркировка сокета, приманка/хвост, TTL/copies/split/frag, ECONNREFUSED. | 2 | quicprobe send-функции: 20 P; qp_now_ms — 31-line C/Rust PASS и бюджет trial; r2o-quic-send-one PASS 10 кейсов, остаются longer/IPv6/real handshake. |
| `CN-QUIC-PROBE-RUN` | QUIC probe run: question ladder, budget, classify | Вопросы junk/frames/datagrams/bit/lowport/length, бюджет и итоговый verdict. | 7 | quicprobe run-функции: 6 P; reason_set/append, budget_left, qp_outcome, qp_progress, budget_ms — 30 строк C/Rust PASS и проводка base-result/таймаута/прогресса/бюджета; нужен differential полного вопроса. |
| `CN-QUIC-ARM-STRATEGY` | QUIC arm strategy and plan text | Лестница TTL/clearance/split/udplen/frag/fallback и текст arm-плана. | 0 | quicarms + udpplan: 0 P; ask_q — 8, ask/ask_frag — 69, original_arms — 56, strategy_ask — 9, strategy_arms — 58, question_plan — 23 строки C/Rust PASS; append_fmt — String+checked_text (8191), delay_plan — мёртв в C. |
| `CN-QUIC-CONNECTION` | QUIC connection/data stage | TLS-over-QUIC, transport params, ACK/frames, streams, RTT/close. | 28 | quicconn: 30 P; r2o_quic_http3/quinn; app_progress — 6 потоков C/Rust PASS; полный побайтовый differential не заявлен. |
| `CN-TLS-RECORD-IO` | TLS record I/O and helpers | Чтение/запись записей, EINTR/EAGAIN, nonce/AAD, dispose/free. | 0 | tls12/tls13 record-хелперы: r2o-tls12-io PASS 13 кейсов; sealed TLS1.2 — exact 34 байта C/Rust PASS; tls13 put16/get16 — 65536 значений C/Rust PASS; TLS1.3 record layer — нет. |
| `CN-TLS13-HANDSHAKE` | TLS 1.3 handshake and keys | CH/SH, HKDF traffic keys, Finished, ECH, downgrade. | 0 | tls13/tls13core: 6 P; d2k_t13_random — 10 строк C/Rust PASS и общий fill_exact; rustls; C/Rust побайтового handshake/ECH нет. |
| `CN-TLS-VERIFY` | TLS/HTTP verify and contact | Проверка TLS1.2/1.3/ECH, тела ответа, контакта по family. | 5 | verify.c TLS-часть: 5 P; request_complete_page — 13, props_contact — 11, body_byte/HTTP framing — 16/16 кейсов C/Rust PASS (verify-режим парсера); остальные verify-* частичные. |
| `CN-QUIC-VERIFY` | QUIC/HTTP3 verify and replay | QUIC probe on/path/mark, replay, H3 headers/chunks, qb request/recv. | 5 | verify.c QUIC-часть + replay: 10 P; нужен e2e DoQ/HTTP3 differential. |
| `CN-HTTP-SEARCH` | HTTP search lifecycle and candidates | Задачи, кандидаты, judge, fallback, runner, diagnostics, persist. | 21 | httpsearch: 21 P; plan_poisons+measured_poison — 215 строк, build_cands/build_fallback/вопросы — 50 строк C/Rust PASS и production candidate_ladder с rec.key после отзыва; test-http-search-response PASS 13; diagnostic_end — event JSON PASS; judge_trial — 13 переходов PASS; переходы/таймеры/live — нет. |
| `CN-VOLUME` | Response volume probe | TLS/plain drain, rx volume, bounded connect, path probe. | 6 | volume: 6 P; RX differential 13 кейсов PASS, rx_short retry и rx_probe handshake-гейт как C; полный path — нет. |
| `CN-VOICE` | Voice/STUN discovery | STUN request, DNS/voice blob, prefix, local failure. | 8 | voice/voice_discovery/stun: 8 P; d2k_stun_request/t13_random — 10 строк C/Rust PASS и production STUN-префикс; voice_resolve-порт теперь как C strtoul; voice differentials частичные. |
| `CS-SCHED-TASK-LIFECYCLE` | Scheduler task/worker lifecycle | Слоты, worker permits, reset/done/fail/join, retire, queue wake, guards. | 2 | sched.c: worker/task/queue/guard; Rust R2oDiscoverySearches/Queue/Life; box_injects_rst/rst_guard_wanted/plan_arm_rst_guard — 32 кейса C/Rust PASS и проводка в candidate+sync; sched_quic_progress — 7 кейсов и проводка в QUIC worker; ask_settle — 9 кейсов и проводка в base/full; worker_type — 16 кейсов C/Rust PASS и живой worker_oldest_type из gate; worker_run — live last_measurement_age_s=2; task_budget — 7 кейсов C/Rust PASS и TX-лестница; join_worker — Drop/reap join до отчёта; prop/contact/ver close — RAII Drop до отчёта; note_worker_start_failure — счётчик/цель/live-reason; box_ensure — 4 строки C/Rust PASS; quic_deny install/recheck/tick — 5 unit-тестов; worker args/wake/active/queued — RAII+queue/live-тесты; stall_budgets_push — dedup и базовое поле 25 как C; полная матрица T_* не доказана. |
| `CS-SCHED-SUSPECT-ADMISSION` | Scheduler suspect admission and refusal | on_suspect, cooldown, dead/refusal, shape/family, refused outcomes. | 24 | sched.c: admission/refusal; Rust queue/cooldown/family recovery; refuse_is_damage — 256 кодов C/Rust PASS и ветка DAMAGED в REFUSED; clear_binding_matches — 9216 кейсов, binding_wire_shape — 126 кейсов, measured trigger profile, client_tcp_profile — 4112 кейсов и drop_client_opts — 6 кейсов C/Rust PASS; cooldown_victim — 4 состояния кольца 128 C/Rust PASS; clean-handshake differential — коды/IP/family/name/TTL PASS; полный differential кодов/порядка. |
| `CS-SCHED-CANDIDATE-VERIFY` | Scheduler candidate verification | verify_confirm, partial_finish, ACK/APPLIED, own plan, exchange. | 2 | sched.c: verify/applied/exchange; production verify_confirm 30 cases, props_text — 243 кейса C/Rust PASS; own_first_plans QUIC — 3 случая C/Rust PASS; own_rank_before — 8 случаев PASS; binding_for — 4 случая PASS и on_shape-перемер; bound_plan_here QUIC — 2 случая PASS; candidate_trial_matches — command/trial mapping; applied_of_candidate — 6 случаев PASS и ранние REFUSED; d2k_sched_free — Drop + shutdown drain; install_next own_first==2 — stop без refill, family_fast — cooldown вместо полной классификации, cached_measure_valid — gate fallback, bad_plan_skip — continue fallback (matched=13), ladder_unmeasurable — owned_fallback gate 4 случая PASS; install_next QUIC split-unfit — 5 случаев PASS, mark_failure — 1 случай (matched=14); install_next закрыт архитектурно (trial_retire/task-state); candidate_retire — 3 случая DEL_NAME_PROBE PASS; question_retire/trial_retire name+addr — 6 случаев PASS; partial_finish — budget-volume PASS и 10-мин cooldown; verify_confirm volume-ladder gate — 3 случая PASS и budget CUT PASS; task_done — lifecycle differential PASS 9; task_fail — lifecycle differential PASS 9; architecture batch: task_reset/sched_quic_yield/launch_task/verify_default/mark_default/classify_unconfigured/voice_default/quic_recv_chunk/qb_request/qb_recv/h3_read_headers; verify_rx_default/verify_rx_gzip_default — architecture; quic_app_silent/qp_ask_vn — architecture; quic_ask/ttl/copies/split/longer/frames — candidate-plan architecture; send-one/frag1-4/arm-ttl — 10 cases PASS; CN-QUIC wrapper/control/core architecture; bind_default — 4 случая PASS; rx_saved_bootstrap — 9 кейсов PASS и late-RX путь; остальные ветви P. |
| `CS-SCHED-PLAN-GENERATION` | Scheduler plan generation | verdict_to_plans, own_first, area/resource path, plan identity, RX bootstrap. | 15 | sched.c: plans/area/resources/identity; signal_human, task_phase, live_binding, live_autopick — full live.json 12 состояний PASS; verdict_name — 14 кодов C/Rust PASS и NO_QUIC/LOCAL_ADDRESS в QUIC-логах; group_exception_status — live-тест active/pending/retrying/rejected/removing; Rust candidates/compose; порядок и поля не сверены. |
| `CS-SCHED-VOLUME-VOICE` | Scheduler volume ladder and voice trials | volume bucket/ladder/room, rx pending, voice trial/observe/fail. | 14 | sched.c: volume/voice; volume_bucket — 28 кейсов, voice_ip_fmt/text/text2 — 9 адресов, voice_trial_same_context — 13 кейсов C/Rust PASS; budget/voice differentials частичные, поля plan_boxes/rx queue иные. |
| `CS-SCHED-ECH-QUIC` | Scheduler ECH witness and QUIC initial/address control | ECH witness, quic own initial/address/multi. | 7 | sched.c: ECH/QUIC; Rust ech/quic initial; quic_text_is_split — 11 текстов C/Rust PASS; local-address policy — differential PASS; ECH RR cache — 12 строк C/Rust PASS (TTL/ring); e2e DoQ и полный порядок не доказаны. |
| `CS-SCHED-DIAGNOSTICS` | Scheduler diagnostics/live output | progress/diagnostics/counts, live binding/phase, say/level/time/hex. | 0 | sched.c: diagnostics/helpers; live 12 states PASS, level_name — 10 значений, is_hex_digit — 256 байт, progress_note — 11 кейсов C/Rust PASS; редкие counters/поля P. |
| `CS-CRYPTO-ECC` | ECC primitives P-256/X25519 | Полевая арифметика, point/scalar, public/keypair/ecdh. | 0 | 2026-11-18: C/Rust vector differential PASS 72 (X25519) + 42 (P-256) строки; production TLS — rustls/ring. |
| `CS-CLI-TOOLS` | CLI tools d2kc/d2kask/d2kfetch/d2kvoice | Флаги, stdout/exit, snapshot wire, usage. | 0 | d2kc/d2kask/d2kfetch/d2kvoice: pval_str — 42-строчный C/Rust PASS; step/ack/seen — тексты сверены, production CLI не переведён; d2kvoice main/usage PASS; snapshot_wire C-путь недостижим; diagnostic_limit/event/tick, http_search_portal и sched_say — PASS; остальные CLI. |
| `CS-PROPS` | QUIC properties text | original/strategy measure and wire properties. | 0 | props: 5 P; quic props findings текстовый контракт не полный. |
| `DP-SESSION-LIFECYCLE` | Datapath session lifecycle | d2kd main/usage, session_new, UDP handle, session_packet. | 0 | session/d2kd: 4 P; usage — d2kd help-блок C/Rust PASS; session_packet/handle_udp live не сверены. |
| `DP-NFQ` | Datapath NFQUEUE error text | nfq say static helper. | 0 | nfq: 1 P; error text/ветви NFQUEUE. |
| `DT-BRIDGE` | Detect bridge scheduler | base/tcp/white/seeded/progress/stop bridge. | 0 | bridge: 8 P; bridge differential 8 cases, progress_seen — 6 кейсов C/Rust PASS; seeded/white ветви P. |
| `DT-RAW-HANDSHAKE` | Detect raw handshake/probe | flush pending, poison family, handshake_as. | 0 | raw: 3 P; raw probe live/ветви. |

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
| `CS-CLI-TOOLS` | CLI tools d2kc/d2kask/d2kfetch/d2kvoice | 2026-11-18: `r2o-ask-cli-differential.sh` PASS 28 сценариев `d2kask main` (no-trigger, полный отказ датапата, save-файлы, CLI/hex/сокет-ошибки); `r2o-serve-cli-differential.sh` PASS 9 сценариев `d2kc main` (version/usage/битый и отсутствующий каталог/приветствие/timeout/SIGTERM). Production-отчёт ask переведён на формат C. |
| `DP-NFQ` | Datapath NFQUEUE error text | 2026-11-18: C `say` — внутренний `vsnprintf` в буфер; Rust возвращает `io::Error`/`String` и логирует причину у вызывающего. Ветви вердиктов/ENOBUFS/timestamp/ICMP покрыты профильными C/Rust differential'ами; отдельного поведенческого контракта у буфера нет. |
| `DT-RAW-HANDSHAKE` | Detect raw handshake/probe non-Linux stubs | 2026-11-18: три не-Linux заглушки (`flush_pending`, `poison_family`, `handshake_as`) закрыты как E*: R2O выпускается только для Linux/OpenWrt, raw-слой вне Linux не компилируется, а Linux-путь покрыт production differential 5 cases. |
| `CN-TLS-RECORD-IO` | TLS record I/O and helpers | 2026-11-18: record/handshake-слой заменён rustls; dispose/free — RAII, `say` — внутренний форматтер. Байты ClientHello TLS1.2 сверены `test-tls12-ch12-differential.sh`, sealed-запись — `test-tls12-record-differential.sh` (34 байта + sequence), поля ServerHello — `d2o_verify_differential`, ключи/IV — `hkdf-*`. **Ограничение:** побайтового differential TLS1.3 record-слоя нет. |
| `CN-TLS13-HANDSHAKE` | TLS 1.3 handshake and keys | 2026-11-18: TLS1.3-стек заменён rustls; ClientHello/ECH и поля ServerHello сверены `d2o_verify_differential`/`r2o-ech-*`, app-data — живыми TLS-проверками. **Ограничение:** побайтового differential handshake/record-слоя нет. |
| `CS-CRYPTO-ECC` | ECC primitives P-256/X25519 | 2026-11-18: C/Rust vector differential — `test-x25519-differential.sh` PASS 72 строки, `test-p256-differential.sh` PASS 42 строки (production C против x25519-dalek/p256, все скаляры и пары). TLS/ECH используют rustls/ring с теми же RFC; ClientHello/рукопожатия покрыты отдельными differential'ами. **Ограничение:** прямого scalar-API у ring нет; production проверяется завершёнными TLS-сессиями. |
| `CS-PROPS` | QUIC properties text | 2026-11-18: C-хуки замера заменены раздельными кандидатами и trial-runner; path/SNI/port/wait/mark — явные аргументы. Кандидаты/вопросы сверены `r2o-quic-*` differential'ами. **Ограничение:** отдельного hook-символа нет. |
| `DT-BRIDGE` | Detect bridge scheduler | 2026-11-18: C-крючки заменены DiscoveryWorker/run_discovery; поля trigger/control/white/seed/mark/repeats/gap/wait/stop и base-ответ выражены задачей. Ветви сверены progress-seen (6), bridge (8) и classify/queue-тестами. **Ограничение:** отдельного hook-символа нет. |
| `CS-SCHED-DIAGNOSTICS` | Scheduler diagnostics/live output | 2026-11-18: C-инъекция say/observer заменена общим logger/Recorder; счётчики диагностики сверены 7 полей, live/status — r2o-live-*, время — Instant/SystemTime. **Ограничение:** дословный формат всех лог-строк не является сетевым контрактом. |
| `DP-SESSION-LIFECYCLE` | Datapath session lifecycle | 2026-11-18: TCP-путь — 36-кейсовый session-packet differential, UDP — path/prepost/release differentials, probe-флаги — controller-probe differential. Конструктор — типизированные таблицы/RAII, бюджет 25, журнал. **Ограничение:** полной матрицы всех ветвей и live-NFQUEUE main-loop нет. |

## Следующий шаг

Закрыты `CS-LINK-IO`, `CS-MEASUREMENT`, `CS-CATALOG-TLV`, `DP-TRACK`,`CN-IP6FRAG`, `CS-VERDICT`, `CS-CLI-TOOLS` и `DP-NFQ`. Следующие приоритеты —
TLS record/handshake, QUIC connection/verify, volume и voice; тяжёлые
live-контракты требуют стенда с датапатом и реальным сетевым путём.

## Ограничение TTL-контракта

`quic-server-ttl-in` закрывает только приём TTL/hop limit
(`qp_recv_ttl`/`recv_with_ttl`) и не заявляет полный `d2k_quic_run`
qprops pipeline. Полная проводка `server_ttl_in` в verdict/props —
отдельный контракт `CN-QUIC-VERIFY`/`CS-PROPS`, а не закрытая часть
TTL receive-контракта.
