# Глубокий аудит core-net: udpruntime/udpplan, TLS 1.2/1.3, QUIC-соединение и N-ряды

## 1. Baseline, метод, ограничения

- D2O-оракул: `a378e230947ebfd011439e1cac0f1e994d883aae`, worktree `E:/d2o-a378w` (HEAD сверен с `/mnt/e/d2o/.git/worktrees/d2o-a378w/HEAD`).
- R2O: HEAD `5abc2a4f65fb960b649c5289abcc6b4b642bf868` на момент проверки исходников; к финальной проверке — `f51ecee59ef65f288304803b0986e3e1ba04a303`. В ходе прохода HEAD менялся (`29163068` → `413d14b` → `d63f446` → `8b107558` → `5abc2a4` → `f51ecee`), поэтому цитаты привязаны не к номеру коммита, а к SHA-256 файлов (все перечисленные ниже хеши на финальной проверке совпали):
  - `r2o-controller/src/quic_replay.rs` — `119dd8254aae73bc…`
  - `r2o-controller/src/r2o_quic_http3.rs` — `246c5fcd48617bef…`
  - `r2o-controller/src/fetch.rs` — `639afb5de30137be…`
  - `r2o-controller/src/r2o_tls.rs` — `17a4781c084c5108…`
  - `r2o-controller/src/main.rs` — `44029e69d4b7c321…`
  - `r2o-controller/src/voice_measure.rs` — `2ad33ad6258315a2…`
  - `r2o-controller/src/voice_discovery.rs` — `5ed6936be5ec36b2…`
  - `r2o-controller/src/r2o_quic_deny.rs` — `602915d95358f827…`
  - `r2k-core/src/quic.rs` — `5ed72ba7f8106bdc…`
  - `r2k-core/src/wire.rs` — `bf46ca65971fdbdc…`
  - `r2o-datapath/src/raw.rs` — `019dba3f865669ac…`
- Срез: `r2o-tooling/audit/slice-core-net.csv`, 548 функций. Для каждой строки ниже прочитано всё тело C по `line..end_line`, найден Rust-аналог по символам/вызовам, проверены ветви, ошибки, таймауты и побочные эффекты.
- `docs/audit/core-net.md` в ходе прохода обновлялся параллельно; цитируемые строки сверены с текущей версией, сам файл не изменялся.
- **Тесты, сборка и дифференциалы в этом проходе не запускались.** `E` означает «есть целевой тест/дифференциал/фикстура», а не «тест только что прошёл»; в таких строках стоит «тест есть, не перезапускался».
- Критерий статуса: `P` — Rust-реализация поведения существует (в том числе в другом крейте или через зависимость), но не все ветви/форматы/ошибки доказаны; `N` — реализации именно этого поведения не найдено. `E` без целевого теста не ставится.
- Замечание о нумерации: CSV для `d2k_httpsearch_test_add_failures`/`add_records` сдвинут на 2 строки, для `d2k_quic_props_findings` — на 1; в таблице указаны и CSV-диапазон, и фактический.

## 2. `core/udpruntime.c` (8 функций)

**Прочитано построчно: 8/8 функций, 190 строк C (1–190).**

| C-функция | C-строки | текущий | проверенный | Rust-аналог (file:line/символ) | доказательство / конкретный пробел |
|---|---|---|---|---|---|
| `udp_next_fragment_id` | 22-30 | P | P | `r2k-core/src/wire.rs:334-337` (`getrandom` в `build_udp_fragments_with_capacity`) | C: процессный `pthread_mutex`-счётчик, одноразовый random seed, `++id`, пропуск нуля при 16-битном переполнении. R2O: новый случайный `id4`/`id6` на каждую сборку, монотонности и защиты от коллизий между посылками нет. Дифференциала на последовательность IP ID нет. |
| `d2k_udp_batch_free` | 32 | P | P | RAII `Vec`/`Drop` (`r2k-core/src/plan/apply.rs`, `Actions`/`Emission`) | Отдельной функции нет; освобождение автоматическое. Функционально эквивалентно, API не совпадает. |
| `d2k_udp_plan_build` | 33-93 | P | P | `r2k-core/src/plan/apply.rs` (apply), `r2o-datapath/src/engine.rs:1753`, `r2k-core/src/wire.rs:299` | В R2O нет контроллерной сборки «текст → TLV → батч байтов»: датапат применяет план к проходящему пакету и строит emissions/фрагменты. Отказы C (IPID_ZERO при любой emission, 53; >1 payload, 50; ipfrag с prefix/seq_shift/poison/wire_profile, 56-57; лимиты батча, 70) закрыты частично: `build_udp_packet` отвергает любой poison, `build_udp_fragments_with_capacity` — формы вне 1..4. Побайтового differential батча нет. |
| `udp_raw_init` | 101-106 | N | P | `r2o-datapath/src/raw.rs:48 RawSocket::open` + `OwnedFd` (`:35-44`) | C инициализирует `udp_raw_sink` и `d2k_ip6frag_sender` (AF_PACKET/netlink). R2O создаёт `RawSocket` с `IP_HDRINCL`/`IPV6_HDRINCL`; IPv6-путь иной (raw IPv6, не AF_PACKET+neigh). Контроллерного raw-sink нет, но поведение отправки в датапате есть. |
| `udp_raw_close` | 107-112 | N | P | `OwnedFd`/`Drop` (`raw.rs:35-44`) | Закрытие fd и ip6-sender заменено RAII. Отдельной функции нет. |
| `udp_raw_prepare` | 113-130 | N | P | `raw.rs:48-93 RawSocket::open`, `:155-167 send_packet_inner` | `IP_HDRINCL` — `raw.rs:75` (IPv4), `IPV6_HDRINCL` — `raw.rs:77`, `SO_MARK` — `:80`. **`IP_NODEFRAG` во всём R2O отсутствует (0 совпадений по `crates/`)**; C ставит его и отказывается работать без него (121-125). R2O требует ненулевой mark (`raw.rs:55-59`), C допускает mark=0. Проверка формы фрагментов есть (`outgoing_packet`), но запрета kernel-рефрагментации нет. |
| `udp_raw_send` | 131-139 | N | P | `raw.rs:147 send_packet` → `send_packet_inner:155-223` | R2O шлёт полный IPv4/IPv6-пакет/фрагмент через `sendto(MSG_DONTWAIT)`, EINTR-цикл, понижение MTU на EMSGSIZE. C: блокирующий `sendto`, IPv4-адрес берётся из `p+16`, IPv6 — через `d2k_ip6frag_send`. R2O отвергает нулевой IPv4 ID (`raw.rs:162-167`), C получает ненулевой ID от `udp_next_fragment_id`. Дифференциала raw-send нет. |
| `d2k_udp_plan_send` | 147-190 | N | P | датапат: `engine.rs:1753` (фрагменты), `main.rs:3604` (`delay_us`), `wire.rs:109/132` (TTL в заголовке), `raw.rs:147` (send); контроллер ставит addr-probe (`main.rs:20340-20353`, `quic_replay.rs:647`); voice — прямые копии (`voice_measure.rs:685-690`) | C: `getsockname/getpeername`, чтение TTL, `d2k_udp_plan_build`, предварительная подготовка всех фрагментов, паузы, `setsockopt(IP_TTL)` на каждую неfragment-посылку и восстановление TTL, `ECONNREFUSED → -2`. R2O: QUIC-контроллер шлёт триггерную датаграмму, датапат применяет план (fake/фрагменты/TTL/задержку) к потоку; voice-плечо шлёт copies+STUN напрямую, что совпадает с телом voice-плана. Нет контроллерного API `fd+text`, нет socket-TTL get/set/restore (TTL уже в raw-заголовке), нет маппинга `ECONNREFUSED → -2`, предподготовка фрагментов не совпадает. Полного differential runtime нет. |

Итог по файлу: в `core-net.md` было `P`×3 + `N`×5; проверено `P`×8. Причина — датапат реализует проводное поведение raw-отправки и применения плана, хотя одноимённого контроллерного API нет.

Ключевые ответы по raw UDP: `IP_HDRINCL` — `r2o-datapath/src/raw.rs:75`, `IPV6_HDRINCL` — `:77`, `SO_MARK` — `:80`; **`IP_NODEFRAG` в R2O не используется нигде**; TTL пишется в IP-заголовок (`r2k-core/src/wire.rs:109/132`), а C-специфичные `getsockopt(IP_TTL)`/`setsockopt`/восстановление TTL и `ECONNREFUSED → -2` в `d2k_udp_plan_send` (152-155, 179-186) аналога не имеют.

## 3. `core/udpplan.c` (12 функций)

**Прочитано построчно: 12/12 функций, 266 строк C (1–266).**

| C-функция | C-строки | текущий | проверенный | Rust-аналог (file:line/символ) | доказательство / конкретный пробел |
|---|---|---|---|---|---|
| `append_fmt` | 10-20 | P | P | `r2o-controller/src/plan_text.rs:67 compile_text`, `String`/`format!` | C возвращает -1 при переполнении и оставляет частичный буфер; Rust-строки не переполняются, ошибка возникает позже на разборе. Отдельной функции нет. |
| `emit_header_proto` | 28-34 | P | P | `compose_d2o.rs:36 header` (только TCP/TLS), `main.rs:20328` (QUIC), `voice_discovery.rs:16` (voice) | C: `d2k-plan 1 1\nid <32 нуля>\nproto <proto>\n`. R2O: TCP/TLS — точный `d2k-plan 1 1` (`compose_d2o.rs:37`); QUIC — `r2o-plan 1 10\nid <random>\nproto udp quic`; voice — `r2o-plan 1 1\nid <stable>`. Общего эмиттера нет; префикс, minexec и id отличаются. |
| `append_hex` | 36-42 | E | E | `http_search.rs:841 append_hex` | Точный lowercase-hex; используется в `candidate_text`; целевые тесты `tests/http_search.rs:227-266` (точные тексты split/disorder/fake). Тест есть, не перезапускался. |
| `quic_arm_found` | 50-54 | P | P | `quic_replay.rs:193 R2oQuicCandidateKind` | Перечисление видов есть, отдельного предиката нет; валидация размазана по конструкторам кандидатов и `Plan::parse`. |
| `quic_split_plan_text` | 59-64 | P | P | `quic_replay.rs:475-479` (`directives: "quicsplit 1\n"`), `main.rs:20328` | C: `d2k-plan 1 10`, нулевой id, `proto udp quic`, `quicsplit 1`, `order forward`. R2O: `r2o-plan 1 10`, случайный/вычисленный id, без строки `order forward` (по умолчанию forward). Побайтового differential нет; тест `discovery.rs:2378` фиксирует только `r2o`-форму. |
| `quic_plan_text` | 69-171 | P | P | `quic_replay.rs:586 r2o_quic_blob_candidate`, `:449 r2o_quic_discovery_candidates`, `main.rs:20328` | C: minexec 1/7/9/10 в зависимости от плана; R2O всегда `1 10`. C для benign-плана печатает `poison 1` и `fake … poison=1`; R2O benign печатает без poison и `poison=0` (`quic_replay.rs:614-615`) — провод тот же, TLV/текст разные. Ветка `pace` у C достижима только при `!arm->original` (166-168), а `d2k_quic_arm_plan` требует `original` (175), т.е. в этих путях мертва. C/Rust differential текста QUIC-плана отсутствует. |
| `d2k_quic_arm_plan` | 173-186 | P | P | `quic_replay.rs:449/586`, проверка `Plan` — `main.rs:20334 validate_runtime_plan` | C валидирует сам arm (SPLIT без original/frag/ttl, FRAG без original/frag_kind, UDPLEN с точными полями, 176-181). R2O валидирует уже собранный Plan, а не arm; негативного differential на недопустимые arm нет. |
| `d2k_quic_compose_plan` | 188-203 | P | P | `quic_replay.rs:449`, `:506 r2o_quic_original_fallback_candidates`; цикл `main.rs:21005-21123` (break на первом Pass) | C: `junk_ahead` → 16 нулевых байт, repeats=1 (199-202); в R2O это семантически покрыто кандидатом `Clearance` (`quic_replay.rs:466-473`), но текст отличается (poison). C отвергает arm `FLAKY` (194); в R2O такого кандидата нет. Условность «length только после двух нет» реализована порядком списка и break, а не конструктором. |
| `d2k_quic_delay_plan` | 205-217 | P | P | `plan_text.rs:444` (разбор `delay`), `r2k-core/src/plan.rs:47/286 REC_DELAY`, датапат `main.rs:3604`; фикстура `main.rs:26066` | C печатает `d2k-plan 1 6 … delay 15000`; `D2K_QUIC_DELAY_US = D2K_PACE_SETTLE_US = 15000` (`d2k_quicprobe.h:811`, `d2k_compose.h:242`), тест C `test_quic_arms.c:373` проверяет `delay 15000`. В R2O **нет продюсера** delay-плана: есть только разбор/применение и тестовая фикстура `r2o-plan 1 11 … delay 15000`. **Текущее доказательство `r2o_quic_deny.rs:203 r2o_delay` — ложное**: это backoff deny-кэша (10/30/60 мин), не эмиттер плана. Описание «delay 500000» в `core-net.md` не соответствует закреплённому C. |
| `d2k_voice_arm_plan` | 219-239 | E | E | `voice_measure.rs:269 r2o_measured_voice_arm_plan_text` | C: payload/poison/fake/repeats/gap_us/order/pace, copies 1..32, dlen>0 (явного предела dlen нет, только cap буфера). Rust: те же строки, copies 1..32, payload ≤ `R2O_VOICE_ARM_MAX=1600` (`voice_measure.rs:11`) — более строгий предел. Unit `measured_voice_arm_plan_preserves_payload_copy_count_and_voice_shape` (`voice_measure.rs:1007`); C/Rust differential `test-controller-udpplan-differential.sh` (копии 1/6/10). Тесты есть, не перезапускались. |
| `d2k_voice_plan` | 241-243 | E | E | `voice_measure.rs:269` (copies=10), `voice_discovery.rs:8` (copies=1) | C — обёртка `d2k_voice_arm_plan(..., D2K_VOICE_DECOY_REPEATS=10)` (`d2k_quicprobe.h:815`). В R2O нет отдельной обёртки, но differential `tests/d2o_udpplan_differential.c:15` вызывает C для copies=10 и сравнивает с Rust-текстом (шапка/id нормализуются), т.е. контракт 10 копий покрыт. **Текущее доказательство «main.rs:17239 / тесты Discovery» неверно** — там copies=1; правильное — `test-controller-udpplan-differential.sh`. Тест есть, не перезапускался. |
| `d2k_quic_question_plan` | 247-266 | P | P | `quic_replay.rs:449/506/586`, композиция `main.rs:20328` | C: вопрос → текст, включая базовый план без параметров `d2k-plan 1 1 … order forward` (258), `control`/`benign` и условный udplen. R2O: набор кандидатов и директив, отдельной функции «вопрос → текст» нет; базовый план — это сам baseline-зонд, а не план. P. |

Итог по файлу: было `E`×3 + `P`×9; проверено `E`×3 + `P`×9. Изменений статусов нет, но у `d2k_quic_delay_plan` и `d2k_voice_plan` неверные доказательства.

Ключевой ответ по тексту планов: C печатает `d2k-plan` с minexec 1 (обычный), 6 (delay), 7 (ipfrag), 9 (udplen), 10 (quicsplit) и нулевым id; R2O в рабочем QUIC-пути всегда печатает `r2o-plan 1 10` со случайным/вычисленным id (`main.rs:20328`), а C/Rust differential (`test-controller-udpplan-differential.sh`) покрывает только voice-тело и нормализует шапку/id. Поэтому побайтового паритета QUIC-планов нет.

## 4. N-ряды (16 функций)

**Прочитано построчно: 16/16 N-строк; тела прочитаны, R2O-отсутствие/частичность подтверждены поиском.**

Список N в задании совпадает с `core-net.md` (16 имён). Ниже проверен каждый; для пяти `udpruntime.c`-строк статус изменён на P (см. §2), поэтому в N-списке остаётся 10 N и 6 P.

| C-функция | C-строки | текущий | проверенный | Rust-аналог (file:line/символ) или «нет» | доказательство / конкретный пробел |
|---|---|---|---|---|---|
| `d2k_tls12_prf_for_test` | 214-218 | N | N | нет; PRF внутри rustls (`r2o_tls.rs:53`) | C-векторы `test_tls12.c:27-64` (опубликованный PRF-вектор + частичный блок) в Rust не перенесены. **Функция не под `#ifdef`** — утверждение в N-таблице `core-net.md`, что она «только под тестовой сборкой», неверно; под `D2K_HS_TESTING` только HTTP-search-хуки. |
| `d2k_verify_tcp_timestamps_get` | 829 | N | N | нет геттера; частично `raw_probe.rs:673 raw_offer_timestamps`, `:87 offer_ts` | C: thread-local `-1/0/1`; `sched.c:2817-2819` ставит профиль из триггера, `verify.c:1361,1514` передают его в `d2k_props_contact_on_family_tcp_profile` → `compose.c:591-636 connect_with_tcp_profile` временно пишет `/proc/sys/net/ipv4/tcp_timestamps`. R2O: в fetch/replay — обычный `TcpStream::connect`, TS-опция ядра по умолчанию; per-call `Option<bool>` есть только в raw_probe (сырой SYN). **Это packet-path, а не CLI** — классификация в N-таблице `core-net.md` неверна. |
| `d2k_httpsprobe_lost` | 460-466 | N | N | нет | C инкрементирует `lost` только при переполнении `done[]` (`httpsprobe.c:337-341`). R2O использует ограниченный `SyncSender` и блокирующий `send` (`https_probe.rs:179`): при переполнении воркер блокируется, а не дропает; при закрытом канале результат теряется без счётчика. Счётчика `lost` нет. |
| `d2k_httpsearch_test_add_failures` | CSV 553-566; факт. 555-568 | N | N | нет | Только под `#ifdef D2K_HS_TESTING` (`httpsearch.c:554-579`). R2O-тесты создают `HttpSearchRecordCache` напрямую (`main.rs:25020,28398`). Тестовый хук, не нужен в проде. |
| `d2k_httpsearch_test_add_records` | CSV 567-576; факт. 569-578 | N | N | нет | То же; только под `D2K_HS_TESTING`. |
| `d2k_qw_retry_build` | 481-521 | N | N | нет; только `r2k-core/src/quic.rs:569 retry_integrity_valid` | R2O умеет только проверять Retry-тег; сборки Retry (серверная роль) нет. Клиентскому datapath не нужна; дифференциала нет. |
| `udp_raw_init` | 101-106 | N | P | `r2o-datapath/src/raw.rs:48 RawSocket::open`, `:35-44 OwnedFd` | См. §2. C-специфичный `d2k_ip6frag_sender` заменён IPv6-raw; контроллерного sink нет. |
| `udp_raw_close` | 107-112 | N | P | `raw.rs:35-44` (RAII) | См. §2. |
| `udp_raw_prepare` | 113-130 | N | P | `raw.rs:48-93`, `:155-167` | См. §2. **`IP_NODEFRAG` в R2O отсутствует**; mark обязателен; IPv6-путь иной. |
| `udp_raw_send` | 131-139 | N | P | `raw.rs:147-223` | См. §2. Полный IP-пакет/фрагмент, MSG_DONTWAIT, EMSGSIZE-понижение MTU. |
| `d2k_udp_plan_send` | 147-190 | N | P | датапат: `engine.rs:1753`, `main.rs:3604`, `wire.rs:109/132`, `raw.rs:147` | См. §2. Контроллерный API отсутствует, проводное поведение плана реализовано в датапате. |
| `qp_recv_ttl` | 937-997 | N | N | нет | Во всём R2O нет `recvmsg`/`IP_RECVTTL`/`IPV6_HOPLIMIT` (0 совпадений). C читает cmsg TTL/hoplimit и отдаёт через `quic_ask_core` (`ttl_in_out`, 1315-1329); это питает TTL-плечо (`quic_ask_ttl`). Quinn/`UdpSocket` TTL не отдают. Реальный packet-path-пробел. |
| `d2k_quic_props_findings` | CSV 2274-2323; факт. 2275-2324 | N | N | нет | C собирает текст из таблицы `offsetof(d2k_quic_props, …)` (2280-2306), используется в `sched.c:11506`. В R2O есть имена кандидатов (`quic_replay.rs:628`), но нет функции выводов. CLI/лог-паритет. |
| `prop_word` | 244-246 | N | N | нет | Точной тройки «прошло/не прошло/ответа нет» в Rust нет; reason-строки в `quic_replay.rs`/`classify.rs` иные. CLI/лог-паритет. |
| `d2k_vol_verdict_name` | 215-222 | N | P | `fetch.rs:486-493 r2o_label`; дубль `bin/r2o-fetch.rs:232-236` | Четыре состояния и почти те же строки: `Short`/`Cut`/`Passed` совпадают дословно; `Unreachable` в `r2o_label` — «цель не ответила», в C — «мишень не ответила» (в JSON-пути `r2o-fetch.rs:233` — «мишень»). Функции нет, теста нет. P, не N. |
| `voice_ask_real` | 365 | N | N | нет; прямой `r2o_ask_voice_with_arm` (`voice_measure.rs:608`, приватный) | C-аксессор нужен для подмены `d2k_voice_ask_hook`; в R2O хуков нет, вызов прямой. API-шима нет, поведение не страдает. |

Итог по N-списку: было `N`×16; проверено `N`×10 + `P`×6. Новые `N` вне списка: `d2k_qc_peer_name`, `remember_live_failure` (см. §5).

## 5. Ключевые P: TLS 1.2/1.3

| C-функция | C-строки | текущий | проверенный | Rust-аналог (file:line/символ) | доказательство / конкретный пробел |
|---|---|---|---|---|---|
| `read_exact` (1.2) | 119-153 | P | P | `fetch.rs:2464 R2oTlsTcpStream::read`, `:2388 R2oTlsRecordTracker`, `:2975 set_deadline` | Абсолютный дедлайн в R2O есть: на каждой итерации рукопожатия `set_deadline` пересчитывает остаток (`fetch.rs:963-986`, `1859-1901`), `WouldBlock/TimedOut/Interrupted` повторяются. Не совпадают: poll-кванты ≤1 с, EINTR-семантика, тексты ошибок, точные `rx_wire_bytes`/`rx_record_missing`. |
| `write_all` (1.2) | 155-171 | P | P | rustls `Stream`/std `Write` (`fetch.rs:2475-2483`) | C обрабатывает EINTR/EAGAIN и шлёт `MSG_NOSIGNAL`; std на blocking-сокете этого не требует. Отдельной функции нет. |
| `prf` | 183-212 | P | P | rustls (TLS1.2 PRF) | Собственной функции нет; C KAT (`test_tls12.c:27-64`) не перенесён. Функционально PRF считает rustls, end-to-end TLS1.2 покрыт `donor_and_r2o_reject_short_tls12_server_finished`. |
| `read_record` (1.2) | 287-345 | P | P | `r2o_tls.rs:53` + rustls `complete_io` (`fetch.rs:965`) | **Ветка «открытый HTTP вместо TLS» (294-299) в fetch/replay не портирована явно**: rustls падает общим `DecryptError`/`InvalidMessage`, а `HTTP/`-префикс проверяет только `response.rs:572 receives_tls_record` (HTTPS-проба). Проверки `rlen==0/>18432` (300-306), минимума 24 байта (322-325), CCS (311), AEAD-ошибки (333-343) делегированы rustls с другими текстами. |
| `hs_next` | 355-407 | P | P | rustls handshake driver | Сборка сообщений из нескольких записей, alert (378-381), CCS-псевдотип (383-388), «не handshake посреди рукопожатия» (389-392) — всё внутри rustls; побайтового differential нет. |
| `ch12_build` | 415-485 | P | P | `r2o_tls.rs:63-116` (`r2o_tls_client_connection_with_alpn`) | C: ровно два шифра (425-426), группы X25519/P-256/**P-384** (446-451), 4 sigalg (455-461), пустой session_id, **без ALPN**, padding-расширение 21 до `want_wire` (464-474). R2O: те же два шифра, но ALPN `http/1.1` всегда (`r2o_tls.rs:59,110`), sigalg — список rustls, и `SECP384R1` разрешён (`:96`). Итог: CH побайтно не равен C; более того, R2O примет P-384 SKE, который C отвергает (609-616). |
| `tls12_finish` | 556-748 | P | P | rustls handshake | Конкретные расхождения: C жёстко отвергает CCS до ServerHelloDone (570-574) и `CertificateRequest` (624-629); rustls ведёт себя иначе (CCS в допустимых точках; при `with_no_client_auth` возможен пустой клиентский сертификат). C принимает только X25519/P-256 (598-623), R2O — ещё P-384. C проверяет длину Finished ровно 16 (736-740), но не сверяет verify_data (AEAD — доказательство); в R2O для не-ECH выставлен `requires_server_finished_verification=false` (`r2o_tls.rs:78`), для ECH — `true` (`:283`), т.е. тот же курс, что в C. Ошибки «сервер требует клиентский сертификат» и «неподдерживаемая группа» C/Rust differential не имеют. |
| `d2k_tls12_read` | 756-793 | P | P | `fetch.rs:2464` + rustls `Stream::read` | C: alert с description==0 — EOF, остальные — ошибка (774-781); не-appdata записи пропускаются (782). Rustls отдаёт `Ok(0)` на close_notify и ошибку на прочих alert; тексты иные, теста на close_notify нет. |
| `d2k_tls12_rx_record_missing` | 800 | P | P | `fetch.rs:2459 r2o_record_missing` → `bool`; `r2o_volume.rs:46` | C возвращает `uint32` «сколько байт записи не дочитано» (`tls12.c:122,150`); C-фикстура `test_tls_rx12.c:24` проверяет точное `2384`. R2O отдаёт только `bool` и только после рукопожатия; точное значение потеряно. |
| `read_record` (1.3) | 175-234 | P | P | rustls `read_tls` + tracker | Как и в 1.2, явной проверки `HTTP/` (183-188) в fetch нет. Дополнительно C **принимает открытый non-appdata после установки ключей** (206-212), rustls такой пакет отвергает. Снятие zero-padding и внутренний тип (226-232), «запись без внутреннего типа» (227-230), AEAD-ошибка (220-223) — внутри rustls. |
| `tls_connect_internal` | 265-523 | P | P | `r2o_tls.rs:53`, `:274 r2o_tls_ech_client_connection` | C: downgrade на 1.2 по `d2k_t13_sh_version==0x0303` с `d2k_tls12_resume` (365-379); ECH — только 1.3 (`offer_tls12 = ech==NULL`, 320); ECH accept (380-383) и **проверка серверного Finished только для ECH** (450-470). R2O: downgrade делает rustls в одном соединении; ECH accept — `fetch.rs:987`; Finished для ECH — `verify_finished=true` (`r2o_tls.rs:283`); для не-ECH — `false` (`:78`), как в C. Не сопоставлены: байтовая форма CH ECH и `offer_tls12`, CCS-совместимость (504-512), тайминги. |
| `d2k_tls_read` | 562-601 | P | P | `fetch.rs:2464` + rustls `Stream::read` | C пропускает CCS (581) и handshake-билеты (589-591), close_notify — EOF (582-588), прочие alert — ошибка. Rustls ведёт себя так же по смыслу, но тексты/классификация не сверялись. |
| `d2k_tls_rx_record_missing` | 611 | P | P | `fetch.rs:2459`, `r2o_volume.rs:46` | То же: `uint32` → `bool`; для TLS1.2-ветки значение берётся из `d2k_tls12_rx_record_missing` (611), но в R2O единый bool-трекер. |

### 5.1. Ветви TLS, которые rustls не покрывает построчно

| Ветвь C | Поведение C | R2O | Вывод |
|---|---|---|---|
| `tls12.c:294-299`, `tls13.c:183-188` | Открытый `HTTP/` вместо TLS → отдельная ошибка «не TLS» | rustls: общая ошибка; явная проверка только в `response.rs:572` (HTTPS-проба) | Не покрыто в fetch/replay; классификация/текст иные. |
| `tls12.c:300-306`, `tls13.c:189-195` | `rlen==0` или `>18432` → отказ до чтения тела | rustls: свой лимит/ошибка; tracker помечает `valid=false` только после рукопожатия | Формально защищено, но не тем кодом и без точного значения. |
| `tls12.c:311`, `tls13.c:199-205` | CCS → пустая запись, не в транскрипт | rustls обрабатывает CCS | Покрыто зависимостью. |
| `tls13.c:206-212` | Открытый Handshake после установки ключей C отдаёт как есть, и цикл `tls_connect_internal` (426-448) его принимает; non-handshake отвергается | rustls отвергает открытый handshake-рекорд после ключей | **Расхождение**: C мягче для plaintext-Handshake. |
| `tls12.c:322-325`, `tls13.c:216-219` | Слишком короткая encrypted-запись → отказ | rustls отвергает | Покрыто. |
| `tls12.c:333-343`, `tls13.c:220-233` | AEAD-тег/внутренний тип/padding | rustls | Покрыто; текст ошибки и номер записи не совпадают. |
| `tls12.c:378-381`, `tls13.c:352-357` | Alert посреди рукопожатия → ошибка с уровнем/описанием | rustls `AlertReceived` | Покрыто; текст иной. |
| `tls12.c:570-574` | CCS раньше ServerHelloDone → отказ | rustls допускает CCS в допустимых точках | Не сопоставлено. |
| `tls12.c:624-629` | `CertificateRequest` → честный отказ | rustls с `with_no_client_auth` | Не сопоставлено; возможен пустой клиентский сертификат. |
| `tls12.c:446-451` + `609-616` | P-384 объявлен, но SKE с P-384 отвергается | `r2o_tls.rs:96` разрешает SECP384R1 | **R2O успешнее C**; паритета нет. |
| `tls12.c:455-461` | 4 sigalg | список rustls | CH отличается. |
| `tls13.c:450-470` | ECH: проверка серверного Finished вручную | rustls `verify_finished=true` | Покрыто зависимостью, C-вектора нет. |
| `tls12.c:122,150`, `tls13.c:105,133` | `rx_record_missing` — точное число байт | bool | Точное значение потеряно. |
| `tls12.c:123-137`, `tls13.c:106-120` | Абсолютный дедлайн + poll ≤1 с + EINTR | `set_deadline` + цикл до дедлайна | Семантика дедлайна сохранена; кванты/EINTR/тексты — нет. |

## 6. Ключевые P: QUIC-соединение

| C-функция | C-строки | текущий | проверенный | Rust-аналог (file:line/символ) | доказательство / конкретный пробел |
|---|---|---|---|---|---|
| `tp_build` | 380-403 | P | P | нет; quinn default `TransportConfig` (`r2o_quic_http3.rs:908-916`) | C объявляет `max_idle_timeout=30000`, `max_udp_payload_size=1452`, окна `D2K_QC_CONN_WIN`/`STREAM_WIN`, `max_streams=16/16`, `active_connection_id_limit=2`, `initial_source_connection_id`. R2O не задаёт `TransportConfig` вообще — действуют значения quinn; сырой Initial строится из снятого 275-байтового профиля (`quic_replay.rs:17,98-134`), а не из `tp_build`. Значения не сопоставлены. |
| `tp_server_parse` | 418-453 | P | P | quinn | C читает `0x04/0x06/0x07/0x08/0x09`, различает «не сказал» и «разрешил 0»; R2O пределы сервера наружу не отдаёт, соблюдение делегировано quinn. |
| `frames_in` | 479-696 | P | P | quinn | C-разбор всех кадров, включая `NEW_CONNECTION_ID` с `retire_prior_to` и 16-байтовым reset-token (540-565), `MAX_DATA/MAX_STREAMS` (567-589), `CONNECTION_CLOSE` (618-632), STREAM (634-693). Quinn обрабатывает это внутри; C/Rust тестов на эти ветви нет. |
| `recv_dgram` | 702-815 | P | P | quinn | C: коалесцированные пакеты, молчаливый пропуск неразобранного хвоста (728-731), Retry только один и только валидный (740-765), `peer_cid_fixed` по SCID сервера (793-798), счётчики rx по уровням. Quinn делает это иначе; байтового паритета нет. |
| `d2k_qc_connect` | 966-1286 | P | P | `quinn::Endpoint::connect` (`r2o_quic_http3.rs:918-936`) | **Ключевое расхождение:** в C нет проверки цепочки/подписи — сертификат разбирается только ради имени (`quicconn.c:1195-1197 d2k_t13_cert_name_ok`), и это заявленная политика проекта (`d2k_tls13.h:9`: «НЕ проверяет сертификат»). R2O использует `with_root_certificates` (`r2o_quic_http3.rs:890`) с webpki-корнями (`fetch.rs:515-516`) → непроверенная цепочка/несовпадение имени в R2O обрывают рукопожатие, в D2O — нет. Также: PTO C 333 мс с удвоением (1121, 1242-1250) и app-PTO 300 мс (1395-1401) заменены loss recovery quinn; классификация отказа по числу Initial/Handshake (1269-1283) в R2O отсутствует. |
| `d2k_qc_peer_name` | 1430 | E | N | нет | `R2oQuicHttp3Result` (`r2o_quic_http3.rs:217-236`) не содержит `name_ok`; `fetch.rs:1000` считает имя только для TCP TLS. C `verify.c:2041` кладёт `d2k_qc_peer_name(c)` в `r.name_ok`. Дифференциал `d2o_verify_differential.rs:719` — TCP TLS1.3 (`"tls13"`), не QUIC. Вдобавок R2O проверяет имя через webpki и при несовпадении рвёт handshake. |
| `first_flight` | 836-892 | E | P | `r2k-core/src/quic.rs:261 r2k_quic_initial_build` + профиль `quic_replay.rs:98` | C собирает CH с `tp_build`, ALPN `h3`, `session_id_len=0` (866-885). R2O `r2k_quic_initial_build` лишь оборачивает **готовый** CH; сырой путь берёт снятый 275-байтовый профиль. Тест `создаёт_аутентифицированный_quic_initial…` проверяет только запечатывание Initial, не CH/TP. |
| `d2k_qc_first_initial` | 928-954 | E | P | `quic.rs:261` + `quic_replay.rs:98` | То же: публичная сборка Initial из CH есть, сборки CH из SNI+TP нет; E не доказан. |
| `d2k_qc_stream_send` | 1288-1375 | P | P | quinn `SendStream` | C проверяет `peer_streams`/`peer_sdata`/`peer_max_data` и возвращает текстовую причину (1300-1333); quinn соблюдает лимиты, но ошибки/блокировки иные. C повторяет последнюю app-посылку по PTO (1363-1373); quinn делает свою ретрансмиссию. |
| `d2k_qc_app_progress` | 1425-1428 | P | P | `r2o_quic_http3.rs:278 r2o_quic_http3_app_bytes_load` | C считает покрытие диапазонами (`d2k_qw_ranges_bytes/complete`); R2O — уникальные принятые байты потока через quinn stats (`R2oQuicHttp3Result.app_bytes`, «уникальные байты… включая HEADERS и framing») и `complete` по признаку завершённого ответа h3. Семантика близкая, но не тождественная (учёт control/QPACK, перекрытия). |

### 6.1. Ветви QUIC, которые quinn не покрывает построчно

| Ветвь C | Поведение C | R2O | Вывод |
|---|---|---|---|
| `tp_build` 380-403 | Клиентские TP: idle 30 с, UDP 1452, окна, streams 16/16, CID limit 2 | quinn defaults | Не сопоставлено; влияет на то, сколько сервер вправе прислать, и на счёт датаграмм в бюджете. |
| `recv_dgram` 740-765 | Второй/поздний Retry отбрасывается; Retry проверяется по тегу | quinn | Не тестировано против C. |
| `frames_in` 540-565 | `NEW_CONNECTION_ID` + `retire_prior_to` меняет DCID | quinn | Не тестировано. |
| `frames_in` 567-589 | `MAX_DATA/MAX_STREAMS` только растут | quinn | Не тестировано. |
| `d2k_qc_connect` 1121,1242-1250,1395-1401 | PTO 333 мс ×2, app-PTO 300 мс ×2 | quinn RFC 9002 | Тайминги и число повторов иные; на бюджете датаграмм это может менять вердикт. |
| `d2k_qc_connect` 1269-1283 | Классификация: «Initial ×N, Handshake нет» / «сервер замолчал» / «Finished не собрался» | нет | В R2O/quinn — общая ошибка handshake; диагностический текст потерян. |
| `frames_in` 656-674, `stream_recv` 1404-1421 | Кредит продлевается на половине окна, ACK на каждый пакет | quinn | Иная частота ACK/MAX_* → иное число датаграмм; прямого differential бюджета нет. |
| `d2k_qc_peer_name` 1430 | Имя из сертификата, handshake продолжается | webpki-проверка | R2O строже: mismatch = отказ, а не `name_ok=0`. |

## 7. Исправления к `core-net.md`

### 7.1. Изменения статусов

1. **`d2k_qc_peer_name`: `E` → `N`.** В `R2oQuicHttp3Result` нет поля имени/сертификата; дифференциал `donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names` запускает C-хелпер с `"tls13"` (TCP), а не QUIC. `verify.c:2041` использует `d2k_qc_peer_name`, в R2O аналога нет. Дополнительно R2O проверяет цепочку/имя через webpki и при mismatch рвёт handshake.
2. **`first_flight` (quicconn.c): `E` → `P`.** E-тест покрывает только `r2k_quic_initial_build` (запечатывание готового CH); C-функция собирает CH с `tp_build`/ALPN h3/`session_id=0`. R2O сырой путь использует снятый профиль, не `tp_build`.
3. **`d2k_qc_first_initial`: `E` → `P`.** То же: публичная сборка Initial из CH есть, сборки CH из SNI+TP нет.
4. **`remember_live_failure`: `P` → `N`.** `HttpSearchRecord` (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`; полей `failures/addr/binding/execution/request_ms`, лимитов байт и счётчиков нет. `HttpLiveFailures` (`main.rs:4457-4460`) строится из каталога `failed_http_programs` (`:4594-4630`), а не пишется живым отказом; `r2o_catalog_mark_flow_unfit` ставит только `recheck_since` (`:2992`), `enabled` остаётся true. Контракт C не реализован.
5. **`udp_raw_init`: `N` → `P`.** `RawSocket::open` (`raw.rs:48-93`) + `OwnedFd` — функциональный аналог; C-специфичный `d2k_ip6frag_sender` заменён IPv6-raw.
6. **`udp_raw_close`: `N` → `P`.** RAII (`raw.rs:35-44`).
7. **`udp_raw_prepare`: `N` → `P`.** `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` есть (`raw.rs:75,77,80`); **`IP_NODEFRAG` отсутствует**, mark обязателен, IPv6-путь иной.
8. **`udp_raw_send`: `N` → `P`.** `raw.rs:147-223` шлёт полный IPv4/IPv6-пакет/фрагмент; отличия — MSG_DONTWAIT, EMSGSIZE-понижение MTU, отказ при нулевом IPv4 ID.
9. **`d2k_udp_plan_send`: `N` → `P`.** Датапат исполняет план (фрагменты `engine.rs:1753`, задержка `main.rs:3604`, TTL `wire.rs:109/132`, raw-send `raw.rs:147`); контроллер ставит addr-probe и шлёт триггер. Нет контроллерного API, socket-TTL get/set/restore и `ECONNREFUSED → -2`.
10. **`d2k_vol_verdict_name`: `N` → `P`.** `fetch.rs:486-493 r2o_label` содержит те же 4 состояния; `Short/Cut/Passed` совпадают дословно, `Unreachable` — «цель не ответила» вместо «мишень не ответила» (в JSON-пути `r2o-fetch.rs:233` — «мишень»). Функции и теста нет.

### 7.2. Исправления доказательств без изменения статуса

11. **`d2k_quic_delay_plan`.** Текущая ссылка `r2o_quic_deny.rs:203 r2o_delay` — ложное сопоставление: это backoff deny-кэша 10/30/60 мин, не эмиттер плана. Правильно: разбор `delay` — `plan_text.rs:444`, `REC_DELAY` — `plan.rs:47/286`, применение — `main.rs:3604`, фикстура — `main.rs:26066`; продюсера нет. Также описание «delay 500000» неверно: C печатает `delay 15000` (`D2K_QUIC_DELAY_US = D2K_PACE_SETTLE_US = 15000`; `test_quic_arms.c:373`).
12. **`failed_live`.** Текущее «main.rs HttpSearchRecord (failures)» — неверно: такого поля нет. Правильно: `failed_http_programs:4594`; он читает **выключенные** (`enabled=false`) name-привязки каталога, а не per-record отказы, и не имеет продюсера живого HTTP-отказа. P сохраняется только как «каталожная эвристика».
13. **`read_record` (tls12.c/tls13.c).** Утверждение «ветка открытого HTTP покрыта fetch.rs» неверно: fetch вызывает rustls `complete_io` (`fetch.rs:963-986`) и получает общую ошибку; явная проверка `HTTP/` есть только в `response.rs:572-604` (HTTPS-проба).
14. **`read_exact` (tls12.c/tls13.c).** Это не «таймаут сокета вместо дедлайна»: R2O пересчитывает остаток от абсолютного дедлайна (`fetch.rs:2975-2982`, циклы `963-986`, `1859-1901`). Не совпадают poll-кванты, EINTR и точные счётчики.
15. **`d2k_qc_connect`.** Добавить расхождение проверки сертификата: в `quicconn.c` нет проверки цепочки/подписи, сертификат разбирается только ради имени (`quicconn.c:1195-1197`), R2O использует webpki-корни (`r2o_quic_http3.rs:890`, `fetch.rs:515-516`). Плюс отсутствие `TransportConfig`: quinn defaults вместо `tp_build`.
16. **`ch12_build`.** Добавить: C не шлёт ALPN в TLS1.2 CH, R2O всегда шлёт `http/1.1` (`r2o_tls.rs:59,110`); C объявляет P-384, но отвергает его в SKE, R2O разрешает `SECP384R1` (`r2o_tls.rs:96`) — R2O принимает то, что C отвергает; sigalg-список rustls шире C.
17. **N-таблица `core-net.md`.** Фраза «тестовые хуки/экспорт существуют только под тестовой сборкой D2O» верна только для `d2k_httpsearch_test_add_*` (`#ifdef D2K_HS_TESTING`). `d2k_tls12_prf_for_test` (`tls12.c:214-218`) — обычный экспорт без `#ifdef`.
18. **N-таблица, `d2k_verify_tcp_timestamps_get`.** Классификация «только CLI/лог, не сеть» неверна: профиль управляет TCP TS-опцией SYN через `compose.c:591-636` (временная запись `/proc/sys/net/ipv4/tcp_timestamps`). Это packet-path; в R2O fetch/replay профиль не проброшен (только raw_probe).
19. **`d2k_httpsearch_diagnostic_counts`.** Не только `limit_hits`: `http_failure_bytes` жёстко 0 (`main.rs:16762`), а `http_failure_limit_hits/record_limit_hits/alloc_failures` остаются 0, потому что массивов отказов и счётчиков нет (`diagnostics.rs:474-481`).
20. **Нумерация.** `d2k_httpsearch_test_add_failures` — факт. 555-568 (CSV 553-566), `d2k_httpsearch_test_add_records` — 569-578 (CSV 567-576), `d2k_quic_props_findings` — 2275-2324 (CSV 2274-2323).
21. **`d2k_vol_verdict_name`.** Даже при смене на P зафиксировать расхождение строки `Unreachable`: `r2o_label` — «цель не ответила», C — «мишень не ответила»; JSON-путь `r2o-fetch.rs:233` использует «мишень».

## 8. Итоговые counts по проверенным строкам

Проверено уникальных строк: 54 — 8 `udpruntime.c`, 12 `udpplan.c`, 11 из N-списка (без 5 повторов `udpruntime.c`), 13 ключевых TLS, 10 ключевых QUIC. Плюс отдельно разобраны 14 ветвей TLS и 8 ветвей QUIC (не входят в 548).

| Показатель | `core-net.md` | после проверки | изменение |
|---|---:|---:|---|
| E | 220 | 217 | −3 (`first_flight`, `d2k_qc_first_initial` → P; `d2k_qc_peer_name` → N) |
| P | 311 | 318 | +7 (+2 E→P, +6 N→P, −1 P→N) |
| N | 16 | 12 | −4 (−6 N→P, +1 E→N, +1 P→N) |
| ? | 1 | 1 | 0 |
| Всего | 548 | 548 | 0 |

Точная арифметика P: 311 + 2 (`first_flight`, `d2k_qc_first_initial`) + 6 (`udp_raw_init/close/prepare/send`, `d2k_udp_plan_send`, `d2k_vol_verdict_name`) − 1 (`remember_live_failure` → N) = 318. E: 220 − 2 − 1 = 217. N: 16 − 6 + 1 (`d2k_qc_peer_name`) + 1 (`remember_live_failure`) = 12.

По подмножествам:

| Подмножество | было | стало |
|---|---|---|
| `core/udpruntime.c` (8) | P 3, N 5 | P 8 |
| `core/udpplan.c` (12) | E 3, P 9 | E 3, P 9 (исправлены доказательства у 2) |
| N-список (16) | N 16 | N 10, P 6 |
| `core/quicconn.c` (36) | E 4, P 32 | E 1, P 34, N 1 |
| TLS-ключевые (13) | P 13 | P 13 (статусы не менялись) |

Ограничения итога: production-поведение на живом роутере, OpenWrt/musl, timing и память не проверялись; дифференциалы (`test-controller-udpplan-differential.sh`, `r2o-tls-verify-differential.sh`, `test-quic-http3-full-stage-differential.sh` и др.) в этом проходе не перезапускались. `E` в таблицах означает наличие целевого теста/дифференциала, а не подтверждённый прогон.
