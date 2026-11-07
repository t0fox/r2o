# Полный function-level индекс production C-функций D2O

Срез: локальное дерево D2O `a378e230947ebfd011439e1cac0f1e994d883aae`; R2O `de0298cd789896cc442be70c0831eafa10192580`.

Индекс построен независимым лексическим экстрактором, а не прежним эвристическим парсером. Учтены:

- **2523** функций в production `.c` (после удаления 3 ложных срабатываний и добавления 3 пропущенных);
- **61** production `static inline` функций в заголовках, которых не было в прежнем индексе;
- всего **2584** функций.

Статусы: `equivalent (scoped)` — есть прямой C/Rust differential на узкий контракт; `partial` — реализация есть, покрытие неполное; `implemented-unproven` — код есть, прямого доказательства нет; `missing` — Rust-аналога нет; `not-applicable` — вне scope/мёртвый API.

Сводка статусов: E=16, P=1798, U=675, M=23, NA=72.

Функций, не названных в тексте аудиторских отчётов: **660**. Они перечислены в `docs/audit/unmentioned-functions.md`; для них действует module-level статус из таблицы ниже.

Контрактные ID нормализованы 2026-11-08: Panel → `A*`, Router → `B*`, Telegram → `TG*`, Classifier → `CL*`, Discord Gateway → `G1`. Все 2584 строки ссылаются только на существующие ID нормализованной матрицы (174 контракта / 263 балла); проверка `check_contract_refs.py` даёт 0 отсутствующих ссылок.

## Сводка по файлам

| Файл | Функций | Rust-владелец | Контракт | Файловый статус |
|---|---:|---|---|---|
| `core/catalog.c` | 60 | r2o-controller/catalog.rs | S5 | partial |
| `core/compose.c` | 53 | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial |
| `core/crypto.c` | 28 | ring/rustls/hpke | CL15/M6 | partial |
| `core/d2kask.c` | 24 | ask.rs, main.rs::run_r2o_ask | M2 | partial |
| `core/d2kc.c` | 28 | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial |
| `core/d2kfetch.c` | 6 | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial |
| `core/d2kvoice.c` | 4 | voice_measure.rs, voice_targets.rs | M4 | partial |
| `core/diagnostics.c` | 41 | r2o-controller/diagnostics.rs | S11 | partial |
| `core/domain.c` | 4 | r2o-controller/domain.rs | S5 | implemented-unproven |
| `core/groups.c` | 14 | r2o-controller/groups.rs | S5 | implemented-unproven |
| `core/h3.c` | 9 | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial |
| `core/hello.c` | 19 | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial |
| `core/httpsearch.c` | 66 | main.rs HTTP search, http_search.rs | S6 | partial |
| `core/httpsprobe.c` | 22 | https_probe.rs, response.rs | CL13 | partial |
| `core/httpup_logic.c` | 15 | r2k-core/httpup.rs | CL14 | partial |
| `core/include/d2k_arm.h` | 1 | r2k-core/plan/apply.rs | D14/D15 | partial |
| `core/include/d2k_http_reply.h` | 6 | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | partial |
| `core/include/d2k_ip6frag_send.h` | 9 | r2o-datapath/raw.rs | D19 | partial |
| `core/include/d2k_link.h` | 3 | r2k-core/control.rs | D20 | missing |
| `core/include/d2k_quicprobe.h` | 9 | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | partial |
| `core/include/d2k_resource.h` | 6 | r2o-controller/r2o_resource.rs | CL15 | partial |
| `core/ipfrag.c` | 8 | r2k-core/wire.rs | D3 | equivalent (scoped) |
| `core/link.c` | 43 | r2k-core/control.rs, main.rs::ControlClient | S1 | partial |
| `core/match.c` | 3 | r2o-controller/catalog.rs | S5 | partial |
| `core/meas.c` | 13 | classify.rs (API-only) | CL6/CL8 | partial |
| `core/measured.c` | 11 | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial |
| `core/net4.c` | 4 | r2k-core/addr.rs, quic_replay.rs, voice_targets.rs | M5 | partial |
| `core/p256.c` | 22 | ring/rustls | CL15/M6 | implemented-unproven |
| `core/plantlv.c` | 20 | r2o-controller/plan_text.rs | M6 | partial |
| `core/props.c` | 5 | quic_replay.rs, main.rs QUIC | Q2/M6 | partial |
| `core/quic.c` | 21 | r2k-core/quic.rs | Q1 | partial |
| `core/quicarms.c` | 8 | quic_replay.rs | Q2 | partial |
| `core/quicconn.c` | 36 | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial |
| `core/quichello.c` | 13 | r2o_tls.rs, quic_replay.rs | Q1 | partial |
| `core/quicprobe.c` | 56 | quic_replay.rs, fetch.rs | Q2/Q3 | partial |
| `core/quicsnap.c` | 6 | r2k-core/quic_snapshot.rs | Q1 | partial |
| `core/quicsnap_reseal.c` | 2 | r2k-core/quic.rs | Q1 | partial |
| `core/quicwire.c` | 28 | r2k-core/quic.rs, wire.rs | Q1 | partial |
| `core/sched.c` | 282 | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial |
| `core/stun.c` | 5 | r2k-core/stun.rs, voice_measure.rs | R1 | partial |
| `core/tls12.c` | 26 | rustls, fetch.rs | CL12 | partial |
| `core/tls13.c` | 23 | rustls, r2o_tls.rs | CL12 | partial |
| `core/tls13core.c` | 24 | rustls, ech.rs, hello.rs | CL12/CL10 | partial |
| `core/udpplan.c` | 12 | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial |
| `core/udpruntime.c` | 8 | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing |
| `core/verdict.c` | 7 | classify.rs (API-only) | CL5 | not-applicable |
| `core/verify.c` | 73 | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial |
| `core/verify_quic_replay.c` | 2 | quic_replay.rs, fetch.rs | Q2 | partial |
| `core/voice.c` | 14 | voice_measure.rs, voice_targets.rs | R2/R3 | partial |
| `core/voice_discovery.c` | 7 | voice_discovery.rs | R2 | partial |
| `core/volume.c` | 19 | r2o_volume.rs, fetch.rs | CL15/M5 | partial |
| `core/x25519.c` | 11 | hpke/rustls | CL15/M6 | partial |
| `datapath/addr.c` | 3 | r2k-core/addr.rs | D18 | partial |
| `datapath/capture.c` | 6 | r2o-datapath/capture.rs | D12 | partial |
| `datapath/ctl.c` | 14 | r2o-datapath/control.rs | S1/D17 | partial |
| `datapath/ctlsrv.c` | 12 | control.rs, main.rs | S1/D18 | partial |
| `datapath/ctq.c` | 20 | conntrack.rs | D13 | partial |
| `datapath/d2kd.c` | 44 | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial |
| `datapath/hold.c` | 12 | r2o-datapath/hold.rs | D6/D7 | partial |
| `datapath/http80.c` | 30 | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial |
| `datapath/http_trace.c` | 1 | — | D17 | missing |
| `datapath/icmpguard.c` | 7 | r2o_icmp_guard.rs | D15 | partial |
| `datapath/include/d2k_ctl.h` | 2 | r2k-core/control.rs | S1 | partial |
| `datapath/include/d2k_http_request_stream.h` | 3 | r2k-core/httpup.rs | CL14 | partial |
| `datapath/include/d2k_http_response.h` | 6 | r2k-core/http_response.rs | CL11 | partial |
| `datapath/include/d2k_packet.h` | 2 | r2k-core/packet.rs | D18 | partial |
| `datapath/include/d2k_plans.h` | 2 | r2o-datapath/control.rs | D16 | partial |
| `datapath/include/d2k_track.h` | 1 | r2o-datapath/engine.rs | D10 | partial |
| `datapath/journal.c` | 14 | flow_journal.rs | D22 | partial |
| `datapath/nat.c` | 5 | proc_nat.rs | D13 | partial |
| `datapath/nfq.c` | 12 | nfqueue.rs | D1a/D1b/D2 | partial |
| `datapath/nl.c` | 19 | netlink.rs | D1a/D1b/D2 | partial |
| `datapath/plan_apply.c` | 15 | r2k-core/plan/apply.rs | D14/D15 | partial |
| `datapath/plan_parse.c` | 17 | r2k-core/plan.rs | D14 | partial |
| `datapath/plans.c` | 75 | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial |
| `datapath/raw.c` | 17 | r2o-datapath/raw.rs | D19 | partial |
| `datapath/routemark.c` | 23 | r2o_route.rs | D20 | partial |
| `datapath/routemark_nl.c` | 8 | r2o_route.rs | D20 | partial |
| `datapath/sched.c` | 16 | scheduler.rs | D21 | partial |
| `datapath/session.c` | 107 | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial |
| `datapath/tls.c` | 7 | r2k-core/tls.rs | D12 | partial |
| `datapath/track.c` | 18 | engine.rs, flow_capacity.rs | D10 | equivalent (scoped) |
| `datapath/udp_hold.c` | 10 | r2o_udp_hold.rs | D8 | partial |
| `datapath/udp_path.c` | 7 | main.rs, r2o_udp_hold.rs | D9 | partial |
| `datapath/udp_release.c` | 34 | r2o_udp_hold.rs | D9 | partial |
| `datapath/wire.c` | 9 | r2k-core/wire.rs | D13 | partial |
| `datapath/wire_udp.c` | 5 | r2k-core/wire.rs | D3/D13 | partial |
| `detect/bridge.c` | 17 | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial |
| `detect/classify.c` | 36 | r2o-controller/classify.rs | CL5 | equivalent (scoped) |
| `detect/include/d2k_detect.h` | 1 | r2o-controller/classify.rs | CL5 | partial |
| `detect/main.c` | 8 | r2o-controller/main.rs CLI | CL16 | partial |
| `detect/poison.c` | 12 | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial |
| `detect/props.c` | 7 | classify.rs, raw_probe.rs | CL5 | partial |
| `detect/raw.c` | 62 | r2o-controller/raw_probe.rs | CL1 | equivalent (scoped) |
| `detect/response.c` | 7 | r2o-controller/response.rs | CL9 | equivalent (scoped) |
| `detect/trigger.c` | 9 | r2o-controller/trigger.rs | CL1 | equivalent (scoped) |
| `panel/main.c` | 18 | r2o-panel/main.rs | A1/A2/A5 | partial |
| `panel/server.c` | 51 | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial |
| `relay-enroll/main.c` | 45 | — | — | not-applicable |
| `relay-gate/main.c` | 19 | — | — | not-applicable |
| `runtime/d2k_diagnostics_files.h` | 4 | r2o-controller/diagnostics.rs | S11 | partial |
| `runtime/d2k_runtime.h` | 6 | r2k-core/control.rs::valid_release_id | S1 | missing |
| `telegram/src/cf_domains.c` | 19 | r2o-telegram/cf_domain_pool.rs | TG13 | partial |
| `telegram/src/config.c` | 9 | r2o-telegram/config.rs | TG1 | partial |
| `telegram/src/dc_map.c` | 13 | r2o-telegram/dc_map.rs | TG3 | partial |
| `telegram/src/dc_map_json.c` | 16 | r2o-telegram/dc_map.rs | TG3 | partial |
| `telegram/src/dc_map_store.c` | 27 | r2o-telegram/dc_map.rs | TG3 | partial |
| `telegram/src/enroll.c` | 1 | — | — | not-applicable |
| `telegram/src/epoll_proxy.c` | 101 | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | partial |
| `telegram/src/identity.c` | 12 | r2o-telegram/identity.rs | TG2 | partial |
| `telegram/src/limits.c` | 3 | r2o-telegram/limits.rs | TG22 | partial |
| `telegram/src/listener.c` | 8 | r2o-telegram/transparent.rs | TG15 | partial |
| `telegram/src/main.c` | 29 | r2o-telegram/main.rs, server.rs | TG24 | partial |
| `telegram/src/memory_budget.c` | 2 | — | TG22 | missing |
| `telegram/src/mtproto_auth.c` | 27 | r2o-telegram/dc_discovery.rs, grammers | TG8 | partial |
| `telegram/src/mtproto_config.c` | 11 | r2o-telegram/dc_discovery.rs | TG4 | partial |
| `telegram/src/mtproto_crypto.c` | 12 | r2o-telegram/crypto.rs | TG5 | partial |
| `telegram/src/mtproto_encrypted.c` | 4 | grammers mtp::Encrypted | TG7 | partial |
| `telegram/src/mtproto_probe.c` | 39 | r2o-telegram/dc_discovery.rs, ws_client | TG8 | partial |
| `telegram/src/mtproto_splitter.c` | 12 | r2o-telegram/splitter.rs | TG6 | partial |
| `telegram/src/net.c` | 2 | r2o-telegram/outbound/connector.rs | TG9/TG18 | partial |
| `telegram/src/route_dns.c` | 49 | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | partial |
| `telegram/src/route_plan.c` | 6 | r2o-telegram/routing.rs, ws_client.rs | TG9 | partial |
| `telegram/src/stats_socket.c` | 10 | r2o-telegram/stats.rs | TG19/TG20 | partial |
| `telegram/src/tls.c` | 4 | r2o-telegram/ws_client.rs, meta_edge.rs | TG11 | partial |
| `telegram/src/transparent.c` | 6 | r2o-telegram/transparent.rs | TG15/TG16 | partial |
| `telegram/src/ws.c` | 18 | r2o-telegram/ws_client.rs | TG12 | partial |
| `telegram/src/ws_pump.c` | 20 | r2o-telegram/bridge.rs, ws_client.rs | TG12 | partial |

## Полные таблицы

### `core/catalog.c` — 60

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `set_err` | 55 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 2 | `jpeek` | 79 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 3 | `jeat` | 92 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 4 | `jeat_null_if_present` | 110 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 5 | `floor_div` | 148 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 6 | `days_from_civil` | 156 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 7 | `civil_from_days` | 166 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 8 | `format_rfc3339` | 185 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 9 | `jparse_raw_int` | 207 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 10 | `jparse_i32` | 241 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 11 | `jparse_u8` | 252 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 12 | `jparse_u16` | 263 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 13 | `jparse_bool_i` | 274 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 14 | `jparse_string_dyn` | 305 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 15 | `jparse_string_fixed` | 408 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 16 | `read_fixed_digits` | 428 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 17 | `eat_lit` | 447 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 18 | `jparse_rfc3339` | 462 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 19 | `jskip_value` | 545 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 20 | `parse_object` | 629 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 21 | `grow` | 667 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 22 | `parse_array` | 692 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 23 | `handle_signal_key` | 723 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 24 | `parse_signal` | 743 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 25 | `handle_fp_key` | 756 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 26 | `parse_fp` | 789 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 27 | `handle_plan_key` | 798 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 28 | `parse_plan` | 817 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 29 | `elem_plan` | 821 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 30 | `handle_binding_key` | 834 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 31 | `parse_binding` | 886 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 32 | `elem_binding` | 891 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 33 | `d2k_cat_shape_fits` | 905 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 34 | `handle_box_key` | 918 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 35 | `parse_box` | 940 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 36 | `elem_box` | 944 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 37 | `handle_domain_observation` | 953 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 38 | `parse_domain_observations` | 972 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 39 | `handle_net_whitelist_key` | 991 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 40 | `handle_catalog_key` | 1001 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 41 | `parse_catalog_obj` | 1028 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 42 | `prune_unavailable_domain_groups` | 1036 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 43 | `free_box` | 1062 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 44 | `d2k_catalog_free` | 1072 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 45 | `d2k_catalog_memory_bytes` | 1084 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 46 | `read_whole_file` | 1103 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 47 | `d2k_catalog_load` | 1145 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 48 | `write_json_string` | 1198 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 49 | `wr_indent` | 1220 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 50 | `write_json_array` | 1230 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 51 | `write_signal_elem` | 1242 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 52 | `write_fp` | 1259 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 53 | `write_plan_elem` | 1268 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 54 | `write_binding_elem` | 1282 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 55 | `write_box_elem` | 1334 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 56 | `write_domain_key` | 1353 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 57 | `write_domain_observation` | 1359 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 58 | `write_domain_group` | 1367 | да | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 59 | `d2k_catalog_save` | 1374 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |
| 60 | `d2k_catalog_save_atomic` | 1445 |  | r2o-controller/catalog.rs | S5 | partial | named in report | JSON/atomic save/sync; parser internals не все diff-tested |

### `core/compose.c` — 53

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_net_whitelist_count` | 107 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 2 | `d2k_net_whitelist_name` | 110 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 3 | `wr16be` | 150 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 4 | `rd16be` | 151 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 5 | `wr32be` | 152 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 6 | `tlv_rec` | 162 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 7 | `tlv_header` | 186 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 8 | `plan_tlv_stamp_ident` | 218 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 9 | `overlap_plan_tlv` | 258 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 10 | `reorder_plan_tlv` | 277 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 11 | `badsum_fake_plan_tlv` | 296 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 12 | `checksum_plan_tlv` | 322 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 13 | `to_hex` | 331 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 14 | `ev_matches_flow` | 351 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 15 | `wait_for_event3` | 397 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 16 | `wait_for_event` | 423 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 17 | `props_bind_any` | 494 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 18 | `d2k_props_bind` | 526 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 19 | `d2k_props_bind_family` | 530 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 20 | `d2k_props_bind_udp` | 534 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 21 | `d2k_props_bind_udp_family` | 538 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 22 | `d2k_props_contact` | 542 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 23 | `d2k_props_contact_on` | 547 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 24 | `d2k_props_contact_on_family` | 553 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 25 | `tcp_timestamps_read` | 567 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 26 | `tcp_timestamps_write` | 580 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 27 | `connect_with_tcp_profile` | 591 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 28 | `d2k_props_contact_on_family_tcp_profile` | 638 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 29 | `build_fake_body` | 786 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 30 | `d2k_props_question_plan` | 798 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 31 | `d2k_props_question_passed` | 845 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 32 | `question_retire` | 874 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 33 | `d2k_props_ask` | 881 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 34 | `step_rc` | 889 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 35 | `d2k_props_ask_traced` | 900 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 36 | `append_fmt` | 1203 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 37 | `emit_header_proto` | 1221 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 38 | `emit_header` | 1229 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 39 | `append_hex` | 1233 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 40 | `overlap_plan_text` | 1245 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 41 | `reorder_plan_text` | 1271 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 42 | `badsum_fake_plan_text` | 1288 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 43 | `checksum_plan_text` | 1312 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 44 | `build_decoy_hello` | 1346 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 45 | `parse_protocol_plan_text` | 1356 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 46 | `duplicates_plan_text` | 1367 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 47 | `body_room` | 1384 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 48 | `everything_plan_text` | 1397 | да | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 49 | `d2k_fallback_arms` | 1498 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 50 | `fb_arm_at` | 1503 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 51 | `d2k_fallback_plan` | 1542 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 52 | `d2k_arm_plan` | 1551 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |
| 53 | `d2k_compose` | 1762 |  | ask.rs, classify.rs, r2o_fallback.rs, plan_text.rs | CL1/CL5/M1 | partial | named in report | compose/fallback; TCP-profile connect отсутствует |

### `core/crypto.c` — 28

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `xtime` | 33 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 2 | `d2k_aes_sbox_byte` | 70 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 3 | `aes128_key_expand` | 80 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 4 | `sub_bytes` | 112 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 5 | `shift_rows` | 121 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 6 | `mix_columns` | 131 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 7 | `add_round_key` | 142 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 8 | `aes128_encrypt_block` | 151 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 9 | `d2k_aes128_ecb` | 167 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 10 | `rotr32` | 175 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 11 | `sha256_compress` | 201 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 12 | `sha256_init` | 230 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 13 | `sha256_update` | 242 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 14 | `sha256_final` | 267 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 15 | `d2k_sha256` | 292 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 16 | `d2k_hmac_sha256` | 301 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 17 | `d2k_hkdf_extract` | 331 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 18 | `d2k_hkdf_expand_label` | 350 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 19 | `d2k_hkdf_expand_label_ctx` | 355 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 20 | `gf128_h_table` | 449 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 21 | `gf128_mul_fast` | 463 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 22 | `ghash` | 479 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 23 | `d2k_ghash_for_test` | 538 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 24 | `inc32` | 547 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 25 | `gctr` | 560 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 26 | `consttime_eq16` | 584 | да | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 27 | `d2k_aes128_gcm_encrypt` | 596 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |
| 28 | `d2k_aes128_gcm_decrypt` | 627 |  | ring/rustls/hpke | CL15/M6 | partial | named in report | замена зависимостями; RFC 9001 векторы |

### `core/d2kask.c` — 24

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `need_value` | 120 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 2 | `parse_flag_u16` | 134 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 3 | `parse_flag_u32` | 157 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 4 | `parse_flag_ms` | 179 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 5 | `parse_args` | 202 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 6 | `hex_nibble` | 315 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 7 | `save_hex` | 329 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 8 | `read_hex_file` | 361 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 9 | `wait_shape` | 424 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 10 | `pval_str` | 462 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 11 | `print_header` | 470 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 12 | `print_snapshot` | 482 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 13 | `pos_decided` | 519 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 14 | `pos_value` | 530 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 15 | `step_rc_str` | 547 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 16 | `ack_code_str` | 565 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 17 | `print_seen_types` | 579 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 18 | `print_step` | 597 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 19 | `print_question` | 632 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 20 | `all_unknown` | 676 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 21 | `print_not_asked_at_all` | 684 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 22 | `print_vector` | 698 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 23 | `print_plans` | 707 | да | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |
| 24 | `main` | 736 |  | ask.rs, main.rs::run_r2o_ask | M2 | partial | named in report | CLI/exit/stdout расходятся |

### `core/d2kc.c` — 28

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `on_signal` | 111 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 2 | `now_ms` | 113 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 3 | `save_atomic` | 122 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 4 | `self_mem` | 136 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 5 | `sched_say` | 150 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 6 | `http_search_portal` | 168 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 7 | `hs_open_port` | 176 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 8 | `hs_close_port` | 210 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 9 | `hs_hex` | 212 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 10 | `hs_set_probe` | 221 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 11 | `hs_del_probe` | 235 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 12 | `hs_set_plan` | 246 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 13 | `hs_del_plan` | 259 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 14 | `hs_start` | 271 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 15 | `hs_changed` | 277 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 16 | `http_portal` | 288 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 17 | `http_push` | 310 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 18 | `http_save` | 317 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 19 | `http_probe_done` | 324 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 20 | `hs_say` | 357 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 21 | `poison_cmp` | 365 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 22 | `hs_measured_poisons` | 368 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 23 | `usage` | 394 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 24 | `offline_self_check` | 406 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 25 | `diagnostic_event` | 415 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 26 | `diagnostic_limit` | 418 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 27 | `diagnostic_tick` | 421 | да | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |
| 28 | `main` | 470 |  | main.rs::serve_catalog/watch_events, diagnostics.rs, live.rs | M1 | partial | named in report | нет --health-file/--measure-mark/--self-check |

### `core/d2kfetch.c` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `json_string` | 41 | да | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |
| 2 | `vol_verdict_code` | 64 | да | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |
| 3 | `usage` | 74 | да | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |
| 4 | `resolve_first` | 104 | да | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |
| 5 | `snapshot_wire` | 117 | да | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |
| 6 | `main` | 157 |  | src/bin/r2o-fetch.rs, fetch.rs | M3 | partial | named in report | JSON level/name_ok/location расходятся |

### `core/d2kvoice.c` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `usage` | 22 | да | voice_measure.rs, voice_targets.rs | M4 | partial | named in report | --wait 0/--list/Приём расходятся |
| 2 | `split_hostport` | 39 | да | voice_measure.rs, voice_targets.rs | M4 | partial | named in report | --wait 0/--list/Приём расходятся |
| 3 | `verdict_word` | 50 | да | voice_measure.rs, voice_targets.rs | M4 | partial | named in report | --wait 0/--list/Приём расходятся |
| 4 | `main` | 63 |  | voice_measure.rs, voice_targets.rs | M4 | partial | named in report | --wait 0/--list/Приём расходятся |

### `core/diagnostics.c` — 41

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `copy` | 98 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 2 | `js` | 105 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 3 | `number` | 131 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 4 | `d2k_diag_new` | 132 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 5 | `d2k_diag_free` | 133 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 6 | `d2k_diag_bytes` | 134 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 7 | `d2k_diag_event_count` | 135 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 8 | `d2k_diag_sample_count` | 136 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 9 | `d2k_diag_memory_history_count` | 137 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 10 | `d2k_diag_memory_enable` | 138 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 11 | `d2k_diag_memory_active` | 139 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 12 | `atomic_read` | 140 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 13 | `atomic_peak` | 141 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 14 | `d2k_diag_memory_acquire` | 145 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 15 | `d2k_diag_memory_release` | 152 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 16 | `d2k_diag_memory_alloc_failure` | 157 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 17 | `d2k_diag_memory_snapshot` | 161 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 18 | `d2k_diag_memory_counts` | 170 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 19 | `d2k_diag_set_madvise` | 180 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 20 | `record_anomaly` | 181 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 21 | `d2k_diag_record_write_error` | 188 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 22 | `d2k_diag_record` | 192 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 23 | `d2k_diag_record_limit` | 202 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 24 | `value` | 213 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 25 | `compact_kib` | 218 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 26 | `compact_bytes_kib` | 221 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 27 | `compact_bytes` | 222 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 28 | `compact_count` | 223 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 29 | `proc_pid_dir_present` | 225 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 30 | `optional_proc_status` | 230 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 31 | `read_proc` | 238 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 32 | `read_detail` | 260 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 33 | `read_status` | 305 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 34 | `write_detail` | 310 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 35 | `write_limit_reason` | 329 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 36 | `write_limit_reason_state` | 344 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 37 | `write_memory_tracking` | 357 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 38 | `write_madvise` | 370 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 39 | `write_anomalies` | 382 | да | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 40 | `d2k_diag_sample` | 395 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |
| 41 | `d2k_diag_write` | 469 |  | r2o-controller/diagnostics.rs | S11 | partial | named in report | allocator/madvise и часть периодики отсутствуют |

### `core/domain.c` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_domain_normalize` | 6 |  | r2o-controller/domain.rs | S5 | implemented-unproven | named in report | PSL/registrable логика; прямого differential нет |
| 2 | `rule_exists` | 31 | да | r2o-controller/domain.rs | S5 | implemented-unproven | named in report | PSL/registrable логика; прямого differential нет |
| 3 | `d2k_domain_base` | 42 |  | r2o-controller/domain.rs | S5 | implemented-unproven | named in report | PSL/registrable логика; прямого differential нет |
| 4 | `d2k_domain_member` | 66 |  | r2o-controller/domain.rs | S5 | implemented-unproven | named in report | PSL/registrable логика; прямого differential нет |

### `core/groups.c` — 14

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_group_key_make` | 9 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 2 | `d2k_group_key_same` | 19 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 3 | `valid` | 24 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 4 | `member` | 38 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 5 | `votes` | 45 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 6 | `failures` | 61 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 7 | `add_group` | 72 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 8 | `rebuild` | 103 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 9 | `cover` | 122 | да | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 10 | `d2k_group_learn` | 133 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 11 | `d2k_group_restore` | 246 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 12 | `d2k_group_match` | 274 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 13 | `d2k_group_forget` | 294 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |
| 14 | `d2k_group_expire` | 311 |  | r2o-controller/groups.rs | S5 | implemented-unproven | named in report | группы/восстановление; прямого differential нет |

### `core/h3.c` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_h3_control` | 19 |  | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 2 | `prefix_int` | 30 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 3 | `prefix_int_read` | 51 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 4 | `d2k_h3_request` | 73 |  | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 5 | `huff_status` | 126 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 6 | `static_status` | 148 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 7 | `name_is_status` | 171 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 8 | `decode_section` | 176 | да | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |
| 9 | `d2k_h3_status` | 262 |  | crate h3, r2o_quic_http3.rs | Q4/Q5 | partial | named in report | H3 status/headers; не все ветви |

### `core/hello.c` — 19

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16` | 51 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 2 | `rd24` | 54 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 3 | `wr16` | 57 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 4 | `wr24` | 61 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 5 | `skip_u8_vec` | 69 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 6 | `skip_u16_vec` | 80 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 7 | `parse_hello` | 128 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 8 | `d2k_hello_complete` | 274 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 9 | `d2k_hello_shape` | 283 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 10 | `d2k_hello_sni` | 308 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 11 | `d2k_hello_ech_offer` | 322 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 12 | `d2k_hello_alpn` | 349 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 13 | `d2k_alpn_is_http` | 377 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 14 | `splice_sni` | 409 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 15 | `hex_nibble` | 462 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 16 | `hex_decode` | 480 | да | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 17 | `d2k_hello_rename` | 500 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 18 | `d2k_hello_without_sni` | 537 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |
| 19 | `d2k_hello_from_profile` | 578 |  | r2k-core/tls.rs, hello.rs, r2o_tls.rs | CL12 | partial | named in report | ClientHello/SNI/ECH/ALPN parse |

### `core/httpsearch.c` — 66

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `mono_ms` | 37 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 2 | `d2k_hs_answer_name` | 43 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 3 | `d2k_hs_judge` | 61 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 4 | `hs_path_ok` | 99 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 5 | `hs_read` | 110 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 6 | `d2k_hs_probe_run` | 132 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 7 | `d2k_hs_candidate_count` | 253 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 8 | `d2k_hs_candidate_key` | 254 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 9 | `poison_key_spec` | 258 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 10 | `known_key` | 289 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 11 | `d2k_hs_candidate_text` | 296 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 12 | `stable_id` | 327 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 13 | `fresh_id` | 334 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 14 | `say` | 442 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 15 | `host_ok` | 452 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 16 | `rec_find` | 468 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 17 | `rec_get` | 477 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 18 | `same_program` | 500 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 19 | `failed_live` | 510 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 20 | `remember_live_failure` | 520 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 21 | `d2k_httpsearch_test_add_failures` | 553 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 22 | `d2k_httpsearch_test_add_records` | 567 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 23 | `d2k_httpsearch_measured_poison` | 579 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 24 | `d2k_hs_plan_poisons` | 608 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 25 | `d2k_httpsearch_new` | 644 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 26 | `drop_socket` | 652 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 27 | `drop_probe` | 659 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 28 | `d2k_httpsearch_free` | 666 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 29 | `d2k_httpsearch_busy` | 676 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 30 | `d2k_httpsearch_plan_of` | 680 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 31 | `d2k_httpsearch_diagnostic_counts` | 687 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 32 | `d2k_httpsearch_diagnostics` | 707 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 33 | `diagnostic_end` | 710 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 34 | `finish` | 722 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 35 | `open_job` | 730 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 36 | `revoke_owned` | 752 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 37 | `all_failed` | 759 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 38 | `install` | 804 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 39 | `d2k_httpsearch_install_ack` | 818 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 40 | `confirmed` | 843 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 41 | `trial_executed` | 894 | да | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 42 | `judge_trial` | 902 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 43 | `next_candidate` | 955 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 44 | `add_cand` | 1005 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 45 | `build_cands` | 1012 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 46 | `build_fallback` | 1041 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 47 | `start` | 1054 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 48 | `start_next` | 1093 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 49 | `live_owner` | 1103 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 50 | `d2k_httpsearch_bound_failure` | 1113 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 51 | `d2k_httpsearch_control` | 1133 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 52 | `d2k_httpsearch_cut` | 1170 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 53 | `d2k_httpsearch_portal` | 1190 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 54 | `d2k_httpsearch_ack` | 1229 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 55 | `d2k_httpsearch_applied` | 1262 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 56 | `d2k_httpsearch_result` | 1289 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 57 | `d2k_httpsearch_tick` | 1397 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 58 | `d2k_httpsearch_push_all` | 1429 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 59 | `d2k_httpsearch_save` | 1444 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 60 | `d2k_httpsearch_load` | 1473 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 61 | `runner_main` | 1525 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 62 | `d2k_hs_runner_new` | 1539 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 63 | `d2k_hs_runner_free` | 1555 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 64 | `d2k_hs_runner_wake_fd` | 1564 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 65 | `d2k_hs_runner_start` | 1566 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |
| 66 | `d2k_hs_runner_done` | 1581 |  | main.rs HTTP search, http_search.rs | S6 | partial | named in report | lifecycle/runner; живой поиск не проверен |

### `core/httpsprobe.c` — 22

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_https_classify` | 32 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 2 | `d2k_https_upgrade` | 42 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 3 | `d2k_https_ttl` | 46 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 4 | `d2k_https_state_name` | 57 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 5 | `mono_ms` | 69 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 6 | `https_connect` | 77 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 7 | `https_tls` | 148 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 8 | `first_flight` | 171 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 9 | `d2k_https_probe_real` | 203 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 10 | `host_ok` | 274 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 11 | `cache_find` | 285 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 12 | `cache_put` | 292 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 13 | `worker` | 314 | да | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 14 | `d2k_httpsprobe_new` | 351 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 15 | `d2k_httpsprobe_free` | 377 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 16 | `d2k_httpsprobe_wake_fd` | 393 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 17 | `d2k_httpsprobe_portal` | 397 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 18 | `d2k_httpsprobe_done` | 430 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 19 | `d2k_httpsprobe_state` | 451 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 20 | `d2k_httpsprobe_lost` | 460 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 21 | `d2k_httpsprobe_save` | 476 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |
| 22 | `d2k_httpsprobe_load` | 507 |  | https_probe.rs, response.rs | CL13 | partial | named in report | cache/TTL/ECH; lost-probe отсутствует |

### `core/httpup_logic.c` — 15

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `ascii_alnum` | 16 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 2 | `dns_host` | 21 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 3 | `host_equal` | 37 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 4 | `known_portal_host` | 46 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 5 | `find_crlf` | 53 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 6 | `parse_request` | 60 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 7 | `d2k_httpup_request_safe` | 132 |  | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 8 | `build_redirect` | 137 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 9 | `portal_marker` | 151 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 10 | `redirect_location_host` | 172 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 11 | `portal_answer` | 193 | да | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 12 | `d2k_httpup_portal_response` | 227 |  | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 13 | `d2k_httpup_request_target` | 240 |  | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 14 | `d2k_httpup_portal_location` | 253 |  | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |
| 15 | `d2k_httpup_redirect_https` | 264 |  | r2k-core/httpup.rs | CL14 | partial | named in report | portal/redirect/request rules |

### `core/include/d2k_arm.h` — 1

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_arm_segment` | 78 | да | r2k-core/plan/apply.rs | D14/D15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `core/include/d2k_http_reply.h` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_http_lower` | 9 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_http_equal` | 12 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_http_hostchar` | 17 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 4 | `d2k_http_portal` | 22 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 5 | `d2k_http_location_portal` | 27 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 6 | `d2k_http_reply_classify` | 55 | да | r2k-core/httpup.rs, fetch.rs | CL13/CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `core/include/d2k_ip6frag_send.h` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_ip6frag_sender_init` | 34 | да | r2o-datapath/raw.rs | D19 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_ip6frag_sender_close` | 37 | да | r2o-datapath/raw.rs | D19 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_f6_now` | 41 | да | — | D19 | missing | header-inline; module-level only | route/neighbor query не перенесён |
| 4 | `d2k_f6_attr` | 46 | да | — | D19 | missing | header-inline; module-level only | route/neighbor query не перенесён |
| 5 | `d2k_f6_query` | 56 | да | — | D19 | missing | header-inline; module-level only | route/neighbor query не перенесён |
| 6 | `d2k_f6_route` | 73 | да | — | D19 | missing | header-inline; module-level only | route lookup не перенесён |
| 7 | `d2k_f6_neighbor` | 107 | да | — | D19 | missing | header-inline; module-level only | neighbor lookup не перенесён |
| 8 | `d2k_ip6frag_prepare` | 155 | да | r2o-datapath/raw.rs | D19 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 9 | `d2k_ip6frag_send` | 196 | да | r2o-datapath/raw.rs | D19 | partial | named in report | IPv6 fragment send частично; route/neighbor нет |

### `core/include/d2k_link.h` — 3

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_link_shape_tcp_profile` | 309 | да | r2k-core/control.rs | D20 | missing | named in report | TCP shape contexts 8-13 не реализованы |
| 2 | `d2k_link_shape_tcp_base` | 321 | да | r2k-core/control.rs | D20 | missing | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_link_shape_tcp_context` | 333 | да | r2k-core/control.rs | D20 | missing | header-inline; module-level only | header-inline; module-level only |

### `core/include/d2k_quicprobe.h` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_quic_arm_data_judge` | 454 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_quic_arm_data_judge_limited` | 466 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_qstall_init` | 523 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 4 | `d2k_qstall_sent` | 540 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 5 | `d2k_qstall_step` | 545 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 6 | `d2k_qbudget_init` | 616 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 7 | `d2k_qbudget_ok` | 626 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 8 | `d2k_qbudget_grew` | 637 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 9 | `d2k_quic_arm_data_judge3` | 641 | да | quic_replay.rs, r2o_quic_http3.rs | Q3/Q5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `core/include/d2k_resource.h` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_resource_word` | 27 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_resource_space` | 36 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_resource_path_ok` | 39 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 4 | `d2k_resource_add` | 51 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 5 | `d2k_resource_tag` | 74 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 6 | `d2k_resource_feed` | 114 | да | r2o-controller/r2o_resource.rs | CL15 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `core/ipfrag.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_ipfrag_shape` | 5 |  | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 2 | `d2k_ipfrag_cuts` | 18 |  | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 3 | `wr16` | 46 | да | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 4 | `sum16` | 47 | да | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 5 | `fold` | 51 | да | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 6 | `d2k_udpfrag_build_ex` | 52 |  | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 7 | `d2k_udpfrag_build` | 85 |  | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |
| 8 | `d2k_udpfrag6_build_ex` | 91 |  | r2k-core/wire.rs | D3 | equivalent (scoped) | named in report | IPv4/IPv6 fragment builders shapes 1-4 |

### `core/link.c` — 43

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `execution_context` | 45 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 2 | `say` | 56 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 3 | `wait_readable` | 70 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 4 | `read_exact` | 92 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 5 | `write_all` | 108 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 6 | `hex_nibble` | 133 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 7 | `hex_decode` | 144 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 8 | `d2k_link_open` | 161 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 9 | `d2k_link_close` | 191 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 10 | `d2k_link_peer_closed` | 197 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 11 | `d2k_link_next` | 223 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 12 | `d2k_link_set_name` | 524 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 13 | `d2k_link_set_name_probe` | 531 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 14 | `send_name_plan` | 538 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 15 | `d2k_link_set_name_family` | 632 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 16 | `d2k_link_set_name_bound` | 639 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 17 | `d2k_link_del_name_bound` | 645 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 18 | `d2k_link_set_name_probe_trial` | 659 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 19 | `area_context_valid` | 670 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 20 | `d2k_link_set_suffix_family` | 677 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 21 | `d2k_link_set_https` | 686 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 22 | `d2k_link_set_stall_budgets` | 707 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 23 | `send_area_key` | 731 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 24 | `d2k_link_del_suffix_family` | 754 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 25 | `d2k_link_set_bypass_family` | 758 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 26 | `d2k_link_del_bypass_family` | 762 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 27 | `d2k_link_area_identified` | 767 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 28 | `addr_shape_ok` | 783 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 29 | `d2k_link_set_addr` | 789 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 30 | `d2k_link_set_addr_family` | 794 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 31 | `addr_probe_flow_bytes` | 852 | да | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 32 | `d2k_link_set_addr_probe` | 868 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 33 | `d2k_link_set_addr_probe_family` | 877 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 34 | `d2k_link_del_addr_probe` | 911 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 35 | `d2k_link_del_addr_probe_family` | 919 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 36 | `d2k_link_arm_shape` | 939 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 37 | `d2k_link_arm_shape_family` | 944 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 38 | `d2k_link_del_name_family` | 981 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 39 | `d2k_link_del_name_probe` | 1014 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 40 | `d2k_link_del_name_probe_family` | 1020 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 41 | `d2k_link_del_addr` | 1051 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 42 | `d2k_link_del_addr_family` | 1056 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |
| 43 | `d2k_ev_outer_appdata` | 1079 |  | r2k-core/control.rs, main.rs::ControlClient | S1 | partial | named in report | decode E, encode P; версия/события несовместимы |

### `core/match.c` — 3

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `same_evidence` | 38 | да | r2o-controller/catalog.rs | S5 | partial | named in report | fingerprint match |
| 2 | `d2k_fp_same` | 75 |  | r2o-controller/catalog.rs | S5 | partial | named in report | fingerprint match |
| 3 | `d2k_catalog_match` | 127 |  | r2o-controller/catalog.rs | S5 | partial | named in report | fingerprint match |

### `core/meas.c` — 13

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `nap_us` | 52 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 2 | `d2k_mark_real` | 61 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 3 | `d2k_accept_serverhello` | 87 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 4 | `d2k_accept_tls_record` | 96 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 5 | `d2k_accept_any` | 101 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 6 | `cuts_valid` | 109 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 7 | `send_all` | 124 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 8 | `connect_bounded` | 142 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 9 | `d2k_meas_once` | 175 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 10 | `d2k_meas` | 269 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 11 | `udp_now_ms` | 307 | да | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 12 | `d2k_udp_port_claim` | 313 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |
| 13 | `d2k_udp_port_forget_all` | 341 |  | classify.rs (API-only) | CL6/CL8 | partial | named in report | в текущем d2kc не вызывается |

### `core/measured.c` — 11

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `append_fmt` | 10 | да | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 2 | `append_hex` | 22 | да | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 3 | `d2k_white_decoy_hello` | 33 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 4 | `template_plan` | 57 | да | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 5 | `d2k_rx_volume_plan_named` | 84 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 6 | `d2k_rx_volume_plan_client` | 90 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 7 | `d2k_rx_volume_plan` | 114 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 8 | `measured_payload` | 121 | да | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 9 | `d2k_tcp_split_plan` | 140 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 10 | `d2k_arm_plan_measured_cap` | 153 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |
| 11 | `d2k_arm_plan_measured` | 387 |  | classify_measured.rs, r2o_rx_volume.rs | CL5/CL6 | partial | named in report | measured plans; не все ветви |

### `core/net4.c` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_ip4_parse` | 7 |  | r2k-core/addr.rs, quic_replay.rs, voice_targets.rs | M5 | partial | named in report | parse/private; IPv6 helper продублирован |
| 2 | `d2k_ip4_text` | 32 |  | r2k-core/addr.rs, quic_replay.rs, voice_targets.rs | M5 | partial | named in report | parse/private; IPv6 helper продублирован |
| 3 | `d2k_ip4_private` | 40 |  | r2k-core/addr.rs, quic_replay.rs, voice_targets.rs | M5 | partial | named in report | parse/private; IPv6 helper продублирован |
| 4 | `d2k_ip6_private` | 53 |  | r2k-core/addr.rs, quic_replay.rs, voice_targets.rs | M5 | partial | named in report | parse/private; IPv6 helper продублирован |

### `core/p256.c` — 22

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `fe_copy` | 31 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 2 | `ge` | 34 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 3 | `is_zero` | 41 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 4 | `sub_raw` | 48 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 5 | `add_raw` | 59 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 6 | `fe_add` | 69 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 7 | `fe_sub` | 76 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 8 | `fe_mul` | 84 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 9 | `fe_sqr` | 115 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 10 | `to_mont` | 124 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 11 | `from_mont` | 125 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 12 | `fe_inv` | 131 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 13 | `fe_from_be` | 143 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 14 | `fe_to_be` | 150 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 15 | `pt_double` | 161 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 16 | `pt_add` | 192 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 17 | `pt_mul` | 235 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 18 | `pt_affine` | 249 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 19 | `scalar_ok` | 262 | да | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 20 | `d2k_p256_public` | 268 |  | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 21 | `d2k_p256_keypair` | 282 |  | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |
| 22 | `d2k_p256_ecdh` | 291 |  | ring/rustls | CL15/M6 | implemented-unproven | named in report | P-256 ECDHE; прямого C/Rust вектора нет |

### `core/plantlv.c` — 20

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `b64_value` | 126 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 2 | `parse_base64` | 133 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 3 | `say` | 163 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 4 | `hex_nib` | 171 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 5 | `parse_hex` | 180 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 6 | `anchor_by_name` | 206 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 7 | `split_fields` | 221 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 8 | `parse_uint` | 237 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 9 | `parse_int` | 248 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 10 | `kv_u32` | 259 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 11 | `str_u32` | 268 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 12 | `plan_free` | 272 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 13 | `parse_text` | 277 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 14 | `put` | 691 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 15 | `put_u8` | 696 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 16 | `put_u16` | 697 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 17 | `put_u32` | 698 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 18 | `put_rec` | 702 | да | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 19 | `d2k_plan_text_to_tlv` | 709 |  | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |
| 20 | `d2k_plan_text_to_hex` | 847 |  | r2o-controller/plan_text.rs | M6 | partial | named in report | d2k-plan vs r2o-plan; autottl minexec |

### `core/props.c` — 5

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `original_probe` | 35 | да | quic_replay.rs, main.rs QUIC | Q2/M6 | partial | named in report | original/strategy measure |
| 2 | `original_data` | 47 | да | quic_replay.rs, main.rs QUIC | Q2/M6 | partial | named in report | original/strategy measure |
| 3 | `wire_measure` | 52 | да | quic_replay.rs, main.rs QUIC | Q2/M6 | partial | named in report | original/strategy measure |
| 4 | `d2k_quic_original_measure` | 80 |  | quic_replay.rs, main.rs QUIC | Q2/M6 | partial | named in report | original/strategy measure |
| 5 | `d2k_quic_strategy_measure` | 88 |  | quic_replay.rs, main.rs QUIC | Q2/M6 | partial | named in report | original/strategy measure |

### `core/quic.c` — 21

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16` | 97 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 2 | `read_varint` | 110 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 3 | `parse_initial_header` | 149 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 4 | `d2k_quic_is_initial` | 182 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 5 | `decrypt_initial` | 191 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 6 | `collect_crypto_frames` | 239 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 7 | `skip_u8_vec` | 434 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 8 | `skip_u16_vec` | 446 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 9 | `find_sni` | 458 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 10 | `find_client_hello_sni` | 503 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 11 | `crypto_stream_of` | 552 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 12 | `d2k_quic_client_hello` | 567 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 13 | `d2k_quic_dgrams_hello` | 607 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 14 | `d2k_quic_hello_name` | 661 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 15 | `d2k_quic_hello_incomplete` | 672 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 16 | `d2k_quic_sni` | 687 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 17 | `d2k_quic_assembly_init` | 708 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 18 | `d2k_quic_assembly_feed` | 712 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 19 | `d2k_quic_assembly_complete` | 780 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 20 | `put_split_frame` | 824 | да | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |
| 21 | `d2k_quic_initial_split_crypto` | 841 |  | r2k-core/quic.rs | Q1 | partial | named in report | Initial crypto/SNI |

### `core/quicarms.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_quic_original_blob` | 12 |  | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 2 | `ask_q` | 30 | да | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 3 | `ask_frag` | 112 | да | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 4 | `ask` | 125 | да | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 5 | `d2k_quic_original_arms` | 142 |  | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 6 | `strategy_ask` | 227 | да | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 7 | `prop_word` | 244 | да | quic_replay.rs | Q2 | partial | named in report | strategy arms |
| 8 | `d2k_quic_strategy_arms` | 248 |  | quic_replay.rs | Q2 | partial | named in report | strategy arms |

### `core/quicconn.c` — 36

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `qc_dispose` | 209 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 2 | `say` | 218 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 3 | `now_ms` | 226 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 4 | `crypto_put` | 243 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 5 | `crypto_ready` | 254 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 6 | `build_ack` | 265 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 7 | `seal_level` | 281 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 8 | `send_level` | 352 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 9 | `tp_put_int` | 367 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 10 | `tp_build` | 380 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 11 | `tp_server_parse` | 418 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 12 | `tp_server_ee` | 460 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 13 | `frames_in` | 479 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 14 | `recv_dgram` | 702 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 15 | `crypto_frame` | 820 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 16 | `first_flight` | 836 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 17 | `prepare_retry` | 898 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 18 | `d2k_qc_first_initial` | 928 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 19 | `qc_no_sigpipe` | 956 | да | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 20 | `d2k_qc_connect` | 966 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 21 | `d2k_qc_stream_send` | 1288 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 22 | `d2k_qc_stream_recv` | 1377 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 23 | `d2k_qc_app_progress` | 1425 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 24 | `d2k_qc_peer_name` | 1430 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 25 | `d2k_qc_rx_wire_bytes` | 1431 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 26 | `d2k_qc_datagrams` | 1432 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 27 | `d2k_qc_handshake_done` | 1436 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 28 | `d2k_qc_rtt_ms` | 1437 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 29 | `d2k_qc_dgrams` | 1438 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 30 | `d2k_qc_outbound` | 1443 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 31 | `d2k_qc_ping` | 1454 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 32 | `d2k_qc_fd` | 1459 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 33 | `d2k_qc_local` | 1461 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 34 | `d2k_qc_local_addr` | 1470 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 35 | `d2k_qc_release` | 1478 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |
| 36 | `d2k_qc_close` | 1486 |  | quinn/rustls, r2o_quic_http3.rs | Q1/Q3/Q4 | partial | named in report | stateful QUIC client заменён quinn |

### `core/quichello.c` — 13

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `select_probe_profile` | 34 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 2 | `split_point` | 69 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 3 | `put_crypto` | 80 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 4 | `prepare` | 124 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 5 | `seal_one` | 183 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 6 | `probe_initial_sized` | 235 | да | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 7 | `d2k_quic_probe_initial` | 276 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 8 | `d2k_quic_probe_initial_longer` | 281 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 9 | `d2k_quic_prepare_target` | 287 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 10 | `d2k_quic_hello_rename` | 312 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 11 | `d2k_quic_hello_ask` | 330 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 12 | `d2k_quic_hello_split` | 412 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |
| 13 | `d2k_quic_hello_recid` | 457 |  | r2o_tls.rs, quic_replay.rs | Q1 | partial | named in report | QUIC ClientHello shapes |

### `core/quicprobe.c` — 56

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `qp_addr_parse` | 173 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 2 | `resolve_family` | 181 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 3 | `resolve_real` | 209 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 4 | `d2k_quic_build_pool` | 254 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 5 | `qp_varint` | 320 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 6 | `qp_parse_hdr` | 337 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 7 | `qp_dcid_of` | 411 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 8 | `qp_donor_unauth_reply` | 456 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 9 | `qp_verify_server_response` | 494 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 10 | `qp_build_vn_trigger` | 574 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 11 | `nap_us` | 622 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 12 | `qp_open_fresh` | 637 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 13 | `qp_send_one` | 716 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 14 | `qp_head_of` | 806 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 15 | `qp_verify_aead` | 815 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 16 | `qp_verify_bound` | 835 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 17 | `d2k_quic_verify_bound` | 880 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 18 | `d2k_quic_verify_response` | 890 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 19 | `qp_verify_vn` | 898 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 20 | `qp_recv_ttl` | 937 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 21 | `qp_send_fragmented` | 1004 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 22 | `qp_neutral_control_sni` | 1045 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 23 | `quic_ask_core` | 1064 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 24 | `quic_ask_ex` | 1405 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 25 | `quic_fragment` | 1418 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 26 | `qp_progress` | 1432 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 27 | `quic_ask_arm` | 1437 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 28 | `qp_arm_first_send` | 1500 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 29 | `qp_now_ms` | 1510 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 30 | `quic_arm_data` | 1516 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 31 | `d2k_quic_data_stage` | 1591 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 32 | `quic_ask` | 1832 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 33 | `qp_ask_vn` | 1855 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 34 | `quic_ask_ttl` | 1869 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 35 | `quic_ask_copies` | 1886 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 36 | `quic_ask_srcport` | 1898 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 37 | `quic_ask_split` | 1909 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 38 | `quic_ask_longer` | 1924 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 39 | `quic_ask_frames` | 1931 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 40 | `quic_ask_control` | 1942 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 41 | `reason_set` | 1957 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 42 | `reason_append` | 1964 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 43 | `budget_left` | 1984 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 44 | `qp_pinned_or_next` | 2018 | да | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 45 | `qp_dyn_wait` | 2088 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 46 | `d2k_quic_budget_ms` | 2095 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 47 | `qp_outcome` | 2110 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 48 | `qp_questions_step` | 2117 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 49 | `d2k_quic_props_findings` | 2274 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 50 | `arm_budget_left` | 2325 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 51 | `arm_budget_spent` | 2328 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 52 | `classify_run` | 2336 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 53 | `d2k_quic_classify` | 2919 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 54 | `d2k_quic_base` | 2923 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 55 | `d2k_quic_run_seeded` | 2927 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |
| 56 | `d2k_quic_run` | 2932 |  | quic_replay.rs, fetch.rs | Q2/Q3 | partial | named in report | probe/strategy/data stage |

### `core/quicsnap.c` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_qsnap_is` | 13 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |
| 2 | `d2k_qsnap_parse` | 17 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |
| 3 | `d2k_qsnap_pack` | 49 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |
| 4 | `d2k_qsnap_client_hello` | 75 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |
| 5 | `d2k_qsnap_sni` | 82 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |
| 6 | `d2k_qsnap_form` | 91 |  | r2k-core/quic_snapshot.rs | Q1 | partial | named in report | snapshot parse |

### `core/quicsnap_reseal.c` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `reseal_one` | 24 | да | r2k-core/quic.rs | Q1 | partial | named in report | reseal |
| 2 | `d2k_qsnap_recid` | 75 |  | r2k-core/quic.rs | Q1 | partial | named in report | reseal |

### `core/quicwire.c` — 28

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `salt_for` | 41 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 2 | `label_key` | 44 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 3 | `label_iv` | 47 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 4 | `label_hp` | 50 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 5 | `d2k_qw_varint_read` | 56 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 6 | `d2k_qw_varint_len` | 69 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 7 | `d2k_qw_varint_write_w` | 77 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 8 | `d2k_qw_varint_write` | 107 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 9 | `long_type_v1` | 119 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 10 | `long_type_wire` | 132 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 11 | `d2k_qw_long_hdr_token_w` | 142 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 12 | `d2k_qw_long_hdr_w` | 176 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 13 | `d2k_qw_long_hdr_token` | 186 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 14 | `d2k_qw_long_hdr` | 196 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 15 | `d2k_qw_hdr_parse` | 204 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 16 | `d2k_qw_pn_len` | 277 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 17 | `d2k_qw_pn_decode` | 295 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 18 | `d2k_qw_initial_secret` | 317 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 19 | `d2k_qw_keys_from_secret` | 327 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 20 | `nonce_of` | 344 | да | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 21 | `d2k_qw_seal` | 351 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 22 | `d2k_qw_open` | 396 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 23 | `d2k_qw_retry_verify` | 454 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 24 | `d2k_qw_retry_build` | 481 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 25 | `d2k_qw_ranges_reset` | 525 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 26 | `d2k_qw_ranges_add` | 529 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 27 | `d2k_qw_ranges_bytes` | 560 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |
| 28 | `d2k_qw_ranges_complete` | 566 |  | r2k-core/quic.rs, wire.rs | Q1 | partial | named in report | wire primitives |

### `core/sched.c` — 282

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `refuse_is_permanent` | 298 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 2 | `refuse_is_damage` | 317 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 3 | `verify_default` | 385 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 4 | `bind_default` | 412 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 5 | `verify_rx_default` | 417 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 6 | `verify_rx_gzip_default` | 426 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 7 | `mark_default` | 435 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 8 | `classify_unconfigured` | 448 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 9 | `voice_default` | 479 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 10 | `d2k_sched_cpu_parse` | 485 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 11 | `cpu_read_proc` | 510 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 12 | `meminfo_field` | 528 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 13 | `d2k_sched_meminfo_parse` | 548 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 14 | `mem_read_proc` | 559 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 15 | `read_u64_file` | 570 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 16 | `ct_read_proc` | 581 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 17 | `client_alpn_nonhttp` | 1111 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 18 | `fresh_trial_id` | 1136 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 19 | `addr_probe_remove` | 1513 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 20 | `question_retire` | 1554 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 21 | `candidate_retire` | 1569 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 22 | `trial_retire` | 1589 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 23 | `say` | 1600 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 24 | `say_quiet` | 1612 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 25 | `d2k_sched_set_send_cap` | 1631 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 26 | `d2k_sched_set_say` | 1636 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 27 | `verdict_name` | 1644 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 28 | `signal_of` | 1669 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 29 | `is_rx_volume_kind` | 1696 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 30 | `fp_add` | 1700 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 31 | `volume_bucket` | 1743 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 32 | `is_volume_kind` | 1750 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 33 | `box_volume_bucket_agrees` | 1757 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 34 | `server_is_low` | 1795 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 35 | `client_ip_of` | 1804 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 36 | `server_of` | 1810 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 37 | `same_flow` | 1821 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 38 | `remember` | 1838 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 39 | `recall` | 1861 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 40 | `cooldown_find_endpoint` | 1868 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 41 | `cooldown_find_challenge` | 1883 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 42 | `dead_find` | 1896 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 43 | `dead_step` | 1912 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 44 | `dead_clear` | 1934 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 45 | `is_late_volume_suspicion` | 1939 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 46 | `cooldown_blocks` | 1945 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 47 | `cooldown_clear_endpoint` | 1972 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 48 | `cooldown_clear_nonchallenge` | 1979 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 49 | `clear_backoff_ms` | 1997 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 50 | `cooldown_victim` | 2009 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 51 | `cooldown_record` | 2029 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 52 | `late_close_what` | 2097 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 53 | `box_stall_budget` | 2111 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 54 | `budget_listed` | 2121 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 55 | `name_stall_budgets` | 2128 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 56 | `tcp_stall_in_name_band` | 2150 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 57 | `stall_budgets_push` | 2167 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 58 | `task_of` | 2190 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 59 | `task_free_slot` | 2201 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 60 | `task_watching_slot` | 2214 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 61 | `tcp_hello_kind` | 2237 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 62 | `hello_fits_client` | 2242 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 63 | `quic_pack_ech` | 2253 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 64 | `quic_named_find` | 2265 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 65 | `client_offers_ts` | 2283 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 66 | `client_tcp_profile` | 2300 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 67 | `flowkey_same` | 2317 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 68 | `take_shape_opts` | 2325 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 69 | `drop_client_opts` | 2339 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 70 | `fill_hellos` | 2344 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 71 | `worker_arg_alloc` | 2516 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 72 | `worker_arg_free` | 2526 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 73 | `d2k_sched_ech_baseline_result` | 2535 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 74 | `worker_volume` | 2558 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 75 | `worker_volume_cut` | 2629 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 76 | `seed_input_of` | 2664 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 77 | `d2k_sched_progress_note` | 2677 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 78 | `ask_settle` | 2697 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 79 | `sched_quic_yield` | 2704 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 80 | `sched_quic_progress` | 2728 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 81 | `sched_mono_ms` | 2732 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 82 | `worker_run_body` | 2738 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 83 | `worker_run` | 3252 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 84 | `quic_text_is_split` | 3273 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 85 | `quic_client_multi` | 3277 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 86 | `quic_split_unfit` | 3290 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 87 | `task_budget` | 3303 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 88 | `note_worker_start_failure` | 3328 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 89 | `start_worker` | 3336 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 90 | `join_worker` | 3402 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 91 | `box_ensure` | 3427 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 92 | `wall_s` | 3456 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 93 | `bind_confirmed` | 3460 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 94 | `fnv1a` | 3571 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 95 | `tried_add` | 3590 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 96 | `plan_ident` | 3595 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 97 | `is_hex_digit` | 3604 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 98 | `question_shape` | 3632 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 99 | `probe_shape` | 3639 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 100 | `task_wire_shape` | 3671 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 101 | `binding_wire_shape` | 3675 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 102 | `stamp_plan_id` | 3681 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 103 | `prop_close` | 3724 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 104 | `contact_close` | 3735 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 105 | `ver_close` | 3746 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 106 | `task_reset` | 3759 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 107 | `box_injects_rst` | 3831 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 108 | `rst_guard_wanted` | 3839 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 109 | `plan_arm_rst_guard` | 3850 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 110 | `prop_send_next` | 3861 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 111 | `prop_finish` | 3971 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 112 | `task_fail` | 3990 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 113 | `quic_deny_find` | 4029 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 114 | `quic_deny_install` | 4037 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 115 | `quic_deny_active` | 4111 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 116 | `quic_deny_recheck` | 4126 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 117 | `quic_deny_tick` | 4152 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 118 | `task_done` | 4180 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 119 | `rx_decoy_name` | 4192 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 120 | `net_whitelist_undecided` | 4198 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 121 | `net_whitelist_needs_probe` | 4208 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 122 | `sched_probe_cap` | 4217 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 123 | `vol_cut_measured` | 4221 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 124 | `vol_cut_kb` | 4224 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 125 | `rx_ladder_pending` | 4230 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 126 | `next_rx_volume_plan` | 4239 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 127 | `refill_from_fallback` | 4289 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 128 | `claim_early_refusal` | 4391 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 129 | `ack_reason_text` | 4409 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 130 | `candidate_trial_matches` | 4421 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 131 | `exec_refusal` | 4434 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 132 | `ech_witness_transport_proof` | 4465 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 133 | `ech_witness_rx_cut` | 4473 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 134 | `local_refusal_verdict` | 4482 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 135 | `install_next` | 4536 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 136 | `binding_for` | 4757 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 137 | `known_plans` | 4774 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 138 | `budget_rank` | 4863 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 139 | `binding_beats` | 4866 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 140 | `bound_plan_here` | 4878 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 141 | `own_rank_before` | 4903 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 142 | `own_first_plans` | 4911 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 143 | `verdict_proves_block` | 5054 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 144 | `clear_measured_shape` | 5071 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 145 | `clear_binding_matches` | 5079 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 146 | `forget_clear_target_bindings` | 5120 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 147 | `props_text` | 5175 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 148 | `probes_word` | 5188 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 149 | `verdict_to_plans` | 5206 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 150 | `d2k_sched_new` | 5563 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 151 | `d2k_sched_set_measure_mark` | 5609 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 152 | `json_str` | 5621 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 153 | `json_time` | 5631 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 154 | `level_name` | 5647 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 155 | `signal_human` | 5660 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 156 | `task_phase` | 5682 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 157 | `live_binding_for` | 5704 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 158 | `live_autopick_status` | 5720 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 159 | `d2k_sched_diagnostics` | 5808 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 160 | `d2k_sched_limit_diagnostics` | 5811 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 161 | `worker_type` | 5814 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 162 | `d2k_sched_diagnostic_counts` | 5823 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 163 | `d2k_sched_diagnostic_madvise` | 5873 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 164 | `d2k_sched_diagnostic_madvise_reset` | 5874 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 165 | `d2k_sched_write_live` | 5876 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 166 | `d2k_sched_free` | 6048 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 167 | `wake_loop` | 6074 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 168 | `d2k_sched_wake_fd` | 6079 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 169 | `d2k_sched_active` | 6081 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 170 | `plan_by_id` | 6093 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 171 | `d2k_sched_sync` | 6109 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 172 | `d2k_sched_sync_pending` | 6124 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 173 | `addr_binding_shape` | 6141 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 174 | `newer_name_binding` | 6168 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 175 | `area_key_same` | 6192 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 176 | `area_find` | 6197 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 177 | `area_store` | 6203 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 178 | `area_retry_delay` | 6211 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 179 | `area_failure` | 6220 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 180 | `area_ack_reason` | 6236 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 181 | `area_reason_name` | 6245 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 182 | `area_retry_due` | 6257 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 183 | `area_plan` | 6264 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 184 | `own_exact_confirmed` | 6275 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 185 | `desired_area` | 6294 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 186 | `desired_has_key` | 6331 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 187 | `write_live_groups` | 6344 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 188 | `sync_area_send` | 6439 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 189 | `area_exceptions_ready` | 6517 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 190 | `area_exception_groups_suspended` | 6531 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 191 | `group_exception_status` | 6550 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 192 | `sync_areas` | 6585 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 193 | `plan_text_max_emit` | 6645 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 194 | `d2k_sched_sync_step` | 6657 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 195 | `has_other_family_target_plan` | 6912 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 196 | `remember_resources` | 6936 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 197 | `remember_measured_path` | 6966 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 198 | `public_resource_peer` | 6982 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 199 | `select_resource_path` | 6992 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 200 | `ech_rr_known` | 7049 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 201 | `ech_rr_store` | 7058 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 202 | `ech_chal_has` | 7071 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 203 | `ech_chal_add` | 7078 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 204 | `ech_pick_witness` | 7085 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 205 | `ech_witness_untried` | 7115 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 206 | `ech_witness_reject` | 7127 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 207 | `ech_witness_add` | 7137 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 208 | `start_search` | 7149 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 209 | `box_id_for` | 7329 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 210 | `voice_trial_send` | 7421 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 211 | `voice_ip_fmt` | 7443 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 212 | `voice_ip_text` | 7447 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 213 | `voice_ip_text2` | 7451 | да | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 214 | `voice_trial_owned` | 7458 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 215 | `voice_trial_same_context` | 7466 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 216 | `voice_start` | 7478 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 217 | `voice_finish_measure` | 7509 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 218 | `quic_addr_start` | 7613 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 219 | `measurements_in_flight` | 7625 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 220 | `queued_measurements` | 7632 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 221 | `res_sample` | 7646 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 222 | `res_valid` | 7693 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 223 | `cpu_free_pct` | 7695 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 224 | `mem_reserve_kb` | 7699 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 225 | `mem_short` | 7704 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 226 | `ct_short` | 7708 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 227 | `ct_pct` | 7714 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 228 | `meas_state` | 7718 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 229 | `measure_slots` | 7738 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 230 | `limiter_text` | 7747 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 231 | `measure_started` | 7764 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 232 | `measure_limit_update` | 7768 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 233 | `installed_family_ready` | 7839 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 234 | `binding_covering` | 7873 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 235 | `watch_shape` | 7896 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 236 | `queued_family_ready` | 7902 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 237 | `family_recovery_eligible` | 7907 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 238 | `group_path` | 7916 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 239 | `family_recovery_start` | 7920 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 240 | `launch_task` | 7996 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 241 | `launch_or_queue` | 8026 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 242 | `voice_observe` | 8067 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 243 | `voice_confirm` | 8087 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 244 | `voice_fail` | 8150 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 245 | `is_voice_class` | 8157 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 246 | `is_telegram_tunnel_domain` | 8164 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 247 | `on_suspect` | 8178 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 248 | `quic_own_initial` | 8604 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 249 | `remeasure_snapped` | 8620 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 250 | `quic_note_multi` | 8687 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 251 | `on_shape` | 8729 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 252 | `group_record` | 9010 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 253 | `record_shape` | 9032 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 254 | `budget_uncountable_note` | 9040 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 255 | `budget_cut_reject` | 9069 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 256 | `say_question_trace` | 9156 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 257 | `ladder_candidate_at` | 9172 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 258 | `ladder_candidate` | 9182 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 259 | `candidate_path` | 9186 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 260 | `search_report` | 9204 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 261 | `verify_confirm` | 9259 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 262 | `partial_finish` | 9665 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 263 | `plan_id_is_ours` | 9688 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 264 | `applied_trial_is_ours` | 9697 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 265 | `applied_of_candidate` | 9705 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 266 | `on_applied` | 9736 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 267 | `on_refused_foreign` | 9897 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 268 | `on_refused_unfit` | 9957 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 269 | `on_refused` | 10050 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 270 | `note_clean_handshake` | 10173 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 271 | `clean_handshake_recent` | 10199 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 272 | `on_exchange` | 10214 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 273 | `d2k_sched_event` | 10322 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 274 | `own_first_continue` | 10462 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 275 | `rx_saved_bootstrap` | 10525 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 276 | `layered_rx_result` | 10571 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 277 | `queued_before` | 10655 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 278 | `quic_yield_tick` | 10663 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 279 | `queued_pick` | 10700 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 280 | `queued_release` | 10725 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 281 | `voice_pending_dispatch` | 10753 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |
| 282 | `d2k_sched_tick` | 10781 |  | main.rs, discovery.rs, r2o_resource_limit.rs | S2 | partial | named in report | controller state machine/19 подсистем |

### `core/stun.c` — 5

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16` | 19 | да | r2k-core/stun.rs, voice_measure.rs | R1 | partial | named in report | STUN/Discovery |
| 2 | `rd32` | 23 | да | r2k-core/stun.rs, voice_measure.rs | R1 | partial | named in report | STUN/Discovery |
| 3 | `d2k_stun_request` | 27 |  | r2k-core/stun.rs, voice_measure.rs | R1 | partial | named in report | STUN/Discovery |
| 4 | `parse_xor_mapped` | 52 | да | r2k-core/stun.rs, voice_measure.rs | R1 | partial | named in report | STUN/Discovery |
| 5 | `d2k_stun_parse_response` | 85 |  | r2k-core/stun.rs, voice_measure.rs | R1 | partial | named in report | STUN/Discovery |

### `core/tls12.c` — 26

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tls12_dispose` | 98 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 2 | `say` | 102 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 3 | `now_ms` | 110 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 4 | `put16` | 116 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 5 | `get16` | 117 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 6 | `read_exact` | 119 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 7 | `write_all` | 155 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 8 | `prf` | 183 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 9 | `d2k_tls12_prf_for_test` | 214 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 10 | `tr_add` | 220 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 11 | `nonce_of` | 228 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 12 | `aad_of` | 235 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 13 | `send_plain` | 246 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 14 | `send_sealed` | 258 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 15 | `read_record` | 287 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 16 | `hs_next` | 355 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 17 | `ch12_build` | 415 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 18 | `d2k_tls12_connect` | 492 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 19 | `d2k_tls12_resume` | 532 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 20 | `tls12_finish` | 556 | да | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 21 | `d2k_tls12_write` | 750 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 22 | `d2k_tls12_read` | 756 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 23 | `d2k_tls12_peer_name` | 795 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 24 | `d2k_tls12_free` | 797 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 25 | `d2k_tls12_rx_wire_bytes` | 799 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |
| 26 | `d2k_tls12_rx_record_missing` | 800 |  | rustls, fetch.rs | CL12 | partial | named in report | TLS 1.2 client заменён rustls |

### `core/tls13.c` — 23

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tls_dispose` | 83 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 2 | `say` | 87 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 3 | `now_ms` | 95 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 4 | `read_exact` | 102 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 5 | `write_all` | 138 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 6 | `put16` | 160 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 7 | `get16` | 161 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 8 | `nonce_of` | 165 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 9 | `read_record` | 175 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 10 | `write_record` | 236 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 11 | `traffic_keys` | 260 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 12 | `tls_connect_internal` | 265 | да | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 13 | `d2k_tls_connect` | 525 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 14 | `d2k_tls_connect_alpn` | 531 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 15 | `d2k_tls_connect_ech` | 538 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 16 | `d2k_tls_ech_accepted` | 548 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 17 | `d2k_tls_write` | 550 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 18 | `d2k_tls_read` | 562 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 19 | `d2k_tls_peer_name` | 603 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 20 | `d2k_tls_free` | 605 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 21 | `d2k_tls_rx_wire_bytes` | 610 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 22 | `d2k_tls_rx_record_missing` | 611 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |
| 23 | `d2k_tls_version` | 613 |  | rustls, r2o_tls.rs | CL12 | partial | named in report | TLS 1.3 client заменён rustls |

### `core/tls13core.c` — 24

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `put16` | 16 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 2 | `get16` | 17 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 3 | `d2k_t13_random` | 21 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 4 | `der_len` | 53 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 5 | `ascii_lower` | 64 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 6 | `name_matches` | 73 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 7 | `cert_name_ok` | 106 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 8 | `d2k_t13_cert_name_ok12` | 166 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 9 | `d2k_t13_cert_name_ok` | 177 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 10 | `d2k_t13_ch_build` | 197 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 11 | `d2k_t13_derive_secret` | 361 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 12 | `d2k_t13_schedule_hs` | 368 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 13 | `d2k_t13_schedule_ap` | 383 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 14 | `d2k_t13_finished_mac` | 396 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 15 | `d2k_t13_sh_version` | 407 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 16 | `d2k_t13_sh_parse` | 428 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 17 | `d2k_t13_flight_next` | 479 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 18 | `ech_host_ok` | 492 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 19 | `d2k_ech_config_parse` | 510 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 20 | `hpke_extract` | 570 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 21 | `hpke_expand` | 583 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 22 | `ech_hpke` | 598 | да | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 23 | `d2k_t13_ech_build` | 621 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |
| 24 | `d2k_t13_ech_accepted` | 684 |  | rustls, ech.rs, hello.rs | CL12/CL10 | partial | named in report | ECH/HPKE/TLS core |

### `core/udpplan.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `append_fmt` | 10 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 2 | `emit_header_proto` | 28 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 3 | `append_hex` | 36 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 4 | `quic_arm_found` | 50 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 5 | `quic_split_plan_text` | 59 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 6 | `quic_plan_text` | 69 | да | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 7 | `d2k_quic_arm_plan` | 173 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 8 | `d2k_quic_compose_plan` | 188 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 9 | `d2k_quic_delay_plan` | 205 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 10 | `d2k_voice_arm_plan` | 219 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 11 | `d2k_voice_plan` | 241 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |
| 12 | `d2k_quic_question_plan` | 247 |  | quic_replay.rs, voice_discovery.rs, voice_measure.rs | Q2/R2 | partial | named in report | QUIC/voice plans |

### `core/udpruntime.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `udp_next_fragment_id` | 22 | да | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 2 | `d2k_udp_batch_free` | 32 |  | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 3 | `d2k_udp_plan_build` | 33 |  | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 4 | `udp_raw_init` | 101 | да | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 5 | `udp_raw_close` | 107 | да | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 6 | `udp_raw_prepare` | 113 | да | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 7 | `udp_raw_send` | 131 | да | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |
| 8 | `d2k_udp_plan_send` | 147 |  | r2k-core/plan, datapath engine; raw UDP sender отсутствует | M5 | missing | named in report | d2k_udp_plan_build/send из контроллера не перенесён |

### `core/verdict.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `looks_like_tls` | 33 | да | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 2 | `reverse_note` | 53 | да | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 3 | `pause_note` | 74 | да | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 4 | `stop_requested` | 92 | да | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 5 | `classify_cancelled` | 96 | да | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 6 | `d2k_classify_cancelable` | 104 |  | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |
| 7 | `d2k_classify` | 336 |  | classify.rs (API-only) | CL5 | not-applicable | named in report | в текущем d2kc не вызывается; production — detect/ |

### `core/verify.c` — 73

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `verify_now_ms` | 52 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 2 | `dns16` | 58 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 3 | `ech_dns_name` | 62 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 4 | `d2k_ech_resolve` | 90 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 5 | `find_hdr_end` | 193 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 6 | `find_eol` | 203 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 7 | `lower_ascii` | 210 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 8 | `span_eq_ascii_ci` | 214 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 9 | `has_cf_challenge` | 227 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 10 | `read13` | 273 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 11 | `read12` | 278 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 12 | `body_read_reason` | 298 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 13 | `body_say` | 304 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 14 | `body_feed` | 308 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 15 | `body_byte` | 317 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 16 | `body_exact` | 331 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 17 | `body_line` | 352 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 18 | `read_http_body` | 380 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 19 | `read_status_buf` | 457 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 20 | `read_status_rd` | 699 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 21 | `d2k_http_read_response` | 730 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 22 | `d2k_verify_probe` | 739 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 23 | `write13` | 750 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 24 | `write12` | 755 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 25 | `redirect_path` | 762 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 26 | `https_redirect_response` | 799 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 27 | `d2k_verify_budget_set` | 822 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 28 | `d2k_verify_budget_get` | 823 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 29 | `d2k_verify_tcp_timestamps_set` | 826 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 30 | `d2k_verify_tcp_timestamps_get` | 829 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 31 | `d2k_verify_quic_form_set` | 837 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 32 | `d2k_verify_tcp_data_packets` | 850 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 33 | `budget_say` | 877 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 34 | `gateway_header_end` | 885 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 35 | `gateway_header_value` | 892 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 36 | `gateway_connection_upgrade` | 905 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 37 | `gateway_json_hello` | 917 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 38 | `gateway_fill` | 976 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 39 | `request_gateway_websocket` | 1000 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 40 | `read_eof` | 1132 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 41 | `budget_tcp` | 1146 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 42 | `fd_peer_spoke` | 1217 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 43 | `fd_packets` | 1223 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 44 | `request_complete_page` | 1238 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 45 | `request_page_budget` | 1247 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 46 | `verify_contact` | 1349 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 47 | `verify_probe13_internal` | 1365 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 48 | `verify_probe13_on` | 1444 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 49 | `ech_http_denial` | 1451 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 50 | `d2k_verify_probe_ech_on` | 1462 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 51 | `d2k_verify_probe_ech_origin_on` | 1478 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 52 | `d2k_verify_replay_on` | 1499 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 53 | `d2k_verify_probe_on` | 1564 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 54 | `d2k_verify_probe_alpn_on` | 1578 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 55 | `verify_probe12_internal` | 1636 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 56 | `d2k_verify_probe12_on` | 1703 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 57 | `d2k_verify_probe_identity_on` | 1710 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 58 | `d2k_verify_probe_gzip_on` | 1717 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 59 | `d2k_verify_probe_baseline` | 1724 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 60 | `d2k_verify_probe_path_on` | 1744 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 61 | `d2k_verify_close` | 1759 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 62 | `d2k_verify_probe_quic` | 1768 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 63 | `quic_app_silent` | 1780 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 64 | `h3_read_headers` | 1799 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 65 | `quic_recv_chunk` | 1816 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 66 | `budget_quic` | 1836 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 67 | `qb_request` | 1953 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 68 | `qb_recv` | 1960 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 69 | `qb_progress` | 1964 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 70 | `qb_packets` | 1967 | да | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 71 | `d2k_verify_probe_quic_on` | 1975 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 72 | `d2k_verify_probe_quic_path_on` | 1983 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |
| 73 | `d2k_verify_probe_quic_path_mark_on` | 1991 |  | fetch.rs, response.rs, ech.rs, https_probe.rs | CL6/CL7/CL9/CL10 | partial | named in report | TLS/HTTP verifier; бюджет/QUIC частично |

### `core/verify_quic_replay.c` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `replay_now_ms` | 23 | да | quic_replay.rs, fetch.rs | Q2 | partial | named in report | replay verification |
| 2 | `d2k_verify_quic_replay_on` | 29 |  | quic_replay.rs, fetch.rs | Q2 | partial | named in report | replay verification |

### `core/voice.c` — 14

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `is_voice_port` | 42 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 2 | `field_val` | 65 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 3 | `d2k_voice_targets` | 84 |  | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 4 | `send_one` | 173 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 5 | `ms_since` | 205 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 6 | `voice_ask` | 214 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 7 | `voice_resolve` | 299 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 8 | `voice_blob_load` | 323 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 9 | `voice_alive` | 349 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 10 | `voice_ask_real` | 365 |  | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 11 | `voice_ask_arms` | 371 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 12 | `say_reason` | 403 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 13 | `add_reason` | 410 | да | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |
| 14 | `d2k_voice_run` | 434 |  | voice_measure.rs, voice_targets.rs | R2/R3 | partial | named in report | voice probe; raw arm отсутствует |

### `core/voice_discovery.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `nibble` | 16 | да | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 2 | `d2k_voice_discovery_prefix` | 22 |  | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 3 | `d2k_discovery_response` | 41 |  | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 4 | `milliseconds` | 49 | да | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 5 | `discovery_probe` | 54 | да | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 6 | `local_failure` | 102 | да | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |
| 7 | `d2k_voice_discovery_search` | 110 |  | voice_discovery.rs | R2 | partial | named in report | endpoint search/verdict |

### `core/volume.c` — 19

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rx_wire_partial` | 58 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 2 | `d2k_volume_rx_partial` | 66 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 3 | `d2k_volume_rx_pair_agrees` | 78 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 4 | `d2k_volume_rx_needs_repeat` | 103 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 5 | `d2k_volume_rx_evidence` | 111 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 6 | `d2k_vol_verdict_name` | 215 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 7 | `now_ms` | 224 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 8 | `nap_ms` | 230 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 9 | `clamp_ms` | 237 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 10 | `fill_pad` | 247 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 11 | `connect_bounded` | 259 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 12 | `drain_head_tls` | 325 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 13 | `drain_head_plain` | 351 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 14 | `resource_retry_path` | 393 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 15 | `rx_probe` | 411 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 16 | `measure_response_volume` | 440 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 17 | `probe_response_volume` | 558 | да | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 18 | `d2k_volume_probe_path` | 595 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |
| 19 | `d2k_volume_probe` | 729 |  | r2o_volume.rs, fetch.rs | CL15/M5 | partial | named in report | TX/RX/ladder; полного verdict differential нет |

### `core/x25519.c` — 11

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `car25519` | 32 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 2 | `sel25519` | 54 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 3 | `pack25519` | 63 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 4 | `unpack25519` | 84 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 5 | `A` | 91 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 6 | `Z` | 92 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 7 | `M` | 94 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 8 | `S` | 106 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 9 | `inv25519` | 109 | да | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 10 | `d2k_x25519` | 119 |  | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |
| 11 | `d2k_x25519_base` | 170 |  | hpke/rustls | CL15/M6 | partial | named in report | X25519; протокольные тесты |

### `datapath/addr.c` — 3

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_addr_parse` | 5 |  | r2k-core/addr.rs | D18 | partial | named in report | parse/text/equal |
| 2 | `d2k_addr_text` | 20 |  | r2k-core/addr.rs | D18 | partial | named in report | parse/text/equal |
| 3 | `d2k_addr_equal` | 32 |  | r2k-core/addr.rs | D18 | partial | named in report | parse/text/equal |

### `datapath/capture.c` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `same` | 4 | да | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |
| 2 | `d2k_capture_forget` | 8 |  | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |
| 3 | `reject` | 16 | да | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |
| 4 | `d2k_capture_feed_ready` | 22 |  | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |
| 5 | `tls_ready` | 109 | да | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |
| 6 | `d2k_capture_feed` | 119 |  | r2o-datapath/capture.rs | D12 | partial | named in report | TTL/generation/overlap/ready |

### `datapath/ctl.c` — 14

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `say` | 66 | да | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 2 | `set_nonblock` | 76 | да | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 3 | `d2k_ctl_open` | 81 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 4 | `d2k_ctl_close` | 129 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 5 | `d2k_ctl_listen_fd` | 143 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 6 | `d2k_ctl_peer_fd` | 144 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 7 | `d2k_ctl_set_disconnect_hook` | 146 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 8 | `d2k_ctl_accept` | 152 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 9 | `drop_peer` | 179 | да | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 10 | `d2k_ctl_flush` | 190 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 11 | `d2k_ctl_event` | 217 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 12 | `d2k_ctl_poll` | 257 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 13 | `d2k_ctl_dropped` | 315 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |
| 14 | `d2k_ctl_sent` | 316 |  | r2o-datapath/control.rs | S1/D17 | partial | named in report | accept/reconnect/ring 64K vs 128K |

### `datapath/ctlsrv.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `put_key` | 23 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 2 | `d2k_plan_fits` | 39 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 3 | `ack` | 84 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 4 | `ack_trial` | 112 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 5 | `d2k_ctlsrv_greet` | 125 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 6 | `d2k_ctlsrv_peer_closed` | 147 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 7 | `canonical_address` | 152 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 8 | `addr_shape_valid` | 163 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 9 | `read_probe_flow` | 169 | да | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 10 | `d2k_ctlsrv_command` | 189 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 11 | `d2k_ctlsrv_pump` | 511 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |
| 12 | `d2k_ctlsrv_http80_event` | 697 |  | control.rs, main.rs | S1/D18 | partial | named in report | commands/ACK/events; v22 vs v48 |

### `datapath/ctq.c` — 20

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `align4` | 16 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 2 | `wr16h` | 18 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 3 | `wr32h` | 19 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 4 | `rd16h` | 20 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 5 | `rd64be` | 21 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 6 | `rd32be` | 26 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 7 | `put` | 31 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 8 | `open_nest` | 43 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 9 | `close_nest` | 48 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 10 | `d2k_ct_get_req` | 52 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 11 | `counter` | 84 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 12 | `tcp_state` | 99 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 13 | `d2k_ct_info_parse` | 122 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 14 | `d2k_ct_counters_parse` | 158 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 15 | `d2k_ct_query_info_fd` | 169 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 16 | `d2k_ct_query_fd` | 188 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 17 | `reply_errno` | 201 | да | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 18 | `d2k_ct_probe_fd` | 214 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 19 | `d2k_ct_open` | 243 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |
| 20 | `d2k_ct_open` | 255 |  | conntrack.rs | D13 | partial | named in report | ctnetlink query/probe |

### `datapath/d2kd.c` — 44

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `on_signal` | 62 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 2 | `self_cost` | 68 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 3 | `now_ns` | 112 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 4 | `tls_route_segment_cap` | 123 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `count_reason` | 165 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 6 | `icmp_step` | 220 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 7 | `log_send_fail` | 253 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 8 | `routes_routed` | 278 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 9 | `describe_oifs` | 282 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 10 | `routes_refresh` | 302 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `cap_refresh` | 372 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 12 | `send_original_verdict` | 417 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 13 | `send_delayed_verdict` | 429 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 14 | `delayed_verdict_done` | 433 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 15 | `hold_owns` | 484 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 16 | `resend_original` | 493 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 17 | `resend_originals` | 510 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 18 | `release_original` | 518 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 19 | `ct_query` | 561 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 20 | `ct_probe` | 578 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 21 | `out_verdict` | 597 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 22 | `out_fail` | 603 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 23 | `out_marked` | 615 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 24 | `out_defer` | 640 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 25 | `out_resend_failed` | 651 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 26 | `out_send_now` | 673 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 27 | `out_send_at` | 686 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 28 | `out_send_at_owned` | 699 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 29 | `http80_log` | 717 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 30 | `http80_io_payload` | 733 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 31 | `http80_io_accept` | 745 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 32 | `http80_io_rst` | 757 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 33 | `http80_cut` | 776 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 34 | `http80_step` | 786 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 35 | `usage` | 834 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 36 | `arg_u32` | 863 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 37 | `port_of` | 873 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 38 | `print_stats` | 878 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 39 | `proto_name` | 1039 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 40 | `jrn_kind` | 1050 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 41 | `print_journal` | 1070 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 42 | `refuse_of_errno` | 1114 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 43 | `offline_self_check` | 1118 | да | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |
| 44 | `main` | 1125 |  | r2o-datapath/main.rs | D1a/D1b/D2/D3/D4/D5 | partial | named in report | daemon loop/CLI/stats/health |

### `datapath/hold.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `r32` | 17 | да | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 2 | `same` | 18 | да | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 3 | `d2k_hold_parse` | 21 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 4 | `d2k_hold_new` | 41 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 5 | `d2k_hold_free` | 42 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 6 | `release_slot` | 43 | да | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 7 | `d2k_hold_flush` | 52 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 8 | `d2k_hold_next` | 73 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 9 | `d2k_hold_get_stats` | 81 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 10 | `d2k_hold_verdicts` | 85 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 11 | `http_ready` | 93 | да | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |
| 12 | `d2k_hold_feed` | 101 |  | r2o-datapath/hold.rs | D6/D7 | partial | named in report | FIFO/limits/flags/ack/startup |

### `datapath/http80.c` — 30

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_http80_new` | 67 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 2 | `d2k_http80_free` | 71 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `d2k_http80_get_stats` | 75 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 4 | `name_norm` | 83 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 5 | `d2k_http80_set_https` | 97 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 6 | `d2k_http80_https` | 120 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 7 | `wr16` | 133 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 8 | `wr32` | 134 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 9 | `sum16` | 138 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 10 | `fold` | 144 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 11 | `build` | 156 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 12 | `rd32` | 190 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 13 | `stale` | 196 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 14 | `find` | 200 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 15 | `make` | 217 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 16 | `d2k_http80_executed` | 238 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 17 | `request_result` | 256 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 18 | `d2k_http80_delivered` | 267 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 19 | `seq_after` | 281 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 20 | `delivered` | 285 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 21 | `cut_pending` | 289 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 22 | `cut_result` | 295 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 23 | `d2k_http80_sweep` | 305 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 24 | `request_prefix` | 327 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 25 | `request_feed` | 342 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 26 | `d2k_http80_packet` | 349 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 27 | `d2k_http80_swap` | 527 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 28 | `lc` | 549 | да | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 29 | `d2k_http_request` | 551 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |
| 30 | `d2k_http_hello` | 634 |  | http_replace.rs, hold.rs, r2k-core/httpup.rs | D17 | partial | named in report | HTTP80 заменён частично; stats/trace нет |

### `datapath/http_trace.c` — 1

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_http_trace` | 9 |  | — | D17 | missing | named in report | текстовой трассы нет |

### `datapath/icmpguard.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_icmpguard_init` | 6 |  | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 2 | `u16` | 10 | да | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 3 | `parse_ip` | 21 | да | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 4 | `d2k_icmpguard_note` | 49 |  | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 5 | `d2k_icmpguard_check` | 71 |  | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 6 | `d2k_icmpguard_dropped` | 112 |  | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |
| 7 | `d2k_icmpguard_noted` | 113 |  | r2o_icmp_guard.rs | D15 | partial | named in report | ICMP quote/summary |

### `datapath/include/d2k_ctl.h` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_ctl_binding_write` | 86 | да | r2k-core/control.rs | S1 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_ctl_binding_read` | 91 | да | r2k-core/control.rs | S1 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `datapath/include/d2k_http_request_stream.h` — 3

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_http_request_stream_init` | 19 | да | r2k-core/httpup.rs | CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_http_request_stream_line` | 22 | да | r2k-core/httpup.rs | CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_http_request_stream_feed` | 31 | да | r2k-core/httpup.rs | CL14 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `datapath/include/d2k_http_response.h` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_hr_decimal` | 21 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_hr_token` | 31 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_hr_field` | 35 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 4 | `d2k_hr_extensions` | 43 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 5 | `d2k_hr_headers` | 72 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 6 | `d2k_http_response_feed` | 107 | да | r2k-core/http_response.rs | CL11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `datapath/include/d2k_packet.h` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_packet_u16` | 20 | да | r2k-core/packet.rs | D18 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_packet_parse` | 24 | да | r2k-core/packet.rs | D18 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `datapath/include/d2k_plans.h` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_binding_known` | 98 | да | r2o-datapath/control.rs | D16 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_binding_equal` | 103 | да | r2o-datapath/control.rs | D16 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `datapath/include/d2k_track.h` — 1

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_key_equal` | 76 | да | r2o-datapath/engine.rs | D10 | partial | named in report | key equality |

### `datapath/journal.c` — 14

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_journal_new` | 16 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 2 | `d2k_journal_free` | 33 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 3 | `d2k_suspect_text` | 41 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 4 | `d2k_refuse_text` | 55 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 5 | `add_entry` | 76 | да | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 6 | `d2k_journal_add` | 132 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 7 | `d2k_journal_add_applied` | 139 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 8 | `d2k_journal_add_refused` | 151 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 9 | `d2k_journal_add_fate_bound` | 160 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 10 | `d2k_journal_add_fate` | 178 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 11 | `d2k_journal_count` | 184 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 12 | `d2k_journal_at` | 188 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 13 | `d2k_journal_dropped` | 198 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |
| 14 | `d2k_journal_added` | 202 |  | flow_journal.rs | D22 | partial | named in report | ring/retention/format |

### `datapath/nat.c` — 5

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `parse_ip4` | 20 | да | proc_nat.rs | D13 | partial | named in report | NAT outside |
| 2 | `field_after` | 46 | да | proc_nat.rs | D13 | partial | named in report | NAT outside |
| 3 | `d2k_nat_outside` | 67 |  | proc_nat.rs | D13 | partial | named in report | NAT outside |
| 4 | `parse_address` | 75 | да | proc_nat.rs | D13 | partial | named in report | NAT outside |
| 5 | `d2k_nat_outside_family` | 84 |  | proc_nat.rs | D13 | partial | named in report | NAT outside |

### `datapath/nfq.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `say` | 33 | да | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 2 | `nl_write` | 43 | да | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 3 | `await_ack` | 61 | да | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 4 | `send_and_ack` | 111 | да | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 5 | `set_rcvbuf` | 127 | да | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 6 | `d2k_nfq_open` | 147 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 7 | `d2k_nfq_close` | 232 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 8 | `d2k_nfq_fd` | 250 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 9 | `d2k_nfq_recv` | 254 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 10 | `d2k_nfq_verdict` | 276 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 11 | `d2k_nfq_verdict_payload` | 294 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |
| 12 | `d2k_nfq_lost` | 313 |  | nfqueue.rs | D1a/D1b/D2 | partial | named in report | AF_INET only C; recv/rcvbuf |

### `datapath/nl.c` — 19

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `align4` | 10 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 2 | `h16` | 16 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 3 | `h32` | 17 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 4 | `wh16` | 18 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 5 | `wh32` | 19 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 6 | `n16` | 22 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 7 | `n32` | 25 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 8 | `wn16` | 29 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 9 | `wn32` | 32 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 10 | `d2k_nl_iter_init` | 37 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 11 | `d2k_nl_next` | 45 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 12 | `d2k_nl_packet` | 79 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 13 | `d2k_nl_errno` | 163 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 14 | `hdr_init` | 181 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 15 | `put_attr` | 200 | да | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 16 | `d2k_nl_verdict` | 218 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 17 | `d2k_nl_verdict_payload` | 236 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 18 | `d2k_nl_cfg_cmd` | 254 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |
| 19 | `d2k_nl_cfg_params` | 275 |  | netlink.rs | D1a/D1b/D2 | partial | named in report | netlink parse/build |

### `datapath/plan_apply.c` — 15

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `anchor_offset` | 26 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 2 | `cmp_size` | 82 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 3 | `split_points` | 90 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 4 | `tls_ch_layout` | 120 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 5 | `random_bytes` | 156 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 6 | `wr16` | 165 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 7 | `wr24` | 168 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 8 | `fake_tls_bytes` | 173 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 9 | `emit_fake` | 239 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 10 | `emit_vec_free` | 268 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 11 | `emit_overhead` | 285 | да | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 12 | `d2k_plan_max_emit` | 297 |  | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 13 | `d2k_plan_apply` | 343 |  | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 14 | `d2k_actions_cancel` | 891 |  | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |
| 15 | `d2k_actions_free` | 923 |  | r2k-core/plan/apply.rs | D14/D15 | partial | named in report | ts_up отсутствует |

### `datapath/plan_parse.c` — 17

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16` | 23 | да | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 2 | `rd32` | 27 | да | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 3 | `fail` | 32 | да | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 4 | `scan` | 45 | да | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 5 | `check_refs` | 224 | да | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 6 | `d2k_find_payload` | 327 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 7 | `d2k_find_poison` | 336 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 8 | `d2k_plan_load` | 345 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 9 | `d2k_plan_free` | 568 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 10 | `d2k_plan_poison_used` | 583 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 11 | `d2k_plan_flow_needs` | 594 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 12 | `d2k_plan_quic_deny` | 601 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 13 | `d2k_plan_guards` | 605 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 14 | `d2k_plan_transport` | 609 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 15 | `d2k_plan_proto` | 613 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 16 | `d2k_plan_stream_input` | 617 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |
| 17 | `d2k_plan_id` | 623 |  | r2k-core/plan.rs | D14 | partial | named in report | D2KP vs R2OP |

### `datapath/plans.c` — 75

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `bind_context` | 94 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 2 | `d2k_plantab_new` | 104 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 3 | `d2k_plantab_free` | 132 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `name_eq` | 154 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 5 | `shape_transport` | 169 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 6 | `area_name_valid` | 177 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 7 | `suffix_member` | 193 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 8 | `area_exact` | 199 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 9 | `area_set` | 209 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 10 | `d2k_plantab_set_suffix_family` | 228 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 11 | `d2k_plantab_set_bypass_family` | 239 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 12 | `area_del` | 246 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 13 | `d2k_plantab_del_suffix_family` | 255 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `d2k_plantab_del_bypass_family` | 260 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `area_bypassed` | 265 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 16 | `area_match` | 275 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 17 | `d2k_plantab_revision` | 286 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 18 | `d2k_plantab_has_ech_target` | 288 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 19 | `d2k_plantab_stream_candidate` | 316 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 20 | `d2k_plantab_stream_candidate_family` | 321 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `d2k_plantab_stream_candidate_target` | 327 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `find_name_skip` | 357 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 23 | `find_name` | 369 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 24 | `find_name_shape_port` | 385 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 25 | `find_name_port` | 401 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 26 | `d2k_plantab_http_candidate` | 414 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 27 | `d2k_plantab_find_http` | 424 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `find_addr_shape` | 439 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 29 | `find_addr` | 452 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 30 | `modern_shape_for_ech` | 465 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 31 | `scan_name` | 471 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 32 | `scan_addr` | 488 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 33 | `oldest` | 518 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 34 | `take_free_or_evict` | 541 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 35 | `d2k_plantab_set_name_shaped` | 571 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 36 | `d2k_plantab_set_name_probe` | 576 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 37 | `probe_transport` | 584 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 38 | `d2k_plantab_set_name_family` | 590 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 39 | `d2k_plantab_set_name` | 672 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 40 | `d2k_plantab_set_addr` | 678 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 41 | `d2k_plantab_set_addr_family` | 686 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 42 | `d2k_plantab_set_addr_shaped` | 692 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 43 | `drop` | 728 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 44 | `d2k_plantab_del_name` | 743 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 45 | `d2k_plantab_del_name_family` | 747 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 46 | `d2k_plantab_del_name_shaped` | 773 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 47 | `d2k_plantab_del_name_bound` | 792 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 48 | `d2k_plantab_del_name_probe` | 808 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 49 | `d2k_plantab_del_name_probe_family` | 813 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 50 | `d2k_plantab_del_addr` | 830 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 51 | `d2k_plantab_del_addr_family` | 837 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 52 | `d2k_plantab_del_addr_shaped` | 844 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 53 | `trial_id_valid` | 850 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 54 | `probe_flow_valid` | 860 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 55 | `probe_flow_equal` | 876 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 56 | `probe_drop` | 889 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 57 | `d2k_plantab_clear_probes` | 897 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 58 | `d2k_plantab_set_addr_probe` | 912 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 59 | `d2k_plantab_del_addr_probe` | 963 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 60 | `find_probe` | 978 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 61 | `d2k_plantab_find_addr_probe` | 1008 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 62 | `d2k_plantab_find_voice_probe` | 1014 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 63 | `d2k_plantab_probe_count` | 1020 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 64 | `shape_fits` | 1044 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 65 | `shape_is_udp` | 1054 | да | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 66 | `d2k_plantab_shape_misses` | 1058 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 67 | `d2k_plantab_find` | 1062 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 68 | `d2k_plantab_find_sport` | 1068 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 69 | `d2k_plantab_find_family` | 1074 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 70 | `d2k_plantab_find_target` | 1081 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 71 | `d2k_plantab_count` | 1238 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | partial | named in report | capacity 2048/LRU vs 128/64 |
| 72 | `d2k_plantab_capacity` | 1242 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 73 | `d2k_plantab_binding` | 1246 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 74 | `d2k_plantab_set_name_trial` | 1259 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |
| 75 | `d2k_plantab_trial` | 1268 |  | r2o-datapath/control.rs, r2k-core/plan.rs | D16 | implemented-unproven | module-level only | helper; module-level only |

### `datapath/raw.c` — 17

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `if_mtu` | 64 | да | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 2 | `pick_maxlen` | 92 | да | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 3 | `route_mtu` | 140 | да | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 4 | `say` | 181 | да | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 5 | `d2k_raw_open` | 193 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 6 | `d2k_raw_close` | 258 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 7 | `d2k_raw_limits` | 271 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 8 | `d2k_raw_maxlen` | 275 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 9 | `d2k_raw_adopt_egress` | 281 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 10 | `blend` | 306 | да | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 11 | `d2k_raw_route_maxlen` | 311 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 12 | `d2k_raw_route_maxlen_family` | 315 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 13 | `d2k_raw_prepare` | 341 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 14 | `d2k_raw_send` | 406 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 15 | `d2k_raw_sent` | 514 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 16 | `d2k_raw_errors` | 518 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |
| 17 | `d2k_raw_busy` | 522 |  | r2o-datapath/raw.rs | D19 | partial | named in report | raw send/MTU; IPv6 NDP нет |

### `datapath/routemark.c` — 23

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16h` | 27 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 2 | `rd32h` | 28 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 3 | `wr16h` | 29 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 4 | `wr32h` | 30 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 5 | `d2k_routemark_init` | 32 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 6 | `d2k_routemark_request` | 36 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 7 | `nl_error` | 49 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 8 | `d2k_routemark_parse` | 53 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 9 | `d2k_routemark_lookup_request` | 103 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 10 | `add_oif` | 122 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 11 | `route_oifs` | 132 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 12 | `d2k_routemark_lookup_parse` | 154 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 13 | `d2k_routemark_watch_relevant` | 175 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 14 | `d2k_routemark_clear_oifs` | 192 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 15 | `d2k_routemark_set_oifs` | 201 |  | r2o_route.rs | D20 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `d2k_routemark_set` | 215 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 17 | `d2k_routemark_merge` | 229 |  | r2o_route.rs | D20 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `d2k_routemark_set_policy` | 269 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 19 | `policy_match` | 277 | да | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 20 | `d2k_routemark_routed` | 282 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 21 | `d2k_routemark_client` | 298 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 22 | `d2k_routemark_gate` | 304 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |
| 23 | `d2k_routemark_describe` | 327 |  | r2o_route.rs | D20 | partial | named in report | route mark/gate |

### `datapath/routemark_nl.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `parse_rules` | 18 | да | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 2 | `dump` | 27 | да | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 3 | `dump_rules` | 61 | да | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 4 | `lookup_route` | 72 | да | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 5 | `dump_socket` | 115 | да | r2o_route.rs | D20 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `d2k_routemark_load` | 130 |  | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 7 | `d2k_routemark_watch_open` | 179 |  | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |
| 8 | `d2k_routemark_watch_drain` | 211 |  | r2o_route.rs | D20 | partial | named in report | netlink rules/lookup |

### `datapath/sched.c` — 16

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_sched_new` | 43 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 2 | `d2k_sched_grow_slot_size` | 73 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 3 | `d2k_sched_free` | 90 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 4 | `earlier` | 102 | да | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 5 | `sift_up` | 109 | да | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 6 | `sift_down` | 122 | да | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 7 | `d2k_sched_push` | 141 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 8 | `d2k_sched_push_serial` | 149 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 9 | `d2k_sched_push_owned` | 154 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 10 | `push` | 159 | да | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 11 | `d2k_sched_pop_due` | 192 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 12 | `d2k_sched_pop_due_serial` | 198 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 13 | `d2k_sched_pop_due_ex` | 204 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 14 | `d2k_sched_next_ns` | 269 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 15 | `d2k_sched_count` | 273 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |
| 16 | `d2k_sched_refusals` | 277 |  | scheduler.rs | D21 | partial | named in report | due ordering/refusals |

### `datapath/session.c` — 107

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `initial_dcid` | 202 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 2 | `init_ring_add` | 215 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 3 | `init_ring_drop` | 239 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 4 | `init_ring_pack` | 253 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 5 | `slot_of` | 288 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 6 | `shape_slot` | 289 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 7 | `next_fragment_id` | 293 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 8 | `d2k_session_new` | 306 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 9 | `d2k_session_free` | 346 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 10 | `d2k_session_set_plan` | 358 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 11 | `name_same` | 369 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 12 | `rd16` | 384 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 13 | `refuse_coded` | 402 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 14 | `refuse` | 415 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 15 | `tcp_options_timestamp_profile` | 422 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 16 | `tcp_options_have_timestamp` | 435 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 17 | `plan_handed_off` | 446 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 18 | `table_of` | 477 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 19 | `suspect_num` | 486 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 20 | `suspect` | 505 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 21 | `on_flow_expire` | 521 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 22 | `rd32` | 532 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 23 | `is_discord_ip_discovery` | 544 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 24 | `is_discord_ip_discovery_response` | 552 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `is_stun_binding` | 569 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `is_stun_request` | 580 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `is_stun_response_for` | 584 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `d2k_session_nat_stats` | 650 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 29 | `plan_fits_transport` | 672 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 30 | `flow_tracked` | 678 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 31 | `handle_udp` | 779 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 32 | `note_tcp_hello` | 1573 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 33 | `routed_flow` | 1593 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 34 | `session_packet` | 1628 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 35 | `d2k_session_packet` | 2603 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 36 | `d2k_session_packet_mtu` | 2608 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 37 | `d2k_session_packet_probe` | 2615 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 38 | `d2k_session_packet_probe_mtu` | 2621 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 39 | `d2k_session_observe_tcp` | 2628 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 40 | `d2k_session_plan_revision` | 2633 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 41 | `d2k_session_stream_anchor` | 2637 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 42 | `d2k_session_set_hook` | 2647 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 43 | `d2k_session_set_route_mark` | 2651 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 44 | `d2k_session_route_mark` | 2655 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 45 | `d2k_session_routed_flows` | 2659 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 46 | `d2k_session_set_udp_reverse_hook` | 2663 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 47 | `d2k_session_set_ct_query` | 2667 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 48 | `d2k_session_udp_hold_begin` | 2671 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 49 | `d2k_session_udp_opening` | 2713 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 50 | `d2k_session_udp_hold_end` | 2738 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 51 | `d2k_session_udp_hold_replay` | 2744 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 52 | `d2k_session_note_unassembled` | 2753 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 53 | `d2k_session_hold_candidate` | 2794 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 54 | `d2k_session_want_shape` | 2926 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 55 | `d2k_session_want_shape_family` | 2931 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 56 | `d2k_session_shape` | 2962 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 57 | `d2k_session_shape_family` | 2966 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 58 | `d2k_session_shape_tcp_options_family` | 2982 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 59 | `d2k_session_plans` | 2992 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 60 | `d2k_session_plan_count` | 2996 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 61 | `d2k_session_plan_capacity` | 3000 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 62 | `silence_deadline` | 3018 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 63 | `tcp_silence_observe` | 3034 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 64 | `fin_retry_window` | 3063 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 65 | `fin_window_over` | 3069 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 66 | `sweep_one` | 3084 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 67 | `sweep_udp_one` | 3112 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 68 | `quic_watch` | 3164 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 69 | `flow_tuple` | 3174 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 70 | `ct_flow` | 3197 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 71 | `tcp_watch` | 3257 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 72 | `tcp_in_band` | 3263 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 73 | `tcp_band_top` | 3271 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 74 | `ct_tcp_flow` | 3279 | да | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 75 | `d2k_session_set_stall_budgets` | 3330 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 76 | `d2k_session_stall_budgets` | 3345 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 77 | `d2k_session_sweep` | 3353 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 78 | `d2k_session_expire` | 3372 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 79 | `d2k_session_flows` | 3397 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 80 | `d2k_session_send_pending` | 3401 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 81 | `d2k_session_sent` | 3407 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 82 | `d2k_session_exec_failed` | 3449 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 83 | `d2k_session_guards` | 3503 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 84 | `d2k_session_client_shape` | 3509 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 85 | `d2k_session_damaged` | 3515 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 86 | `d2k_session_unsent` | 3525 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 87 | `d2k_session_applied` | 3541 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 88 | `d2k_session_done` | 3545 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 89 | `d2k_session_damaged_count` | 3549 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 90 | `d2k_session_sent_lost` | 3553 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 91 | `d2k_session_refusals` | 3557 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 92 | `d2k_session_capacity` | 3561 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 93 | `d2k_session_flows_tcp` | 3565 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 94 | `d2k_session_flows_udp` | 3569 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 95 | `d2k_session_capacity_tcp` | 3573 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 96 | `d2k_session_capacity_udp` | 3577 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 97 | `d2k_session_refusals_tcp` | 3581 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 98 | `d2k_session_refusals_udp` | 3585 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 99 | `d2k_session_hellos` | 3589 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 100 | `d2k_session_with_sni` | 3593 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 101 | `d2k_session_suspects` | 3597 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 102 | `d2k_session_rst_dropped` | 3601 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 103 | `d2k_session_exchanges` | 3605 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | partial | named in report | full session_packet/handle_udp differential нет |
| 104 | `d2k_session_reply_hidden` | 3609 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 105 | `d2k_session_tcp_hello_flows` | 3613 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 106 | `d2k_session_payload_stats` | 3617 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |
| 107 | `d2k_session_journal` | 3640 |  | engine.rs, hold.rs, r2o_udp_sessions.rs, r2o_quic.rs, r2o_voice.rs | D6-D11 | implemented-unproven | module-level only | helper; module-level only |

### `datapath/tls.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rd16` | 30 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 2 | `skip_u8_vec` | 36 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 3 | `skip_u16_vec` | 48 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 4 | `has_ech_offer` | 72 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 5 | `has_tls13` | 105 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 6 | `find_sni` | 131 | да | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |
| 7 | `d2k_tls_parse` | 179 |  | r2k-core/tls.rs | D12 | partial | named in report | ClientHello parse |

### `datapath/track.c` — 18

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_key_make` | 18 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `d2k_key_make_addr` | 55 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `round_pow2` | 84 | да | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `key_eq` | 92 | да | engine.rs, flow_capacity.rs | D10 | partial | named in report | capacity differential (304 pin) |
| 5 | `key_hash` | 108 | да | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `d2k_track_new` | 117 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `d2k_track_free` | 135 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `d2k_track_find` | 144 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `remove_at` | 165 | да | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `d2k_track_get` | 193 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `d2k_track_new_connection` | 231 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `d2k_track_remove` | 259 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `d2k_track_walk` | 269 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `d2k_track_expire` | 280 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `d2k_track_remove_if` | 310 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `d2k_track_count` | 327 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `d2k_track_capacity` | 331 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `d2k_track_refusals` | 335 |  | engine.rs, flow_capacity.rs | D10 | implemented-unproven | module-level only | helper; module-level only |

### `datapath/udp_hold.c` — 10

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `same_key` | 14 | да | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 2 | `clear_slot` | 18 | да | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 3 | `release_slot` | 22 | да | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 4 | `d2k_udp_hold_new` | 31 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 5 | `d2k_udp_hold_free` | 33 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 6 | `d2k_udp_hold_flush` | 41 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 7 | `d2k_udp_hold_feed` | 54 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 8 | `d2k_udp_hold_feed_marked` | 60 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 9 | `d2k_udp_hold_take` | 98 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |
| 10 | `d2k_udp_hold_next_ns` | 115 |  | r2o_udp_hold.rs | D8 | partial | named in report | slots/expiry/overflow |

### `datapath/udp_path.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_udp_path_release` | 6 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 2 | `d2k_udp_path_pre` | 15 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 3 | `d2k_udp_path_post` | 35 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 4 | `d2k_udp_path_read` | 62 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 5 | `d2k_udp_path_expire` | 69 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 6 | `d2k_udp_path_passed` | 76 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |
| 7 | `d2k_udp_path_planned` | 90 |  | main.rs, r2o_udp_hold.rs | D9 | partial | named in report | pre/post/expire |

### `datapath/udp_release.c` — 34

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_udp_release_new` | 29 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 2 | `d2k_udp_release_free` | 53 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `d2k_udp_release_enqueue` | 61 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `next_due` | 83 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 5 | `d2k_udp_release_flush` | 96 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `d2k_udp_release_next_ns` | 124 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `d2k_udp_replay_fates` | 135 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 8 | `plain_verdict` | 174 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 9 | `plain_resend` | 178 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 10 | `d2k_udp_release_batch` | 184 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 11 | `release_batch` | 194 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 12 | `follow_stale` | 272 | да | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `follow_drop` | 277 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 14 | `d2k_udp_follow_age` | 282 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 15 | `d2k_udp_follow_live` | 289 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `d2k_udp_follow_busy` | 290 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `d2k_udp_follow_queue_full` | 291 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `d2k_udp_follow_refused` | 292 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `d2k_udp_send_busy` | 294 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 20 | `d2k_udp_follow_new` | 298 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 21 | `d2k_udp_follow_free` | 300 |  | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `follow_tuple` | 302 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 23 | `same_tuple` | 321 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 24 | `d2k_udp_follow_mark` | 329 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 25 | `follow_put` | 334 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 26 | `follow_find` | 357 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 27 | `d2k_udp_follow_match` | 372 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 28 | `out_resend` | 388 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 29 | `d2k_udp_out_owned_emit` | 417 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 30 | `refused_flow` | 425 | да | r2o_udp_hold.rs | D9 | implemented-unproven | module-level only | helper; module-level only |
| 31 | `out_verdict` | 432 | да | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 32 | `d2k_udp_out_neutral` | 437 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 33 | `d2k_udp_out_batch` | 442 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |
| 34 | `d2k_udp_out_late` | 475 |  | r2o_udp_hold.rs | D9 | partial | named in report | deferred verdicts/follow |

### `datapath/wire.c` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `wr16` | 23 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 2 | `wr32` | 28 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 3 | `rd16` | 35 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 4 | `auto_ttl` | 54 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 5 | `sum16` | 73 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 6 | `fold` | 84 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 7 | `pseudo_sum` | 99 | да | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 8 | `d2k_wire_build` | 109 |  | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |
| 9 | `d2k_wire_tcp_checksum_ok` | 279 |  | r2k-core/wire.rs | D13 | partial | named in report | ts_up отсутствует |

### `datapath/wire_udp.c` — 5

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `wr16` | 22 | да | r2k-core/wire.rs | D3/D13 | partial | named in report | UDP/fragment build |
| 2 | `sum16` | 31 | да | r2k-core/wire.rs | D3/D13 | partial | named in report | UDP/fragment build |
| 3 | `fold` | 42 | да | r2k-core/wire.rs | D3/D13 | partial | named in report | UDP/fragment build |
| 4 | `pseudo_sum` | 57 | да | r2k-core/wire.rs | D3/D13 | partial | named in report | UDP/fragment build |
| 5 | `d2k_wire_build_udp` | 67 |  | r2k-core/wire.rs | D3/D13 | partial | named in report | UDP/fragment build |

### `detect/bridge.c` — 17

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_detect_stop_all` | 45 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 2 | `stop_asked` | 50 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 3 | `plannable_hit` | 76 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 4 | `map_verdict` | 95 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 5 | `bridge_input` | 116 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 6 | `progress_seen` | 261 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 7 | `trace_questions` | 284 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 8 | `retry_base_timeout` | 314 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 9 | `sched_tcp` | 320 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 10 | `d2k_detect_sched_tcp` | 466 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 11 | `d2k_detect_sched_tcp_white` | 478 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `d2k_detect_sched_tcp_seeded` | 488 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `d2k_detect_sched_tcp_seeded_white` | 503 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `base_seen` | 531 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 15 | `base_stop` | 537 | да | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 16 | `d2k_detect_sched_tcp_ack` | 548 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |
| 17 | `d2k_detect_sched_tcp_base` | 575 |  | classify.rs, discovery.rs, raw_probe.rs, main.rs | CL5 | partial | named in report | bridge/split/clone/decoy |

### `detect/classify.c` — 36

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_verdict_name` | 57 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 2 | `d2k_resp_name` | 74 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 3 | `d2k_now_ms` | 86 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 4 | `d2k_sleep_ms` | 96 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 5 | `d2k_trigger_accepts` | 109 |  | r2o-controller/classify.rs | CL5 | equivalent (scoped) | named in report | full-tree/control differential (scoped) |
| 6 | `d2k_trigger_sni` | 126 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 7 | `d2k_detect_stopped` | 136 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 8 | `d2k_opts_defaults` | 141 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 9 | `d2k_opts_acceptable` | 164 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 10 | `d2k_opts_skipped` | 172 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 11 | `d2k_trace_add` | 183 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 12 | `obs_done` | 210 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 13 | `d2k_note` | 217 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 14 | `note_gap_loss` | 238 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 15 | `d2k_split_offsets` | 253 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 16 | `dial_marked_mode` | 292 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 17 | `d2k_dial_deadline_err` | 368 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 18 | `dial_marked` | 376 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 19 | `once_probe` | 385 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 20 | `unacked_bytes` | 499 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 21 | `d2k_probe_data_ack` | 520 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 22 | `measure` | 608 | да | r2o-controller/classify.rs | CL5 | equivalent (scoped) | named in report | full-tree/control differential (scoped) |
| 23 | `bind_decoy` | 717 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 24 | `answered_by_props` | 732 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 25 | `fam_ix` | 766 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 26 | `self_ix` | 769 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 27 | `selftest_cached_age` | 774 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 28 | `selftest_store` | 791 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 29 | `d2k_raw_note_rc` | 801 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 30 | `raw_selftest` | 827 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 31 | `raw_doubted` | 860 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 32 | `raw_recheck` | 867 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 33 | `sweep_poisons` | 887 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 34 | `cross_check_tls12` | 1084 | да | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 35 | `d2k_classify_run` | 1095 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |
| 36 | `d2k_send_nosig` | 1481 |  | r2o-controller/classify.rs | CL5 | partial | named in report | full-tree/control differential (scoped) |

### `detect/include/d2k_detect.h` — 1

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_prop_majority` | 490 | да | r2o-controller/classify.rs | CL5 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `detect/main.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `usage` | 19 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 2 | `print_json_str` | 51 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 3 | `print_tri` | 67 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 4 | `print_json` | 75 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 5 | `print_progress` | 193 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 6 | `tri_word` | 201 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 7 | `print_human` | 207 | да | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |
| 8 | `main` | 277 |  | r2o-controller/main.rs CLI | CL16 | partial | named in report | stdout/exit/JSON не полностью |

### `detect/poison.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_poison_supports_family` | 17 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 2 | `d2k_poison_has_fake` | 24 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 3 | `add` | 47 | да | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 4 | `d2k_poison_same` | 62 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 5 | `already_listed` | 73 | да | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 6 | `init_poisons` | 84 | да | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 7 | `d2k_poisons` | 182 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 8 | `d2k_note_props_hit` | 194 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 9 | `d2k_note_props_miss` | 216 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 10 | `d2k_strategy_for_poison` | 226 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 11 | `d2k_strategy_for` | 401 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |
| 12 | `d2k_arm_from_poison` | 413 |  | classify.rs, raw_probe.rs, classify_measured.rs | CL5 | partial | named in report | 85 poison; strategy_for отсутствует |

### `detect/props.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `prop_probes` | 49 | да | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 2 | `apply_set` | 198 | да | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 3 | `d2k_run_properties` | 261 |  | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 4 | `d2k_run_properties_family` | 267 |  | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 5 | `tri_no` | 418 | да | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 6 | `tri_yes` | 419 | да | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |
| 7 | `d2k_compose_from_props` | 426 |  | classify.rs, raw_probe.rs | CL5 | partial | named in report | 12 questions/compose |

### `detect/raw.c` — 62

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `parse_long_exact` | 63 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 2 | `d2k_parse_rst_rule` | 79 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 3 | `d2k_parse_stale_rst_rule` | 121 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 4 | `pid_alive` | 128 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 5 | `d2k_rst_rule_stale` | 137 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 6 | `d2k_raw_supported` | 164 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 7 | `raw_rule_system` | 224 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 8 | `d2k_raw_rst_fail_count` | 262 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 9 | `d2k_raw_dial_count` | 263 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 10 | `seed_init` | 265 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 11 | `seed_once` | 271 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 12 | `next_source_port` | 283 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 13 | `rst_nft` | 313 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 14 | `sweep_stale_rst_rules` | 319 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 15 | `rst_rule_cmd_form` | 382 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 16 | `rst_rule_cmd` | 402 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 17 | `rc_exit1` | 407 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 18 | `rst_delete_once` | 416 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 19 | `rst_abandon` | 424 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 20 | `register_atexit` | 437 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 21 | `rst_remember` | 440 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 22 | `retry_pending_releases` | 454 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 23 | `rst_release_locked` | 471 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 24 | `d2k_raw_flush_pending` | 481 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 25 | `d2k_raw_pending_count` | 488 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 26 | `raw_atexit` | 497 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 27 | `rst_key_of` | 506 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 28 | `suppress_kernel_rst` | 517 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 29 | `release_kernel_rst` | 547 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 30 | `local_addr_for` | 556 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 31 | `rd16` | 598 | да | r2o-controller/raw_probe.rs | CL1 | equivalent (scoped) | named in report | profile/emission/cancel differential (scoped) |
| 32 | `rd32` | 600 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 33 | `wr16` | 606 | да | r2o-controller/raw_probe.rs | CL1 | equivalent (scoped) | named in report | profile/emission/cancel differential (scoped) |
| 34 | `wr32` | 608 | да | r2o-controller/raw_probe.rs | CL1 | equivalent (scoped) | named in report | profile/emission/cancel differential (scoped) |
| 35 | `checksum` | 614 | да | r2o-controller/raw_probe.rs | CL1 | equivalent (scoped) | named in report | profile/emission/cancel differential (scoped) |
| 36 | `tcp_checksum` | 630 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 37 | `build_ipv4_tcp` | 652 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 38 | `tcp_checksum_family` | 738 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 39 | `build_ip_tcp` | 750 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 40 | `raw_sendto` | 773 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 41 | `d2k_raw_set_segment_max` | 814 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 42 | `raw_send` | 830 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 43 | `raw_send_syn` | 864 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 44 | `raw_recv` | 900 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 45 | `raw_read_payload` | 952 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 46 | `raw_close` | 990 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 47 | `raw_handshake` | 1008 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 48 | `raw_dial` | 1092 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 49 | `d2k_raw_probe_handshake_as` | 1187 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 50 | `raw_send_plan` | 1209 | да | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 51 | `d2k_raw_probe_poison_family` | 1272 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 52 | `d2k_raw_supported` | 1328 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 53 | `d2k_raw_set_segment_max` | 1329 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 54 | `d2k_raw_rst_fail_count` | 1330 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 55 | `d2k_raw_dial_count` | 1331 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 56 | `d2k_raw_flush_pending` | 1332 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 57 | `d2k_raw_pending_count` | 1333 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 58 | `d2k_raw_probe_poison_family` | 1335 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 59 | `d2k_raw_probe_handshake_as` | 1345 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 60 | `d2k_raw_probe_handshake` | 1357 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 61 | `d2k_raw_probe_handshake_family` | 1364 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |
| 62 | `d2k_raw_probe_poison` | 1372 |  | r2o-controller/raw_probe.rs | CL1 | partial | named in report | profile/emission/cancel differential (scoped) |

### `detect/response.c` — 7

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `resp_timeout` | 64 | да | r2o-controller/response.rs | CL9 | partial | named in report | shared fixtures + follow-up (scoped) |
| 2 | `d2k_resp_scan12` | 83 |  | r2o-controller/response.rs | CL9 | equivalent (scoped) | named in report | shared fixtures + follow-up (scoped) |
| 3 | `d2k_resp_handshake12` | 123 |  | r2o-controller/response.rs | CL9 | partial | named in report | shared fixtures + follow-up (scoped) |
| 4 | `count_handshakes` | 215 | да | r2o-controller/response.rs | CL9 | partial | named in report | shared fixtures + follow-up (scoped) |
| 5 | `d2k_neutral_sni` | 233 |  | r2o-controller/response.rs | CL9 | partial | named in report | shared fixtures + follow-up (scoped) |
| 6 | `d2k_resp_decide` | 274 |  | r2o-controller/response.rs | CL9 | equivalent (scoped) | named in report | shared fixtures + follow-up (scoped) |
| 7 | `d2k_probe_response` | 310 |  | r2o-controller/response.rs | CL9 | partial | named in report | shared fixtures + follow-up (scoped) |

### `detect/trigger.c` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_trigger_tls` | 21 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 2 | `hexval` | 52 | да | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 3 | `d2k_trigger_raw_hex` | 67 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 4 | `d2k_trigger_control` | 118 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 5 | `d2k_opts_decoy` | 130 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 6 | `d2k_trigger_host_ts_override` | 156 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 7 | `host_offers_ts` | 158 | да | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 8 | `d2k_trigger_offers_ts` | 180 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |
| 9 | `d2k_trigger_allows_poison` | 201 |  | r2o-controller/trigger.rs | CL1 | partial | named in report | raw hex differential (scoped) |

### `panel/main.c` — 18

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `on_signal` | 42 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 2 | `say` | 47 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 3 | `usage` | 55 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 4 | `trim` | 63 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `known_key` | 71 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 6 | `valid_mode` | 91 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `remember_unknown` | 96 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 8 | `copy_value` | 106 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `normalize_shell_value` | 114 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `config_unsigned` | 138 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `read_config` | 151 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `split_listen` | 211 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 13 | `listen_socket` | 235 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `is_loopback_addr` | 269 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `set_state_note` | 276 | да | r2o-panel/main.rs | A1/A2/A5 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `serve` | 287 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 17 | `offline_self_check` | 396 | да | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |
| 18 | `main` | 404 |  | r2o-panel/main.rs | A1/A2/A5 | partial | named in report | serve/config/bind |

### `panel/server.c` — 51

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `monotonic_ms` | 41 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `d2k_panel_control_tick` | 47 |  | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 3 | `d2k_panel_ignore_sigpipe` | 58 |  | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `json_ws` | 68 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `json_string` | 73 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 6 | `json_compound` | 96 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `json_number` | 120 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `json_value` | 144 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 9 | `json_valid_object` | 158 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `json_top_value` | 166 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `json_top_true` | 197 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `json_top_nonempty_string` | 204 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `pid_path_running` | 211 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `engine_pid_running` | 233 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `controller_pid_running` | 237 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `write_all` | 241 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 17 | `response_ex` | 261 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 18 | `response` | 287 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 19 | `header_value` | 292 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 20 | `d2k_panel_same_origin` | 316 |  | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 21 | `run_service_action` | 329 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 22 | `telegram_config_flags` | 376 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 23 | `telegram_status_value` | 405 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 24 | `telegram_stats_number` | 420 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `telegram_stats_optional_number` | 434 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `telegram_stats_value` | 445 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 27 | `worker_domain_normalize` | 547 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `worker_domain_add` | 588 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 29 | `worker_line` | 601 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 30 | `worker_domains_from_config` | 614 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 31 | `worker_domains_from_json` | 670 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 32 | `worker_config_write` | 711 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 33 | `worker_request_body` | 784 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 34 | `api_telegram_workers` | 822 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 35 | `api_control` | 895 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 36 | `api_update` | 980 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 37 | `read_request` | 1008 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 38 | `json_object_file` | 1030 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 39 | `buf_add` | 1065 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 40 | `buf_puts` | 1072 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 41 | `buf_printf` | 1074 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 42 | `buf_json_string` | 1091 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 43 | `catalog_revision` | 1110 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 44 | `buf_live_knowledge` | 1129 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 45 | `append_stage` | 1155 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 46 | `append_snapshot` | 1165 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 47 | `api_status` | 1249 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 48 | `static_file` | 1314 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 49 | `diagnostic_response` | 1361 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |
| 50 | `api_diagnostics` | 1364 | да | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | partial | named in report | endpoints/limits; absolute response deadline/IO gap |
| 51 | `d2k_panel_handle_fd` | 1397 |  | r2o-panel/server.rs | A3/A4/A6/A7/A8/A9/A10/A11/A12/A13/A14/A15/A16/A17/A18/A19/A20/A21/A22/A23/A24/A25/A26 | implemented-unproven | module-level only | helper; module-level only |

### `relay-enroll/main.c` — 45

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `rate_allow` | 112 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 2 | `shared_limits_create` | 123 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 3 | `shared_lock` | 133 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 4 | `shared_unlock` | 148 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 5 | `limits_lock` | 151 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 6 | `limits_unlock` | 152 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 7 | `conn_admit` | 156 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 8 | `conn_set_pid` | 170 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 9 | `conn_release_slot` | 174 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 10 | `conn_release_pid` | 179 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 11 | `conn_route` | 187 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 12 | `route_status` | 200 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 13 | `valid_proof` | 210 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 14 | `parse_headers` | 221 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 15 | `system_resolve` | 258 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 16 | `monotonic_ms` | 270 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 17 | `monotonic_seconds` | 275 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 18 | `clock_now` | 276 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 19 | `dns_build_query` | 280 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 20 | `dns16` | 293 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 21 | `dns_read_name` | 297 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 22 | `dns_parse_reply` | 321 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 23 | `udp_open` | 373 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 24 | `udp_send` | 385 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 25 | `udp_recv` | 389 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 26 | `udp_close` | 402 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 27 | `addr_add` | 409 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 28 | `answer_cache_create` | 416 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 29 | `cache_get` | 421 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 30 | `cache_put` | 430 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 31 | `public_phase` | 439 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 32 | `json_space` | 474 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 33 | `json_char` | 477 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 34 | `json_name` | 481 | да | — | — | not-applicable | module-level only | helper; module-level only |
| 35 | `allowed_host` | 492 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 36 | `handle_resolve` | 502 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 37 | `socket_write_all` | 554 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 38 | `forward_registration` | 560 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 39 | `ssl_write_all` | 587 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 40 | `reply_json` | 592 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 41 | `reply` | 600 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 42 | `serve_client` | 611 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 43 | `stop_server` | 658 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 44 | `child_exited` | 659 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 45 | `main` | 661 |  | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |

### `relay-gate/main.c` — 19

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `host_allowed` | 93 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 2 | `host_syntax_ok` | 106 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 3 | `parse_port` | 116 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 4 | `split_hostport` | 129 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 5 | `parse_head` | 143 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 6 | `request_allowed` | 187 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 7 | `header_is` | 194 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 8 | `build_origin_request` | 202 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 9 | `v4_public` | 238 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 10 | `addr_public` | 248 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 11 | `rate_allow` | 278 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 12 | `now_ms` | 295 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 13 | `write_all` | 300 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 14 | `reply` | 309 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 15 | `connect_timeout` | 315 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 16 | `dial` | 333 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 17 | `relay` | 347 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 18 | `serve` | 375 | да | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |
| 19 | `main` | 441 |  | — | — | not-applicable | named in report | отдельный VPS-сервис, unported |

### `runtime/d2k_diagnostics_files.h` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_diag_dir` | 14 | да | r2o-controller/diagnostics.rs | S11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 2 | `d2k_diag_path` | 20 | да | r2o-controller/diagnostics.rs | S11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 3 | `d2k_diag_enabled` | 28 | да | r2o-controller/diagnostics.rs | S11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |
| 4 | `d2k_diag_toggle` | 33 | да | r2o-controller/diagnostics.rs | S11 | implemented-unproven | header-inline; module-level only | header-inline; module-level only |

### `runtime/d2k_runtime.h` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `d2k_runtime_id_valid` | 18 | да | r2k-core/control.rs::valid_release_id | S1 | implemented-unproven | header-inline; module-level only | release ID validation |
| 2 | `d2k_runtime_offline` | 26 | да | — | D5 | missing | header-inline; module-level only | offline self-check не перенесён |
| 3 | `d2k_runtime_mono_ms` | 34 | да | std::time::Instant | D5 | implemented-unproven | header-inline; module-level only | monotonic helper |
| 4 | `d2k_runtime_start_ticks` | 38 | да | — | D5 | missing | header-inline; module-level only | start_ticks для health не перенесён |
| 5 | `d2k_runtime_listener_ready` | 50 | да | — | D5 | missing | header-inline; module-level only | listener readiness helper |
| 6 | `d2k_runtime_heartbeat` | 54 | да | — | D5 | missing | named in report | heartbeat datapath/controller отсутствует |

### `telegram/src/cf_domains.c` — 19

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `normalize_domain` | 29 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `add_unique` | 59 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `decode_domain` | 70 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `tg_cf_domain_pool_parse_remote` | 97 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `merge_domains` | 130 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `parse_timestamp` | 141 | да | r2o-telegram/cf_domain_pool.rs | TG13 | partial | named in report | donor z2kOW; remote/cache/fallback |
| 7 | `load_cache` | 155 | да | r2o-telegram/cf_domain_pool.rs | TG13 | partial | named in report | donor z2kOW; remote/cache/fallback |
| 8 | `write_all` | 201 | да | r2o-telegram/cf_domain_pool.rs | TG13 | partial | named in report | donor z2kOW; remote/cache/fallback |
| 9 | `create_parent_directories` | 212 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `write_cache` | 232 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `load_fallback` | 270 | да | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_cf_domain_pool_init` | 282 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `tg_cf_domain_pool_install_remote` | 311 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `tg_cf_domain_pool_count` | 339 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `tg_cf_domain_pool_copy_at` | 348 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `tg_cf_domain_pool_fetched_at` | 362 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `tg_cf_domain_pool_refresh_due` | 371 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `tg_cf_domain_pool_refresh` | 383 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `tg_cf_domain_pool_destroy` | 423 |  | r2o-telegram/cf_domain_pool.rs | TG13 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/config.c` — 9

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `trim` | 12 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `copy_value` | 18 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `normalize_domain` | 22 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `parse_domain_list` | 63 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `parse_boolean` | 91 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `parse_bounded_uint` | 98 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `normalize_shell_value` | 110 | да | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_config_read` | 123 |  | r2o-telegram/config.rs | TG1 | partial | named in report | donor; файловый парсер не используется |
| 9 | `tg_config_clean` | 227 |  | r2o-telegram/config.rs | TG1 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/dc_map.c` — 13

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_dc_builtin_endpoint_count` | 42 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_dc_builtin_endpoint_at` | 46 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `ipv4_non_global` | 61 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `ipv6_v4_mapped` | 73 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `public_address` | 78 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `not_future` | 91 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `tg_dc_snapshot_validate` | 96 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `normalized_destination` | 128 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `endpoint_matches` | 140 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `resolve_official` | 147 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `resolve_builtin` | 182 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_dc_resolve` | 206 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `tg_dc_lookup_result_text` | 231 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/dc_map_json.c` — 16

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `appendf` | 20 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `skip_space` | 63 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `take` | 70 | да | r2o-telegram/dc_map.rs | TG3 | partial | named in report | donor; JSON parse/encode |
| 4 | `hex_value` | 77 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `read_string` | 84 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `read_integer` | 122 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `read_u32` | 153 | да | r2o-telegram/dc_map.rs | TG3 | partial | named in report | donor; JSON parse/encode |
| 8 | `read_port` | 162 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `read_bool` | 169 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `read_nullable_secret` | 186 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `read_endpoint` | 209 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `read_endpoints` | 256 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `tg_dc_snapshot_parse_json` | 280 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `tg_dc_snapshot_destroy` | 327 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `bool_text` | 333 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `tg_dc_snapshot_encode_json` | 337 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/dc_map_store.c` — 27

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `copy_snapshot` | 29 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `same_address_port` | 39 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `same_address` | 46 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `same_route` | 53 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `same_identity` | 60 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `replaced_by_incoming` | 70 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `endpoint_order` | 83 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `append_builtin_endpoints` | 98 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `merge_snapshot` | 124 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `read_snapshot_file` | 160 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `make_parent_dirs` | 190 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `write_all` | 212 | да | r2o-telegram/dc_map.rs | TG3 | partial | named in report | donor; persist/merge/manifest |
| 13 | `atomic_write` | 223 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `save_snapshot` | 253 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `tg_dc_map_store_init` | 263 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `tg_dc_map_store_destroy` | 270 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `tg_dc_map_store_load` | 276 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `tg_dc_map_store_current` | 299 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `tg_dc_map_store_refresh_due` | 303 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `tg_dc_map_store_install` | 312 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `snapshot_is_fresh` | 338 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `tg_dc_map_store_resolve` | 343 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `destination_equals` | 353 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `tg_dc_handshake_secrets` | 368 |  | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `pair_order` | 403 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `port_is_allowed` | 413 | да | r2o-telegram/dc_map.rs | TG3 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `tg_dc_write_endpoint_manifest` | 420 |  | r2o-telegram/dc_map.rs | TG3 | partial | named in report | donor; persist/merge/manifest |

### `telegram/src/enroll.c` — 1

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_enroll_proof` | 5 |  | — | — | not-applicable | named in report | relay enrollment вне scope |

### `telegram/src/epoll_proxy.c` — 101

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `monotonic_ms` | 213 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `monotonic_us` | 219 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `record_client_response_latency` | 226 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `add_bytes` | 243 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `add_u64` | 248 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `route_session_owner` | 253 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `route_session_add_bytes` | 258 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `route_session_transport_for` | 268 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `route_session_append` | 283 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `route_session_event` | 300 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `route_session_selected` | 321 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `route_session_first_response` | 345 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `read_le32` | 359 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `read_le64` | 364 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `set_nonblocking` | 369 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | partial | named in report | donor; Tokio вместо epoll |
| 16 | `set_tcp_nodelay` | 374 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `set_tcp_quickack` | 379 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `default_original_destination` | 388 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `queue_append_grow` | 394 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `queue_prepend` | 433 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `queue_release` | 464 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `queue_flush` | 477 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `client_events` | 499 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `upstream_events` | 518 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `watch_update` | 538 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `watch_remove` | 557 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `connection_close` | 564 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `collect_retired` | 594 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 29 | `route_health_key_matches` | 608 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 30 | `route_health_in_use` | 629 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 31 | `route_health_get` | 642 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 32 | `route_failure_record` | 673 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 33 | `route_health_cooldown_at` | 688 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 34 | `route_health_failed_at` | 704 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 35 | `route_health_failed` | 716 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 36 | `route_health_preferred_step` | 741 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 37 | `route_plan_prioritize` | 810 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 38 | `route_plan_prioritize_kind` | 825 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 39 | `target_sockaddr` | 838 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 40 | `ipv4_public` | 862 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 41 | `public_route_target` | 876 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 42 | `resolve_route_domain` | 900 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 43 | `route_worker_count` | 911 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 44 | `route_worker_domain` | 916 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 45 | `route_cf_domain_count` | 923 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 46 | `route_cf_domain` | 930 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 47 | `set_direct_hostname` | 943 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 48 | `set_worker_path` | 954 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 49 | `prepare_wss_tls` | 965 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 50 | `begin_upstream` | 979 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 51 | `clear_wss_state` | 1039 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 52 | `clear_route_attempt` | 1067 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 53 | `hedge_retire_candidate` | 1107 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 54 | `hedge_cancel_candidates` | 1121 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 55 | `setup_route_attempt` | 1132 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 56 | `start_next_route` | 1185 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 57 | `advance_route` | 1314 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 58 | `hedge_candidate_count` | 1323 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 59 | `hedge_connection_count` | 1328 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 60 | `hedge_launch_next` | 1336 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 61 | `hedge_fill` | 1438 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 62 | `hedge_fail_candidate` | 1466 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 63 | `connection_update` | 1473 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 64 | `hedge_promote_candidate` | 1492 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 65 | `advance_half_closes` | 1589 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 66 | `route_after_handshake` | 1621 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 67 | `receive_client` | 1717 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 68 | `receive_upstream` | 1805 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 69 | `socket_error` | 1834 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 70 | `queue_wss_packet` | 1841 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 71 | `process_client_payload` | 1848 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 72 | `clear_wss_replay` | 1869 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 73 | `disable_wss_replay_after_payload_write` | 1874 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 74 | `queue_wss_replay_payload` | 1884 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 75 | `flush_wss_replay` | 1903 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 76 | `hedge_candidate_flush_buffered_payload` | 1923 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 77 | `response_packet_valid` | 1942 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 78 | `observe_mtproto_response` | 1971 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 79 | `queue_wss_response` | 2089 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 80 | `establish_wss_stream` | 2139 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 81 | `set_tls_want` | 2180 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 82 | `progress_wss` | 2193 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 83 | `handle_pending_dns_client_event` | 2322 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 84 | `client_event` | 2348 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 85 | `upstream_event` | 2380 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 86 | `accept_clients` | 2519 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 87 | `wss_waiting_for_first_response` | 2580 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 88 | `timeout_until_expiry` | 2585 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 89 | `expire_connections` | 2629 | да | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 90 | `tg_epoll_proxy_create` | 2724 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 91 | `tg_epoll_proxy_step` | 2811 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 92 | `tg_epoll_proxy_destroy` | 2838 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 93 | `tg_epoll_proxy_active_connections` | 2847 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 94 | `tg_epoll_proxy_max_connections` | 2851 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 95 | `tg_epoll_proxy_get_stats` | 2855 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 96 | `tg_epoll_proxy_create` | 2974 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 97 | `tg_epoll_proxy_step` | 2979 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 98 | `tg_epoll_proxy_destroy` | 2985 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 99 | `tg_epoll_proxy_active_connections` | 2986 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 100 | `tg_epoll_proxy_max_connections` | 2990 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |
| 101 | `tg_epoll_proxy_get_stats` | 2994 |  | r2o-telegram/server.rs, transparent_proxy.rs, bridge.rs | TG15/TG24 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/identity.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `read_all` | 18 | да | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `write_all` | 29 | да | r2o-telegram/identity.rs | TG2 | partial | named in report | donor; identity без production-потребителя (TG2 extension) |
| 3 | `set_hex_id` | 40 | да | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `save_identity` | 48 | да | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `identity_error` | 77 | да | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `load_identity` | 86 | да | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `tg_identity_load_or_mint` | 121 |  | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_identity_cleanup` | 154 |  | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_identity_public_key` | 160 |  | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_identity_sign` | 168 |  | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_identity_verify` | 183 |  | r2o-telegram/identity.rs | TG2 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_register_hmac_hex` | 198 |  | r2o-telegram/identity.rs | TG2 | partial | named in report | donor; identity без production-потребителя (TG2 extension) |

### `telegram/src/limits.c` — 3

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_limits_soft_nofile` | 13 |  | r2o-telegram/limits.rs | TG22 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_limits_auto_max_connections` | 21 |  | r2o-telegram/limits.rs | TG22 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_limits_runtime_memory_budget` | 41 |  | r2o-telegram/limits.rs | TG22 | partial | named in report | donor; memory budget отсутствует |

### `telegram/src/listener.c` — 8

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_listener_decode_original_dst` | 9 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_listener_is_self_dial` | 18 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_listener_get_original_dst` | 27 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `tg_listener_decode_original_dst_any` | 38 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `original_dst_option` | 68 | да | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_listener_get_original_dst_any` | 78 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `ipv4_non_global` | 105 | да | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_listener_is_self_dial_addr` | 117 |  | r2o-telegram/transparent.rs | TG15 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/main.c` — 29

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `memory_bytes_from_sysinfo` | 54 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `proxy_memory_budget` | 62 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `on_signal` | 79 | да | r2o-telegram/main.rs, server.rs | TG24 | partial | named in report | donor; CLI/check |
| 4 | `log_msg` | 81 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `write_status` | 87 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `create_local_listener` | 96 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `monotonic_ms` | 167 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `discovery_cancelled` | 173 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `discover_wss_host` | 180 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `refresh_local_dc_map` | 229 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `dc_refresh_worker` | 295 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `start_dc_refresh` | 304 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `finish_dc_refresh` | 324 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `stop_dc_refresh` | 337 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `run_local_daemon` | 345 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `check_config` | 500 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `redirect_log` | 509 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `meta_verify_name` | 536 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `check_instagram_ip` | 546 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `offline_self_check` | 559 | да | r2o-telegram/main.rs, server.rs | TG24 | partial | named in report | donor; CLI/check |
| 21 | `parse_unsigned_arg` | 563 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `check_telegram_dc` | 576 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `telegram_probe_stage_name` | 612 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `telegram_probe_error_name` | 624 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `check_telegram_wss_matrix` | 641 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `discover_telegram_dc` | 671 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `check_telegram_dc_matrix` | 713 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `discover_telegram_dc_matrix` | 722 | да | r2o-telegram/main.rs, server.rs | TG24 | implemented-unproven | module-level only | helper; module-level only |
| 29 | `main` | 731 |  | r2o-telegram/main.rs, server.rs | TG24 | partial | named in report | donor; CLI/check |

### `telegram/src/memory_budget.c` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_memory_budget_reserve` | 5 |  | — | TG22 | missing | module-level only | helper; module-level only |
| 2 | `tg_memory_budget_release` | 16 |  | — | TG22 | missing | module-level only | helper; module-level only |

### `telegram/src/mtproto_auth.c` — 27

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `read_le32` | 40 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `read_le64` | 45 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `write_bytes` | 50 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `write_u32` | 59 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | partial | named in report | donor; auth через grammers |
| 5 | `write_u64` | 66 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `write_tl_bytes` | 73 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `read_tl_bytes` | 97 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `read_fixed` | 128 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | partial | named in report | donor; auth через grammers |
| 9 | `read_tl_u32` | 137 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `sha1_pair` | 146 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `sha1_triple` | 159 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `parse_res_pq` | 174 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `add_mod` | 200 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `mul_mod` | 204 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `gcd_u64` | 215 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `pow_mod` | 224 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `is_prime_u64` | 235 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `rho_next` | 271 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `factorize_pq` | 275 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `u64_to_be_min` | 305 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `sha256_pair` | 317 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `rsa_modulus` | 330 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `rsa_encrypt_hashed` | 338 | да | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `tg_mtproto_auth_step2` | 397 |  | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `tg_mtproto_auth_step3` | 466 |  | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `tg_mtproto_auth_step4` | 665 |  | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `tg_mtproto_auth_clear` | 717 |  | r2o-telegram/dc_discovery.rs, grammers | TG8 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/mtproto_config.c` — 11

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `load_le32` | 24 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `read_u32` | 29 | да | r2o-telegram/dc_discovery.rs | TG4 | partial | named in report | donor; getConfig |
| 3 | `read_bytes` | 38 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `skip_bytes` | 71 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `skip_string` | 77 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `skip_ints` | 81 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `parse_reaction` | 89 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `parse_dc_option` | 100 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `parse_uncompressed_config` | 149 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `inflate_config_gzip` | 218 | да | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_mtproto_config_parse` | 250 |  | r2o-telegram/dc_discovery.rs | TG4 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/mtproto_crypto.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `proto_from_bytes` | 9 | да | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `reserved_handshake_prefix` | 24 | да | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_mtproto_ctr_init` | 38 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `tg_mtproto_ctr_xor` | 50 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `tg_mtproto_ctr_destroy` | 64 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_mtproto_direct_stream_ciphers` | 70 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `tg_mtproto_direct_server_stream_cipher` | 93 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_mtproto_aes_ige` | 105 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `parse_with_key` | 159 | да | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_mtproto_parse_obfuscated2` | 187 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_mtproto_parse_secret` | 193 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_mtproto_make_obfuscated2_init` | 215 |  | r2o-telegram/crypto.rs | TG5 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/mtproto_encrypted.c` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `digest_parts` | 7 | да | grammers mtp::Encrypted | TG7 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `derive_v2_key_iv` | 24 | да | grammers mtp::Encrypted | TG7 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_mtproto_v2_encrypt` | 48 |  | grammers mtp::Encrypted | TG7 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `tg_mtproto_v2_decrypt` | 95 |  | grammers mtp::Encrypted | TG7 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/mtproto_probe.c` — 39

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `monotonic_ms` | 40 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `wait_fd` | 46 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `transfer_all` | 73 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `collect_discovery_wss_bytes` | 106 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `discovery_wss_pump` | 138 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `discovery_transfer_all` | 180 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `read_le32` | 210 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `write_le32` | 215 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `read_le64` | 219 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `write_le64` | 224 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `make_message_id` | 228 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `read_tl_bytes` | 249 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `parse_res_pq` | 277 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `parse_plain_response` | 309 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `set_probe_socket_mark` | 326 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `make_address` | 337 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `connect_numeric_until` | 358 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `tg_mtproto_probe_res_pq` | 395 |  | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `connect_hostname` | 525 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `ssl_wait` | 585 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `ssl_handshake_until` | 601 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `ssl_transfer_until` | 611 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `wss_upgrade_until` | 634 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `collect_wss_probe_response` | 671 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `wss_wait_for_res_pq` | 718 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `tg_mtproto_probe_res_pq_wss` | 757 |  | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `discovery_write` | 885 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `discovery_write_u32` | 895 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 29 | `discovery_write_u64` | 901 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 30 | `discovery_write_tl_bytes` | 907 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 31 | `discovery_write_string` | 931 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 32 | `send_frame` | 938 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 33 | `read_frame` | 963 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 34 | `exchange_plain` | 995 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 35 | `build_config_query` | 1032 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 36 | `tg_mtproto_parse_rpc_result` | 1049 |  | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 37 | `discover_config_common` | 1105 | да | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 38 | `tg_mtproto_discover_config` | 1256 |  | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |
| 39 | `tg_mtproto_discover_config_wss` | 1276 |  | r2o-telegram/dc_discovery.rs, ws_client | TG8 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/mtproto_splitter.c` — 12

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `grow_packet` | 9 | да | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `append_encrypted` | 36 | да | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `required_header` | 48 | да | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `parse_total_length` | 56 | да | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `tg_mtproto_splitter_init` | 88 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_mtproto_splitter_init_accounted` | 93 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `tg_mtproto_splitter_destroy` | 105 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `emit_packet` | 112 | да | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_mtproto_splitter_feed` | 129 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_mtproto_splitter_flush` | 213 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_mtproto_splitter_error` | 225 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_mtproto_split_result_text` | 229 |  | r2o-telegram/splitter.rs | TG6 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/net.c` — 2

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_nip_host_to_ipv4` | 16 |  | r2o-telegram/outbound/connector.rs | TG9/TG18 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_tcp_connect_ipv4` | 43 |  | r2o-telegram/outbound/connector.rs | TG9/TG18 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/route_dns.c` — 49

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_route_dns_test_doh_endpoint_count` | 70 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_route_dns_test_doh_endpoint` | 74 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `monotonic_ms` | 87 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `ipv4_public` | 93 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `public_target` | 107 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `system_dns_error_is_negative` | 135 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `system_lookup` | 143 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `dns_skip_name` | 188 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_route_dns_parse_response` | 217 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `wait_socket` | 271 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `set_route_socket_mark` | 284 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `https_connect` | 295 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | partial | named in report | donor; узкий differential |
| 13 | `dns_encode_question` | 386 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `ssl_write_all` | 424 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | partial | named in report | donor; узкий differential |
| 15 | `ssl_read_exact` | 443 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `h2_write_frame` | 465 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `h2_read_frame` | 482 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `hpack_encode_integer` | 501 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `hpack_encode_string` | 523 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `hpack_encode_header` | 533 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 21 | `h2_encode_doh_headers` | 541 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 22 | `tg_route_dns_test_h2_encode_headers` | 568 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 23 | `hpack_read_integer` | 576 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 24 | `hpack_skip_string` | 602 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 25 | `h2_response_is_ok` | 616 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 26 | `tg_route_dns_test_h2_response_is_ok` | 663 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 27 | `h2_response_body` | 669 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 28 | `tg_route_dns_https2_request` | 752 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 29 | `http_response_has_explicit_framing` | 790 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 30 | `ssl_read_response` | 819 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 31 | `decode_chunked_body` | 848 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 32 | `tg_route_dns_parse_http_response` | 893 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 33 | `contains_http_control` | 949 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 34 | `tg_route_dns_https_request` | 956 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 35 | `doh_query_endpoint` | 1004 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 36 | `doh_lookup` | 1032 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 37 | `system_then_doh_lookup` | 1063 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 38 | `tg_route_dns_lookup_now` | 1074 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 39 | `find_entry` | 1082 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 40 | `get_entry` | 1089 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 41 | `enqueue` | 1112 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | partial | named in report | donor; узкий differential |
| 42 | `resolver_worker` | 1125 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 43 | `tg_route_dns_create` | 1187 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 44 | `tg_route_dns_destroy` | 1217 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 45 | `valid_domain` | 1229 | да | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | partial | named in report | donor; узкий differential |
| 46 | `tg_route_dns_prefetch` | 1253 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 47 | `tg_route_dns_prefetch_cf_pool` | 1263 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 48 | `tg_route_dns_resolve_status` | 1285 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |
| 49 | `tg_route_dns_resolve` | 1312 |  | r2o-telegram/routing.rs, cf_proxy_doh.rs | TG10 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/route_plan.c` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_route_websocket_dc` | 6 |  | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_route_cf_proxy_hostname` | 10 |  | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `append_step` | 22 | да | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `append_direct` | 31 | да | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `append_cloudflare` | 39 | да | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_route_plan_build` | 54 |  | r2o-telegram/routing.rs, ws_client.rs | TG9 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/stats_socket.c` — 10

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `route_stage_name` | 16 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `route_state_name` | 26 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `route_transport_name` | 34 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `stats_append` | 45 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `append_active_sessions` | 57 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `set_socket_flags` | 130 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `remove_stale_socket` | 140 | да | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_stats_socket_open` | 169 |  | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_stats_socket_serve` | 233 |  | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_stats_socket_close` | 322 |  | r2o-telegram/stats.rs | TG19/TG20 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/tls.c` — 4

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `tg_tls_client_context` | 8 |  | r2o-telegram/ws_client.rs, meta_edge.rs | TG11 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_tls_connect_fd` | 23 |  | r2o-telegram/ws_client.rs, meta_edge.rs | TG11 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_tls_prepare_client_fd` | 27 |  | r2o-telegram/ws_client.rs, meta_edge.rs | TG11 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `tg_tls_connect_fd_sni` | 54 |  | r2o-telegram/ws_client.rs, meta_edge.rs | TG11 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/transparent.c` — 6

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `prefix_matches` | 14 | да | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `cidr_matches` | 25 | да | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `destination_allowed` | 50 | да | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `parse_client_handshake` | 68 | да | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `tg_transparent_select_route` | 101 |  | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_transparent_select_target` | 136 |  | r2o-telegram/transparent.rs | TG15/TG16 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/ws.c` — 18

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `valid_opcode` | 11 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_ws_encode_client_frame` | 16 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_ws_decode_server_frame` | 47 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `ssl_read_all` | 82 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `ssl_write_all` | 92 | да | r2o-telegram/ws_client.rs | TG12 | partial | named in report | donor; upgrade/frames |
| 6 | `header_has_token` | 102 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `get_header` | 116 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `has_http_control` | 137 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_ws_upgrade_start_ex` | 144 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_ws_upgrade_start` | 197 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_ws_upgrade_pending` | 202 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_ws_upgrade_advance` | 214 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `validate_upgrade_response` | 223 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `tg_ws_upgrade_feed` | 255 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `tg_ws_upgrade` | 290 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `write_frame` | 309 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `tg_ws_write_binary` | 319 | да | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `tg_ws_read_binary` | 324 |  | r2o-telegram/ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |

### `telegram/src/ws_pump.c` — 20

| # | Функция | Строка | static | Rust-владелец | Контракт | Статус | Evidence | Примечание |
|---:|---|---:|---|---|---|---|---|---|
| 1 | `release_frames` | 15 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 2 | `tg_ws_pump_init` | 24 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 3 | `tg_ws_pump_init_accounted` | 28 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 4 | `reserve_rx` | 49 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 5 | `trim_idle_buffers` | 67 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 6 | `tg_ws_pump_destroy` | 97 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 7 | `queue_opcode` | 104 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 8 | `tg_ws_pump_queue_binary` | 128 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 9 | `tg_ws_pump_queue_mtproto_payload` | 129 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 10 | `tg_ws_pump_queue_ping` | 131 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 11 | `tg_ws_pump_queue_close` | 132 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 12 | `tg_ws_pump_fd` | 133 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 13 | `tg_ws_pump_events` | 134 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 14 | `append_fragment` | 141 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 15 | `tg_ws_reassembly_destroy` | 170 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 16 | `valid_utf8` | 177 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 17 | `tg_ws_reassembly_feed` | 203 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 18 | `dispatch_frames` | 293 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 19 | `flush_tx` | 313 | да | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
| 20 | `tg_ws_pump_process` | 329 |  | r2o-telegram/bridge.rs, ws_client.rs | TG12 | implemented-unproven | module-level only | helper; module-level only |
