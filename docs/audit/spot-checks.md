# Точечная сверка сложных функций (предварительно)

Этот файл — независимая проверка функций, у которых нет прямого совпадения по
имени. Полные таблицы групп находятся в `docs/audit/core-*.md`,
`datapath-*.md`, `detect.md`; здесь зафиксированы конкретные находки, чтобы
итоговый отчёт не опирался только на автоматическую карту имён.

| C-функция | Строки D2O | R2O-аналог | Статус | Что проверено / пробел |
|---|---:|---|---|---|
| `core/meas.c::d2k_meas` | 269–300 (32) | `r2o-controller/src/classify.rs::Tally` (992), цикл `measure` (1111), `unproven` (1225), `with_mark_status` (628) | **P** | Повтор серии, `pass/fail/errors/unproven`, AND-семантика метки и отказ при unmarked перенесены. Differential `test-classifier-*` покрывает классификатор, но отдельного C/Rust-теста именно на AND-метку серии нет. |
| `detect/response.c::d2k_resp_handshake12` | 123–209 (87) | `r2o-controller/src/response.rs::handshake` (1050), `count_handshakes` (1148), `scan12` (1248) | **P** | Legacy ClientHello без supported_versions, 65 536-байтовый предел, `ServerHelloDone`/fatal alert и подсчёт рукопожатий есть. Нужен отдельный C/Rust differential на граничный буфер и таймаут; в общем classifier-дифференциале эта функция не адресуется по имени. |
| `core/quicsnap_reseal.c::d2k_qsnap_recid` | 75–134 (60) | `r2k-core/src/quic_snapshot.rs::r2k_quic_snapshot_reseal` (79) | **E** | Перезапечатывание всех датаграмм одним новым DCID, проверка версии/старого DCID и отказ при коротком DCID. Покрыто `crates/r2k-core/tests/quic_snapshot.rs` и QUIC snapshot differential. |
| `datapath/ctlsrv.c::d2k_ctlsrv_pump` | 511–694 (184) | `r2o-datapath/src/main.rs` — журнал/события (1162, 1393 `control.send_event`), `flow_journal.rs` | **P** | События HELLO/SUSPECT/APPLIED/REFUSED и курсор `seen` перенесены в журнал/control. Нет отдельного differential на все виды событий и на потерю/переполнение журнала в этом цикле. |
| `core/crypto.c::d2k_aes128_ecb` | 167–171 (5) | QUIC header protection через `quinn-proto`/`ring`; `r2o-datapath/src/r2o_quic.rs` | **E** | Используется только для QUIC header protection (`quicwire.c:388,404`). R2O использует проверенную библиотеку; 18/18 HTTP/3 full-stage и QUIC differential проходят. Отдельного вектора AES-ECB в R2O нет, но поведение покрыто QUIC-тестами. |
| `core/x25519.c::d2k_x25519` / `d2k_x25519_base` | 119–168 (50) | `ring`/`x25519-dalek` в QUIC и ECH; `r2o-controller/src/ech.rs` HPKE (9, 22) | **E** | Секрет X25519 для QUIC initial и ECH HPKE. Покрыто QUIC full-stage, ECH-тестами и `test-ech`. |
| `core/p256.c::d2k_p256_keypair` / `d2k_p256_ecdh` | 282–316 (35) | `ring` SECP256R1 в `r2o_tls.rs` (95, 101, 288) | **N** | В production C вызовов `d2k_p256_*` не найдено — только `test_p256.c`; TLS-путь использует `ring`. Функция не является router-runtime контрактом R2O. |
| `core/httpsprobe.c::d2k_httpsprobe_done` | 430–449 (20) | `r2o-controller/src/https_probe.rs`, `response.rs::HttpsProbeState` (75) | **P** | Состояние/завершение HTTPS-пробы и кэш состояний есть; отдельного differential на `done`/persist нет. |
| `datapath/routemark.c::d2k_routemark_describe` | 327–343 (17) | `r2o-datapath/src/r2o_route.rs` (`r2o_route_mark`, 175), `netlink.rs` | **P** | Маршрутная метка/ifindex и выбор egress есть; функция `describe` — диагностическое описание, отдельного аналога по имени нет. Проверить, нужна ли она панели/журналу. |
| `core/quicconn.c::d2k_qc_dgrams` / `d2k_qc_ping` | 1438–1458 (8) | `r2o-controller/src/r2o_quic_http3.rs`, `quic_replay.rs` | **P** | Обмен датаграммами и ping/ack покрыты HTTP/3 full-stage 18/18; отдельных функций с теми же именами нет, поэтому построчная сверка ветвей не выполнена. |

## Вывод по точечной сверке

- Прямых «дыр» в критическом packet path не видно: QUIC/ECH/TLS-крипто
  закрыто библиотеками R2O и существующими differential-тестами.
- Основные пробелы — не отсутствие кода, а отсутствие **адресных**
  C/Rust-тестов на отдельные функции: `d2k_meas` (AND-метка серии),
  `d2k_resp_handshake12` (граница 65 536/таймаут), `d2k_ctlsrv_pump`
  (полный набор событий), `httpsprobe_done` (persist/state), `routemark_describe`.
- `d2k_p256_*` в production C не вызывается; это тестовый/резервный код,
  поэтому его отсутствие в R2O не является функциональным пробелом.
