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
| `core/quicsnap.c::d2k_qsnap_form` | 91–105 (15) | `r2k-core/src/quic_snapshot.rs::r2k_quic_snapshot_parse` (50), `R2kQuicSnapshot::datagrams` (17) | **P** | Форма снимка (n, длина датаграммы, ClientHello) восстанавливается из `quic_snapshot`; отдельного differential именно на `form` нет. |
| `datapath/nl.c::d2k_nl_errno` | 163–180 (18) | `r2o-datapath/src/netlink.rs::kernel_error` (183) | **E** | Разбор `NLMSG_ERROR` с отрицательным errno совпадает по коду; netlink-тесты и `test-nfq-*` покрывают ошибочные ответы. |
| `datapath/nl.c::d2k_nl_cfg_cmd` | 254–275 (22) | `r2o-datapath/src/netlink.rs::config_command` (219), `config_params` (234) | **E** | Заголовок `nfgenmsg`, `NLM_F_ACK`, атрибут `NFQA_CFG_CMD` и `F_FAIL_OPEN/GSO` перенесены; netns-тесты queue bind. |
| `datapath/http80.c::d2k_http80_delivered` | 267–281 (15) | `r2o-datapath/src/hold.rs::mark_http_response_answered` (239), `delivered` (276) | **P** | Учёт доставленных байт и `answered` есть; отдельного C/Rust differential на «ответ пришёл без портала» нет. |
| `datapath/http80.c::d2k_http80_swap` | 527–545 (19) | `r2o-datapath/src/main.rs` (`response_delivered`, 2086–2123), `hold.rs` | **P** | Замена ответа и отправка RST/verdict-payload реализованы в main/hold; построчная сверка состояний `ST_SWAP/ST_ANSWERED` не выполнена. |

## Вывод по точечной сверке

- Прямых «дыр» в критическом packet path не видно: QUIC/ECH/TLS-крипто
  закрыто библиотеками R2O и существующими differential-тестами.
- Основные пробелы — не отсутствие кода, а отсутствие **адресных**
  C/Rust-тестов на отдельные функции: `d2k_meas` (AND-метка серии),
  `d2k_resp_handshake12` (граница 65 536/таймаут), `d2k_ctlsrv_pump`
  (полный набор событий), `httpsprobe_done` (persist/state), `routemark_describe`.
- `d2k_p256_*` в production C не вызывается; это тестовый/резервный код,
  поэтому его отсутствие в R2O не является функциональным пробелом.
