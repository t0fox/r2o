# Поведенческий контракт: TTL/hop limit ответа QUIC

Дата: 2026-11-16. Статус: закрыт для receive-контракта; полный QUIC-прогон
на реальном сервере не входит в этот срез.

## Наблюдаемое поведение

Вход: UDP-датаграмма на IPv4/IPv6-сокете, для которого включён
`IP_RECVTTL`/`IPV6_RECVHOPLIMIT`.

Выход:

- длина принятой полезной нагрузки;
- TTL (IPv4) или hop limit (IPv6) из control-сообщения `recvmsg`;
- отсутствие control-сообщения или нулевая датаграмма означают
  «не измерено» (`0` в C, `None` в Rust);
- нулевой TTL дошедшего пакета не считается измеренным: C принимает только
  `1..=255` для `int`-представления;
- ошибка `recvmsg` возвращается вызывающему без подмены на «не измерено».

Побочные эффекты:

- включение socket-опции best-effort: её отказ не ломает зонд и оставляет
  TTL неизмеренным;
- TTL первого аутентифицированного ответа QUIC сохраняется один раз;
  последующие ответы его не перезаписывают;
- таймауты, `EINTR`, `EAGAIN`, `ECONNREFUSED` и остальная обработка ошибок
  остаются прежними.

## C-оракул

- `core/quicprobe.c:937-997` — `qp_recv_ttl`: `recvmsg`, разбор
  `IP_TTL`/`IP_RECVTTL`/`IPV6_HOPLIMIT`, проверка `cmsg_len`.
- `core/quicprobe.c:743-755` — включение `IP_RECVTTL`/`IPV6_RECVHOPLIMIT`
  при создании сокета, отказ игнорируется.
- `core/quicprobe.c:1329-1330` — TTL первого подтверждённого ответа.
- `core/quicprobe.c:2476` — `r.qprops.server_ttl_in = ttl_in`.

## Rust-реализация

- `crates/r2o-controller/src/recv_ttl.rs` — `enable_recv_ttl`,
  `recv_with_ttl`; проверка `cmsg_len`, оба имени IPv4-TTL, нулевая
  датаграмма, отсутствие опции.
- `crates/r2o-controller/src/quic_replay.rs` — `QuicReplayResult.server_ttl_in`;
  `QuicReplayProbe` использует `recv_with_ttl` и пишет TTL только с первого
  аутентифицированного ответа.
- `crates/r2o-controller/src/quic_props.rs` — `R2oQuicProps.server_ttl_in`
  как справочное поле C-структуры (0 — не измерено).

## Доказательства

```sh
R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-quic-recv-ttl-differential.sh
# PASS: qp_recv_ttl C/Rust match (4 cases, D2O a378e230...)

cargo test -p r2o-controller --lib recv_ttl::tests --locked --offline
# 5 passed

cargo test -p r2o-controller --lib \
  server_ttl_records_only_first_measured_authenticated_response --locked --offline
# 1 passed

cargo test -p r2o-controller --lib \
  quic_replay_probe_records_ttl_of_accepted_retry --locked --offline
# 1 passed: подлинный Retry по loopback, server_ttl_in > 0
```

C-фикстура `crates/r2o-controller/tests/d2o_quic_recv_ttl_differential.c`
включает production `core/quicprobe.c` и проверяет четыре исхода: IPv4 TTL,
IPv4 без `IP_RECVTTL`, нулевая датаграмма, IPv6 hop limit. Rust-сторона
печатает тот же протокол; скрипт сравнивает вывод побайтово.

Ограничения: проверка выполнена на loopback в Linux/WSL; физический
маршрутизатор, реальный QUIC-сервер и сырой сетевой путь не проверялись.
Значение TTL зависит от ядра, поэтому контракт фиксирует факт измерения и
семантику «0/None = не измерено», а не конкретное число.

## Старый и новый метод

Старый пофункциональный подход требовал бы перенести как минимум четыре
C-единицы (`qp_recv_ttl`, участок `qp_send_one`, `quic_ask`, участок
`d2k_quic_run`) и отмечать их по отдельности, даже если Rust-архитектура
иная. Объём: построчный разбор 61-строчной функции и трёх мест её
использования, отдельные тесты на каждую единицу.

Новый метод фиксирует один контракт «TTL/hop limit входящего ответа» и
проверяет его через наблюдаемые входы/выходы. Объём: 3 production-файла
Rust, 1 C-фикстура, 1 differential-скрипт, 7 Rust-тестов и 4 differential-
кейса. Внутренняя структура C-хелперов не является единицей переноса.
