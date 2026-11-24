# Сведения о стороннем коде

## D2K

В Rust-контроллере адаптированы `journal_snapshot`, `journal_text_snapshot`,
`dns_journal_parse` и `journal_instance_domain` из коммитов
[`741e036a90f4`](https://github.com/necronicle/d2k/commit/741e036a90f4c428fcec116ae62e4aa4de469299)
и [`044ea4ef6935`](https://github.com/necronicle/d2k/commit/044ea4ef69356d70cf48bacc85dcda23bb1c6177).
R2O использует имеющийся JSON-парсер, сверяет запущенный экземпляр procd и
полный upstream, а курсор пропускает историю после смены конфигурации.
Из [`d615bf6c0556`](https://github.com/necronicle/d2k/commit/d615bf6c0556c63e1489d42d2097d512eb7a8abc)
адаптированы проверки `d2k_http80_packet` и `missing_response` для
раннего RST и повтора запроса до первого байта HTTP-ответа.
[MIT, Copyright (c) 2026 Necronicle](docs/licenses/d2k.txt).

## Telegram MTProto/WSS-прокси

- Источник: [`t0fox/z2kOW`](https://github.com/t0fox/z2kOW), каталог
  `platform/openwrt/tg-proxy/`.
- Проверенный HEAD донора: `9fc14bb67c3147b51d6d022575c9bba8f8f9ed2d`.
- Последний коммит, изменявший сам Telegram crate: `733cad48931dc81b9019eb7253cea710dbf7c9b0`.
- Лицензия: MIT; авторское уведомление: Copyright (c) 2026 valnesfjord.
- Полный текст лицензии сохранён в [`crates/r2o-telegram/LICENSE`](crates/r2o-telegram/LICENSE).

Rust-алгоритмы прокси и его тестовые сценарии перенесены из этого crate.
В `r2o` изменены имя пакета и исполняемого файла, пути состояния и интерфейс
платформенного адаптера; дополнительно сохранены модули локальной идентичности
и прямого Meta DNS. Исходный репозиторий и его рабочая копия не изменялись.

## Поведенческий эталон r2o

- Исходный репозиторий: `t0fox/r2o`, ревизия
  `ba61bba8ab6355b4a550762b4a47cd3bc6f93673`.
- Используется как поведенческий эталон и набор C-тестов при независимой
  реализации Rust. В checkout этой ревизии нет корневого файла `LICENSE` или
  `COPYING`; поэтому пакеты `r2o-datapath` и `r2k-core` не заявляют лицензию.
- `r2k-core::httpup` — независимая реализация логики из
  `core/httpup_logic.c`; поведение сверяется с `core/test_httpup_logic.c`.
  Исходник C в Rust-репозиторий не включён.
- `r2o_controller::http_search` — независимые классификатор HTTP-ответов и генератор
  четырёх планов из `core/httpsearch.c`; сценарии и golden-строки сверяются с
  `core/test_httpsearch.c`. Исходник C в Rust-репозиторий не включён.
- TLS 1.2 профиль в `crates/r2o-controller/src/profiles/legacy.hex` — сохранённый
  сетевой снимок с его исходным комментарием и ограничениями; fixture
  `crates/r2o-controller/tests/fixtures/legacy-youtube-c.bin` получен из C
  `r2o_hello_from_profile` для побайтного сравнения. C исходники в Rust crate
  не включены.
- TLS 1.3 профиль в `crates/r2o-controller/src/profiles/modern.hex` — сохранённый
  сетевой снимок из `core/profiles/modern.hex` той же ревизии. C собирает
  ClientHello через `r2o_hello_from_profile(R2O_SHAPE_MODERN, ...)`; Rust
  сохраняет снимок, подставляет SNI и пересчитывает вложенные длины. Исходник
  профиля содержит сведения о происхождении и точке замены SNI.
- Этот пункт не меняет лицензию перечисленного выше `r2o-telegram`.
- `crates/r2o-manager/release-public.pem` сохраняет открытый ключ выпуска
  Ed25519 из указанного обновлятора r2o, чтобы Rust-клиент использовал прежний
  корень доверия. Соответствующий закрытый ключ в репозитории отсутствует.

## QUIC-проба с ограничением TTL

- Источник байтов: `t0fox/d2o`, ревизия `eb848976`, файл
  `core/profiles/quic_arms.h`, массив `quic_donor_blob_0` (`quic5`).
- Комментарий исходного файла указывает происхождение образца из `z2k`, коммит
  `e9a3913`, каталог `files/fake`.
- Точный образец из 1200 байт сохранён в
  `crates/r2k-core/src/quic/quic_ttl_probe.bin`; SHA-256:
  `a7ea947b0efe4690b91f6180ff16c0f750443901f0f6310d94dca9f0b8606dac`.
- В исходном заголовке отдельная лицензия для этого набора байтов не указана.

## Резервные образцы QUIC

- Источник: тот же набор донора из коммита `e9a3913`, файл
  `core/profiles/quic_arms.h`; сохранены массивы `quic_donor_blob_1` и
  `quic_donor_blob_2` без изменения байтов.
- Образец `quic_default.bin` точно повторяет 620-байтовый `default_blob` из
  `core/quicarms.c`: первый байт `0x40`, остальные байты нулевые.
- Файлы находятся в `crates/r2k-core/src/quic/`.

| Файл | Размер | SHA-256 |
|---|---:|---|
| `quic_google.bin` | 1200 байт | `f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a` |
| `quic_rutracker.bin` | 1200 байт | `d5d77f90ff45489d246bd447c3e9f28e98891e206dc17c79d4de1da6bd0f18e8` |
| `quic_default.bin` | 620 байт | `6e996949e69b2e99dba41b83660f43268527b8b4434f1ab33d61b4cfa1c89d1b` |

- Для этих данных исходные файлы не задают отдельную лицензию. Назначение,
  происхождение и точные хеши сохранены, сами исходные файлы в `r2o` не копировались.

## Библиотека и парсер стратегий Geneva

- Источник: [`avatarDD/geneva_c`](https://github.com/avatarDD/geneva_c),
  ревизия `bdb767d97e3af0f74de7db4d391bd38808e416cf`, файлы
  `src/library_data.h`, `src/strategy.c`, `src/pkt_fields.c`,
  `src/library.c`, `tests/geneva_strategies.h`.
- Лицензия: BSD 3-Clause; Copyright (c) 2020, University of Maryland
  College Park. Библиотека стратегий сгенерирована в geneva_c из Geneva
  `library.py`; уведомление и условия BSD-3-Clause применяются к данным.
- В Rust перенесены 58 строк стратегий для тестов
  (`crates/r2o-controller/src/geneva_library.rs`) и поведение разбора
  и канонической печати (`crates/r2o-controller/src/geneva.rs`).
  Исходники C в Rust-крейт не включены.
- Эталонные строки `crates/r2o-controller/src/geneva_corpus.rs` получены
  прогоном geneva_c (`strategy_parse` + `strategy_print`) на 145 записях
  корпуса и 58 записях библиотеки на ПК; они используются только в тестах.
- Примитив `tamper{TCP:dataofs:replace:N}` реализован в R2OP независимо
  по семантике Geneva `strategy.c`/`pkt_fields.c`; исходный C-код в
  Rust-крейт не копировался.
- Компилятор поддерживаемого подмножества
  (`crates/r2o-controller/src/geneva_compile.rs`) и поля
  `REC_POISON_TCP`/`place=after` реализованы независимо по семантике
  `strategy.c`/`mutate.c`; исходный C-код не копировался.
- Бинарные фикстуры `crates/r2o-controller/tests/fixtures/geneva/*.bin`
  получены прогоном `geneva apply` на `tests/golden/in.pcap` из ревизии
  `bdb767d` (команда и стратегия — в `README.md` рядом с фикстурами) и
  используются только в дифференциальном тесте.

## Public Suffix List

- `r2o-controller` использует crate `psl` версии `2.1.241` (MIT) для расчёта
  registrable domain. Встроенные правила взяты из Mozilla Public Suffix List
  и распространяются под MPL 2.0: [источник списка](https://publicsuffix.org/list/),
  [текст MPL 2.0](https://www.mozilla.org/MPL/2.0/).
- Точная версия зависимости закреплена в `Cargo.lock`.

## Ресурсы веб-панели

- Файлы интерфейса в `crates/r2o-panel/assets/` скопированы из указанного
  checkout r2o и поставляются как встроенные ресурсы.
- `gsap.js` — неизменённый GSAP 3.15.0; уведомление GreenSock о бесплатной
  стандартной лицензии сохранено в заголовке файла:
  https://gsap.com/standard-license.
- Шрифты Onest, Manrope, Unbounded, IBM Plex Mono и JetBrains Mono
  сопровождаются текстами лицензий OFL в `crates/r2o-panel/assets/fonts/`.

## Платформенный firewall

| Донор и ревизия | Использованные функции | Лицензия |
| --- | --- | --- |
| [DFW](https://github.com/pitkley/dfw/tree/30d7edeb20c3c4ef2722b8df2d9620346becc48a) | `FirewallBackend::apply`, `Nftables::apply`, `Iptables::restore`. Раздельные типы правил, пакет `nft -f` и транзакция `iptables-restore` через stdin | [MIT](docs/licenses/dfw.txt) |
| [nlink](https://github.com/p13marc/nlink/tree/174b5458c2191fff2e729bef99156c064a87067c) | `dump_frame::classify`, `done_result`, `Backoff::delay`, `config::rules::longest_increasing` и упорядоченная часть `plan_chain`, используемая `NftablesConfig::diff_snapshot` | [MIT](docs/licenses/nlink.txt) |
| [rust-iptables](https://github.com/yaa110/rust-iptables/tree/e0e1f5dcc02023dbd162940af1b2f5159677dbd7) | `IPTables::new`, выбор iptables/ip6tables и определение поддержки `-w` по версии | [MIT](docs/licenses/rust-iptables.txt) |
| [Tailscale linuxfw](https://github.com/tailscale/tailscale/tree/da6276d77025ee2bce288c4ccf07b35e14f253a7/util/linuxfw) | `CheckIPv6`, читающая часть `CheckIPRuleSupportsV6`, проверка таблицы по образцу `checkSupportsV6Filter` | [BSD-3-Clause](docs/licenses/tailscale.txt) |

Реализация использует действующие утилиты и итератор Netlink R2O. Из netavark
(`ba588de03fb8c72d2dade087e288de9d63f785fc`), routerforge
(`b27670d45314fb2793a60fa359abfe3b9f37fbd9`) и zapret-gui
(`582e518cddde85187bec0aac9b38dee94f9a4186`) изучены соответственно firewall drivers,
инвентаризация возможностей Keenetic и восстановление после NDMS flush.
В приложение не включён код этих трёх проектов.
