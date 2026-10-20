# Сведения о стороннем коде

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
- Шрифты Onest и JetBrains Mono сопровождаются текстами лицензий OFL в
  `crates/r2o-panel/assets/fonts/`.
