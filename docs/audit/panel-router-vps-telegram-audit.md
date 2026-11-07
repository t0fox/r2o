# Аудит паритета D2O → R2O: Panel, Router, Telegram, VPS

Дата аудита: 2026-11-07.

Источники: локальные деревья `E:\d2o` (C/shell/section units) и `E:\r2o` (Rust/shell), `docs/functional-parity-matrix.md`, `docs/parity-function-inventory.md`, `README.md`, `router/README.md`, `docs/audit/function-index.md`, существующие differential-скрипты и CI-workflow.

**Интеграция 2026-11-08.** Детальные строки A1–A26, B1–B54 и C1–C26 сведены в единую scored-матрицу `docs/functional-parity-matrix.md`, раздел «Нормализованная матрица покрытия»: 173 контракта / 261 балл, строгий счёт 89/261 = 34,10 %. В scored не входят `B32`/`B45`/`B54`, `C2`, `C25`/`C26` как extension/out-of-scope/дубли. `B9` и `B52` закрыты после аудита (`scripts/test-router-clear-found-state.sh`, `scripts/test-router-log-maintenance.sh`); таблицы ниже сохранены как исходное доказательное основание.

## 0. Метод и ограничения

1. **Ничего не собиралось и не запускалось.** В PATH нет `git`, `cargo`, `rustc`; C-оракулы и Rust-тесты в этом окружении не запускались. Все выводы ниже — анализ исходников, встроенных тестов, differential-скриптов и CI-конфигурации, а не результат прогона.
2. **C D2O — эталон поведения, но не источник переноса для Telegram.** C11-реализация Telegram сравнивается как oracle; R2O Telegram взят из донора z2kOW (`tg-proxy`). Для panel/router C-код является и источником, и oracle.
3. **Версии в документах противоречат друг другу.** Заголовок матрицы говорит о 57 контрактах/89 баллах и 80/89, а примечания 73–92 — о 84 баллах, 53/84 и 63,10 %. Одновременно panel-скрипты закреплены на D2O `304ba893`, матрица panel-строки — на `a378e23`, router-скрипты — на `8e2c981`. В этом аудите **баллы не начислялись**; единый процент по четырём областям не выводится.
4. **Легенда статусов:**
   - `ДИФ` — есть production C/Rust differential-скрипт или fixture, прямо вызывающий обе реализации; в этом аудите не перезапускался.
   - `ТЕСТ` — есть только Rust unit/integration/browser-тест либо shell-harness с моками.
   - `ИСХ` — есть только сравнение исходников/донора, исполнение ветви не доказано.
   - `ПРОБЕЛ` — найдено расхождение, отсутствие ветви или недоказанное утверждение.
   - `EXT` — осознанное R2O-only расширение, не паритет.
   - `N/A` — вне области R2O (VPS/relay).

   Формулировка «совпадает по коду» в таблицах означает совпадение прочитанных ветвей, а не подтверждённый паритет: балл/эквивалентность без differential не заявляются.

## 1. Резюме

- **Panel.** Все 8 route-групп и 22 differential-сценария имеют Rust-аналоги. Основные пробелы: нет абсолютного дедлайна ответа (C `response_ex`, есть `test_response_deadline.c`, нет R2O-дифференциала); фатальная ошибка чтения сокета завершает весь `serve`, тогда как C отвечает 400 и продолжает; парсер конфигурации Rust не отвергает незакрытую кавычку в `PANEL_LISTEN`/`STATE_DIR`; список известных ключей Rust не совпадает с D2O (`TG_RELAY_*`, `TG_ENROLL_PORT`, `D2K_PPE_DEOFFLOAD`); R2O-конфиг по умолчанию содержит `AUTOUPDATE` и `D2K_GATE`, которых нет в known-list, поэтому `/api/status` на свежей установке показывает непустой `unknown_keys`.
- **Router.** Порядок start/stop, nft/iptables-генерация, fastnat, flow-offload, PPE, DNS-exclusions, heal/watchdog и procd в основном отображены. Реальные пробелы: `clear-found` удаляет только каталог и оставляет `https-cache.json`; `KEENETIC_POLICY` (`ndmc show ip policy` → `--only-mark`) не перенесён вовсе; ротация журналов не покрывает `instagram-dns.log` и `instagram-dns-scheduler.log`; `heal` в R2O может запустить остановленный Telegram, чего D2O не делает; `engine-restart` при `MODE=off` сначала останавливает движок; действия `dns-tick/dns-refresh/dns-remove` отсутствуют в `S99r2o`; uninstall не имеет аварийной очистки при отсутствующем адаптере.
- **Flow-offload.** Текущий `r2o-firewall.sh` **глобально выключает** fw4 offload, как D2O. Примечания матрицы 20/26/28/66/67/81/83/84/85/86/88/92 описывают уже отсутствующую selective-схему; скрипт `test-router-flowoffload-selective-differential.sh`, на который они ссылаются, в дереве отсутствует, а действующий `test-router-flowoffload-d2o-differential.sh` прямо запрещает `ct mark`/`mark_flow`/`flow offload @`.
- **Telegram.** R2O — функциональный superset донора по большинству модулей, но не пофункциональный паритет с C. Неперенесённые/расходящиеся ветви: memory budget и жёсткий `max_connections=64` D2O; файловый парсер `tg_config_read`; строгая проверка `TG_PORT=1443`; `TG_DIAGNOSTIC_DIRECT_TCP`; `TG_CF_DOMAIN_CACHE_PATH`; отсутствие стартовой валидации и лимита 32 для `TG_CF_DOMAIN`; stats-сокет без таймаута чтения запроса; identity/`enroll.c` без потребителя. C-векторы crypto/splitter не используются в Rust-дифференциалах.
- **VPS.** `relay-enroll` и `relay-gate` в R2O отсутствуют полностью: нет бинарников, systemd-юнитов, install-server, портов 9443/9444, `/register`, `/resolve`, allowlist-proxy. README прямо фиксирует работу без VPS/relay/WARP. Единственный след — совместимое исключение `D2K_GATE` из NFQUEUE; транспорт обновлений R2O его не использует (`curl --noproxy '*'`). Identity в R2O создаётся, но ни для enrollment, ни для relay не применяется.
- **CI.** Все 40 `test-router-*.sh` запускаются в CI (shell job). Panel-джоба запускает только `cargo test -p r2o-panel`; 22 `test-panel-*.sh` не входят в CI (в donor-shard есть только `r2o-panel-bind-default-differential.sh`). Telegram `--check`/service harness в CI отдельно не запускаются; они входят только через `test-router-*.sh`.

## 2. A. Panel (`E:\d2o\panel`, `E:\r2o\crates\r2o-panel`)

### A.1 HTTP-маршруты, методы и коды

| Контракт | C D2O | Rust R2O | Ветви/коды | Тест | Статус |
|---|---|---|---|---|---|
| `GET /` | `server.c:1449`, `static_file:1314` | `server.rs:287`, `static_asset:1780` | 200/304/404; `index.html` | `test-panel-static-etag-differential.sh`; browser.cjs | ДИФ |
| `GET /assets/favicon.svg`, `panel.css`, `panel.js`, `diagnostics.js`, `telegram-flow.js`, `telegram-flow-prototype.js`, `gsap.js`, `onest.woff2`, `jbmono.woff2` | `server.c:1452-1477` | `server.rs:290-349`; R2O дополнительно `refresh-mask.svg`, `panel-motion.js`, `panel-lava.js`, `nunito-*.woff2`, `jetbrains-mono-lava.woff2` | 200/304/404; тип по маршруту | `static-etag`, `static-asset-size`; browser.cjs | ДИФ + EXT |
| `GET /api/status` | `api_status:1249` | `api_status:754` | 200; live/ unavailable; revision/unchanged | `status-unavailable`, `live-status-size`, `catalog-revision` | ДИФ |
| `POST /api/control/{start,stop,restart,reapply,clear-found,telegram-enable,telegram-disable,update-check,update-install,update-auto-on,update-auto-off}` | `api_control:895`, таблица `897-913` | `api_control:1124`, таблица `1125-1173` | 202/403/404/409/400/500 | `control-response`, `control-timeout`, `telegram-config-gate` | ДИФ |
| `POST /api/control/telegram-check` | нет | `server.rs:1150`, `start_telegram_check:1284` | 202/409 | Rust `telegram_check_runs_as_an_authenticated_async_service_action` | EXT |
| `GET /api/update` | `api_update:980` | `api_update:1112` | 200 `absent`/`never`/raw state; 405 для не-GET | `update-state` | ДИФ |
| `GET/POST /api/telegram/workers` | `api_telegram_workers:822` | `api_workers:1432` | 200/202/400/403/405/409/415/500 | `workers-busy`, `workers-config`, `workers-config-size`, `workers-config-write`, `workers-json`, `worker-content-length`, `worker-body-deadline` | ДИФ |
| `GET/POST /api/diagnostics` | `api_diagnostics:1364` | `api_diagnostics:571` | GET 200/500/503; POST 200/400/403/405/500; `enable`/`disable`/`status`/`report`/`download` | `diagnostics-default-query`; Rust `diagnostics_api_matches_d2o_*` | ДИФ |
| Неизвестный путь | `server.c:1478` | `server.rs:355` | 404 `not found\n` | C `test_unknown_and_traversal_paths_are_not_served`; Rust route-table | ТЕСТ |
| Неподдерживаемый метод | `server.c:1423-1446` | `server.rs:256-283` | 405 `method not allowed\n` | `test_server.c:410`; Rust `control_routes_reject_get` | ДИФ |
| Некорректная строка запроса/HTTP-версия | `sscanf` + проверка `HTTP/1.0/1.1`, `server.c:1415` | `Request::parse:201` | 400 | Rust unit/HTTP | ТЕСТ |
| Заголовок > 32 КиБ | `read_request:1008`, `REQUEST_MAX` `server.c:25` | `read_request:474`, `REQUEST_MAX` `server.rs:13` | 431 `request too large\n` | `request-header-limit` | ДИФ |
| Заголовок не пришёл за 5 с | `read_request:1010` | `read_request:478` | 408 `request timeout\n` | `header-deadline` | ДИФ |
| Тело неизвестного маршрута | игнорируется | игнорируется | — | — | Совпадает по коду |

Все ответы C и Rust содержат `Content-Type`, `Content-Length`, `Connection: close`, CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`server.c:264-273`; `server.rs:176`). C собирает заголовок в буфер 1024 и при переполнении не отвечает; Rust пишет потоком. Для текущих ETag/extra это недостижимо.

### A.2 Лимиты, таймауты, auth/gates

| Контракт | C | Rust | Комментарий | Статус |
|---|---|---|---|---|
| Лимит заголовка | 32 КиБ (`server.c:25`) | 32 КиБ (`server.rs:13`) | Совпадает; на границе ровно 32 КиБ C может принять терминатор, Rust проверяет `raw.len() >= REQUEST_MAX` до поиска `\r\n\r\n` — возможен разный ответ 431/200 на точной границе | ПРОБЕЛ (edge) |
| Лимит тела Workers | 4096 (`server.c:544`, `worker_request_body:784`) | 4096 (`server.rs:18`, `read_request:522`, `api_workers:1468`) | Content-Length обязан быть 1–4 цифры; C отвергает `00021` сразу, Rust в `read_request` сначала ждёт 21 байт, затем маршрут возвращает 400 — разная задержка при отсутствующем теле | ДИФ/ПРОБЕЛ |
| Лимит live-файла | 1 МиБ (`BODY_MAX`, `json_object_file:1034`) | 1 МиБ (`LIVE_STATUS_MAX`, `read_regular_file:1930`) | Совпадает | ДИФ |
| Лимит статики | 1 МиБ (`static_file:1329`) | 1 МиБ (`STATIC_ASSET_MAX`) | Совпадает для файлов | ДИФ |
| Лимит Workers-конфига | 1 МиБ (`worker_domains_from_config:622`, `worker_config_write:718`) | 1 МиБ (`WORKER_CONFIG_MAX`) | Совпадает | ДИФ |
| Лимит `update.json` | 16 384 (`api_update:986`) | 16 384 (`read_update_state_body:1899`) | Совпадает | ДИФ |
| Лимит diagnostics report | `D2K_DIAG_REPORT_MAX` | 256 КиБ (`DIAGNOSTICS_REPORT_MAX:564`) | Значение C задаётся runtime-заголовком; эквивалентность не доказана | ПРОБЕЛ |
| Таймаут заголовка | 5 с абсолютный (`D2K_PANEL_HEADER_TIMEOUT_MS`) | 5 с абсолютный (`read_request:478`) | Совпадает | ДИФ |
| Таймаут ответа | 5 с **абсолютный на заголовки и тело** (`response_ex:278`, `write_all:241`) | по 5 с на каждый `read`/`write` (`serve:378-379`, `Response::send:157`) | Медленный клиент может растянуть ответ Rust; C оборвёт по общему дедлайну. `test_response_deadline.c` в D2O есть, R2O-дифференциала нет | ПРОБЕЛ |
| Таймаут action | 60 с (`D2K_PANEL_ACTION_TIMEOUT_MS`) | 60 с (`CONTROL_TIMEOUT`) | R2O для update-check/install расширяет до 5/30 мин | ДИФ + EXT |
| Тело Workers | отдельный абсолютный 5-с дедлайн после заголовков (`worker_request_body:804`) | `read_request:526` | Совпадает по смыслу; см. различие `00021` | ДИФ |
| Telegram stats | 1250 мс общий дедлайн connect+read (`telegram_stats_value:469`) | 1250 мс **на каждую** операцию чтения/записи (`read_telegram_stats:2210`) | Медленный stats-сервер может удержать панель дольше; нет R2O-дифференциала на этот случай | ПРОБЕЛ |
| Same-origin | `d2k_panel_same_origin:316` | `same_origin:1241` | `Origin: http://Host`, точное равенство authority | ДИФ (control) |
| `control_enabled` | жёстко 1 в `main.c:361` | жёстко 1 в `main.rs:118` | Совпадает | ИСХ |
| Аутентификация | отсутствует; предупреждение только для non-loopback (`main.c:323`) | отсутствует; предупреждение всегда (`main.rs:116`) | Функционально эквивалентно, текст/условие различаются | EXT/ПРОБЕЛ |
| Параллелизм | один клиент за раз (`main.c:369-391`) | один клиент за раз (`serve:367-395`) | Совпадает по модели | ИСХ |

### A.3 `/api/status`, JSON-поля и Telegram-интеграция

| Контракт | C | Rust | Пробел/статус |
|---|---|---|---|
| Поля snapshot | `append_snapshot:1165-1247`: `taken`, `version`, `commit`, `built`, `dirty`, `config_path`, `config_exists`, `mode`, `panel_listen`, `controls_enabled`, `control_state`, `catalog_available`, `live_fresh`, `engine_running`, `controller_running`, `telegram_*`, `telegram_stats`, `state_dir`, `state_dir_note`, `queue_num`, `unknown_keys`, `started_at`, `uptime_seconds`, `stages`, `absent` | `snapshot:992-1097` | Все поля есть; Rust добавляет `telegram_diagnostics` — EXT. Порядок ключей Rust не сохраняет (serde_json Map), C вставляет вручную; байтовое равенство не доказано |
| `knowledge` unavailable | `server.c:1292-1295` | `unavailable_knowledge:984` | Значения совпадают; проверяется как JSON, не байты (`d2o_status_unavailable.c`, Rust `status_without_live_file_returns_the_panel_contract`) |
| `catalog_revision` | `catalog_revision:1110` (FNV по raw `boxes`/`groups`) | `catalog_revision:1947` | Алгоритм совпадает; `test-panel-catalog-revision-differential.sh` |
| `catalog_unchanged` | `query` начинается с `catalog_revision=` и равен hash | `strip_prefix` + равенство | Совпадает |
| Live `knowledge` | сырые байты JSON с заменой `linked`/`boxes`/`groups` (`buf_live_knowledge:1129`) | парсинг в `Value` + повторная сериализация (`api_status:819-842`) | **Семантика совпадает, байты/порядок ключей — нет.** Матрица заявляет только size/revision, это корректно |
| Свежесть live | mtime ±15/5 с и не старше engine start (`1263-1267`) | то же (`797-805`) | Совпадает |
| Дополнительные live-файлы | нет | `--live-extra`, `merge_live_snapshot:859` | EXT; отдельный Rust-тест |
| Telegram enabled/configured | `telegram_config_flags:376` | `telegram_config_flags:2093` | Строки/кавычки/дубликаты `TG_MODE` совпадают; Rust обрезает NUL иначе, чем `fgets` — только edge |
| Telegram status | `telegram_status_value:405` | `telegram_status:2170` | `stopped` при отсутствии PID; `error` из файла не пробрасывается. Примечание матрицы 62 («R2O отдаёт error») **устарело**: код и строка 65 уже про `stopped` |
| Telegram stats | `telegram_stats_value:445`: AF_UNIX, 1250 мс, 131072, полный EOF обязателен, поля legacy | `read_telegram_stats:2204`: 131071, `valid_telegram_stats:2638` принимает **два** схемы (legacy D2O и Rust-донор) | Расширение схемы и таймаута; D2O-поля `wss_attempts`, `last_success_*` R2O не выдаёт, панель принимает Rust-схему |
| `unknown_keys` | `main.c:71-89`, `remember_unknown:96` | `parse_config:2807-2814` | Максимум 64, ключ <128, дедупликация — совпадает; **состав known-list различается**, см. A.4 |

### A.4 Парсер конфигурации, bind и disabled panel

| Контракт | C | Rust | Статус |
|---|---|---|---|
| Читаемые ключи панели | `SCHEMA`, `MODE`, `PANEL_LISTEN`, `STATE_DIR`, `QUEUE_NUM` (`main.c:179-204`) | те же (`parse_config:2825-2873`) | Совпадает |
| Known, но игнорируемые | C пропускает разбор значения для всех прочих known-ключей (`main.c:178-182`) | `ignored` до `strip_shell_value` (`server.rs:2816`) | Совпадает (после примечания 25) |
| Список known-ключей | `main.c:71-89`: включает `TG_RELAY_URL`, `TG_RELAY_SECRET`, `TG_ENROLL_PORT`, `D2K_PPE_DEOFFLOAD` | `server.rs:2728-2765`: этих четырёх нет; есть R2O-ключи | **ПРОБЕЛ:** D2O-конфиг на R2O даст лишние `unknown_keys` |
| `AUTOUPDATE`, `D2K_GATE` | отсутствуют в known-list | отсутствуют | **ПРОБЕЛ продукта:** `config.default` R2O содержит оба, поэтому свежий `/api/status` показывает непустой `unknown_keys`; D2O default-конфиг их не содержит |
| Комментарии `#` | полная строка, хвост после пробела/tab, после закрытой кавычки (`main.c:114-135`) | `strip_shell_value:3165` | Совпадает; `config-comment-bytes` |
| Кавычки | одиночные/двойные, требуется закрывающая; после неё только пробел/tab/`#` | то же | Совпадает, кроме одного случая |
| Незакрытая кавычка в unquoted значении | C отвергает значение, оканчивающееся на `'`/`"` (`main.c:132-133`) | Rust этого не делает (`strip_shell_value:3175-3182`) | **ПРОБЕЛ:** `PANEL_LISTEN=127.0.0.1:8090'`/`STATE_DIR=/opt/r2o/state'` R2O примет |
| Не-UTF-8 байты | C пропускает `0xff` в комментариях/значениях игнорируемых ключей, сохраняет unknown-ключ (`config_comment_bytes`) | `sanitize_config_bytes:2993` | Заявлено дифференциалом `test-panel-config-comment-bytes-differential.sh`; логика совпадает, но тест не перезапускался |
| Строка > 2046 байт | C отвергает переполненный `fgets` (`main.c:167-171`) | `line.len() >= 2047` (`server.rs:2793`) | Совпадает |
| Неизвестный ключ | до 64, <128, dedup | то же | Совпадает |
| `SCHEMA` 0/1, `QUEUE_NUM` 0..65535, `STATE_DIR` абсолютный, `MODE` off/observe/apply | `main.c:183-204` | `parse_config:2825-2873` | Совпадает |
| Bind по умолчанию | `127.0.0.1:8090` (`main.c:423`), installer пишет выбранный LAN IP | `127.0.0.1:8090` (`main.rs:100`, `config.default:24`), `select-panel-ip.sh` побайтно совпадает | `r2o-panel-bind-default-differential.sh`, `test-router-select-panel-ip.sh`, `test-router-panel-bind-install.sh`; ДИФ |
| Public-only bind | D2O не запрещает, только предупреждает | R2O selector fail-closed по README; panel main тоже не запрещает | Заявлено installer-тестом; в panel main разницы нет |
| Пустой `PANEL_LISTEN` | панель выключается, `main.c:317-320` | выключается, `main.rs:107-110`; S99 `panel_start` учитывает | `test-router-update-panel-disabled-differential.sh`; ДИФ |
| IPv6-listen `[::1]:8090` | `split_listen:211` | `split_listen:127` | Совпадает |
| Health-файл | `/tmp/d2k/d2kpanel.health`, формат `D2KH1` | `/tmp/r2o/r2o-panel.health`, формат `R2OH1` | Внутренний формат R2O; внешние потребители D2O его не читают. Не паритет, но и не контракт |

### A.5 Control/actions, Workers и атомарная запись

| Контракт | C | Rust | Статус |
|---|---|---|---|
| Машина состояний action | `action_pid`/`action_state` `idle→running→done/failed/timeout`, `d2k_panel_control_tick:47-56` | `Config.action: Arc<Mutex<String>>`, `start_action_command_with_completion:1335-1430` | Имена состояний совпадают; `timeout` выставляется по своему таймеру |
| Busy | `action_pid` → 409 | `state == "running"` → 409 | `workers-busy`, `control-response`; ДИФ |
| Ошибка запуска | fork/exec fail → 500 | spawn fail → 500 | ДИФ |
| Код 124 от самой службы | C трактует как `timeout` (`server.c:54`) | Rust трактует как `failed` (`status.success() == false`) | **ПРОБЕЛ (edge):** самозавершение службы с кодом 124 |
| Тело control запрещено | любой `Transfer-Encoding`, `Content-Length != "0"` → 400 (`server.c:947-961`) | те же проверки (`server.rs:1199-1203`) | Совпадает |
| `MODE=off` gate | start/restart → 409 (`server.c:933-939`) | start/restart → 409 (`server.rs:1185`) | ДИФ |
| `telegram-enable` gate | `TG_MODE=local` иначе 409 (`server.c:940-946`) | то же + `telegram-check` (`server.rs:1191-1198`) | ДИФ + EXT |
| GET Workers | читает файл, 500 при ошибке, 200 `{"domains":[...]}` | то же (`api_workers:1433-1440`) | ДИФ |
| POST Workers gates | control/same-origin 403, Content-Type 415, TE 400, Content-Length 1–4096/≤4 цифры 400, JSON/домены 400 | те же (`server.rs:1442-1482`) | ДИФ |
| Домены | ≤8, ≤253, lowercase, только `[a-z0-9.-]`, метки 1–63, TLD ≥2 и с буквой; URL допускается только в конфиге, в POST — нет (`server.c:547-599`) | `add_domain:1639`, `worker_domains_from_json:1519` | ДИФ (`workers-json`) |
| Сохранение конфига | удаляет все строки `TG_CF_WORKER_DOMAIN=`, добавляет новую; сохраняет прочие байты, включая `0xff` (`worker_config_write:711-782`) | `write_worker_config:1687`, `worker_line_bytes:1589` | ДИФ; Rust сохраняет байты, кроме заменяемой строки |
| Атомарность | `mkstemp` рядом, `fchmod` исходного режима, `fsync`, `rename`; **без fsync каталога** | `create_new` рядом, mode исходного режима, `sync_all`, `rename`, **fsync каталога** (`1732-1778`) | Rust строже; режим может отличаться из-за umask (R2O `mode()` не маскирует обратно) |
| Busy до записи | C проверяет `action_pid` после разбора тела, до записи (`server.c:875-880`) | Rust резервирует action до `setup()`-записи и восстанавливает состояние при ошибке (`1358-1367`) | ДИФ (`workers-busy`) |
| Перезапуск Telegram после записи | `run_service_action("telegram-restart")` | `start_action_command_with_setup` + `telegram-restart` | ДИФ; C11 runtime не портирован, вызывает R2O adapter |

### A.6 Тесты panel: что есть и чего нет

Существуют 22 скрипта `scripts/test-panel-*.sh` (все закреплены на D2O `304ba893`) плюс `r2o-panel-bind-default-differential.sh`. Они вызывают настоящие C handler-функции через `tests/d2o_*.c` и production Rust route. **В CI эти 22 скрипта не запускаются**; panel-джоба делает только `cargo test -p r2o-panel`. В donor-shard включён только bind-default.

Нет дифференциалов для:
- абсолютного дедлайна ответа (`test_response_deadline.c`);
- обрыва клиента во время чтения заголовка (C отвечает 400, Rust может завершить `serve`);
- незакрытой кавычки в `PANEL_LISTEN`/`STATE_DIR`;
- полного списка known-ключей D2O;
- точной границы 32 КиБ заголовка;
- non-UTF-8 заголовков запроса (C принимает, Rust `from_utf8` → 400);
- пути длиннее 255 (C обрезает `sscanf`, Rust 400);
- кода 124 от службы;
- отсутствующего статического файла: C 404, Rust отдаёт embedded fallback;
- байтового порядка ключей `/api/status`.

### A.7 Итог по panel

Реализация покрывает весь маршрутный набор и большинство лимитов; 22 дифференциала дают хорошую, но не полную доказательную базу. Перечисленные пробелы — не косметика: обрыв соединения и медленный ответ меняют устойчивость панели, а расхождение known-list/`unknown_keys` видно в штатном `/api/status`.

## 3. B. Router: сервисы, firewall, обновление

### B.1 S99/действия и порядок жизненного цикла

| Действие/функция | D2O | R2O | Поведение/коды | Тест | Статус |
|---|---|---|---|---|---|
| `start` | `S99d2k:1376-1388` | `S99r2o:929-936` | D2O: engine→telegram→panel→DNS scheduler→updater. R2O: engine→telegram→panel→Meta DNS→update. При `MODE=off` D2O возвращает ошибку, R2O — 0 и ничего не запускает | `test-router-openwrt-init.sh`, `test-router-install-lifecycle.sh` | ДИФ/ПРОБЕЛ (код возврата off) |
| `stop` | `S99d2k:1516-1526` | `S99r2o:938-947` | D2O: DNS→updater→telegram→engine→panel→log→rst-all→`rm live.json`. R2O: supervisor-disable→Meta DNS→update→telegram→engine→panel→log→rst-down; live-файл не удаляется | `test-router-update-lifecycle.sh`, `test-telegram-stop-order-differential.sh` | ДИФ/ПРОБЕЛ (live cleanup) |
| `restart` | `stop && start` | `stop && start` | Совпадает | — | ИСХ |
| `engine-start` | `start_engine:1263` | `engine_start:407` | MODE off→1; проверка бинарей; частичный запуск→engine_stop; ожидание NFQUEUE 50×0.1 с; firewall up; fastnat/flowoffload; controller; watchdog | `test-router-reapply`, `route-gate-config`, `flowoffload-lifecycle` | ДИФ |
| `engine-stop` | `engine_stop:1501` | `engine_stop:347` | D2O: heal stop→fw down→legacy http→fastnat restore→flowoffload restore→controller→datapath→`rst_rules_down dead`. R2O: watchdog stop→hook remove→fw down→fastnat→flowoffload→controllers→datapaths; RST-таблица не снимается, её удаляет полный `stop`/`rst-down`, а controller чистит свои iptables-правила сам | `test-router-firewall-watchdog`, `flowoffload-lifecycle` | ДИФ/ПРОБЕЛ (dead-owner sweep в shell) |
| `engine-restart` | `S99d2k:1628-1631` | `S99r2o:1089` | D2O проверяет `MODE=off` **до** stop. R2O делает `engine_stop && engine_start`; при off сначала остановит | — | **ПРОБЕЛ** |
| `settings-restart` | нет отдельного действия | `S99r2o:468-475` | `engine_stop/start` + `telegram_restart` | `test-router-update-lifecycle` косвенно | EXT |
| `supervise` | нет | `S99r2o:242-245`, `openwrt-init:45-48` | Повторный `start` каждые 60 с, маркер `supervisor-disabled` | `test-router-process-supervisor.sh`, QEMU | EXT |
| `status` | `S99d2k:1528-1562` | `S99r2o:1038-1074` | D2O печатает datapath/controller/panel/TG/DNS/updater/heal/rules/policy/queue/version. R2O — IPv4/IPv6 раздельно, watchdog, firewall. Строки D2O не совпадают (`датапат: работает` vs `r2o-datapath IPv4: работает`) | `test-router-firewall-status-differential.sh`, `iptables-status` | ДИФ/ПРОБЕЛ (формат) |
| `clear-found` | `S99d2k:1588-1605` | `S99r2o:651-668` | D2O останавливает engine, удаляет `catalog.json`, `http-plans.txt`, `https-cache.txt`, `measurements/`, затем поднимает engine. R2O останавливает engine, `manager --clear-catalog` (только каталог), поднимает engine | — | **ПРОБЕЛ:** `https-cache.json` (и `measurements`) остаются |
| `reapply` | `S99d2k:1568-1574` | `S99r2o:853-856` | D2O: datapath жив→legacy http stop→load_modules→fw_up или die. R2O: IPv4 datapath жив→firewall up или die; IPv6 не проверяется | `test-router-reapply-differential.sh` | ДИФ |
| `heal` | `S99d2k:1609-1610` | `S99r2o:904-907` | D2O: если datapath жив, `fw_installed || reapply`, `ppe_ensure`, затем `telegram_reapply`. R2O: `firewall_heal` + `telegram_reapply`, причём R2O `telegram_reapply` при неготовом listener вызывает `telegram_start` | `heal-concurrency`, `reapply` | ДИФ/ПРОБЕЛ (побочный запуск Telegram) |
| `firewall-heal` | нет отдельного | `S99r2o:888-902` | R2O дополнительно каждый круг делает `flowoffload-ensure`; при отказе останавливает datapath | `test-router-heal-concurrency`, `firewall-watchdog` | EXT/ПРОБЕЛ |
| `dns-ensure` | `S99d2k:1640` | в `r2o-firewall.sh:946`, вызывается из heal; в `S99r2o` действия нет | D2O действие доступно снаружи; R2O — только внутренний вызов | `dns-exclusion` | ДИФ/ПРОБЕЛ (интерфейс) |
| `dns-tick`, `dns-refresh`, `dns-remove` | `S99d2k:1611-1613` | нет; вместо них `meta-dns-refresh/remove` через manager и собственный scheduler | Внешний интерфейс D2O не совпадает | `test-router-meta-dns-scheduler` | ПРОБЕЛ (интерфейс) |
| `log-tick` | `S99d2k:1614` | `S99r2o:1121` | `r2o-log-maintenance.sh tick` | `test-router-log-maintenance.sh` | ДИФ |
| `update-*` | `S99d2k:1617-1620` | `S99r2o:1115-1119` | D2O: updater check/install/auto. R2O: manager update-check, `update-install[-auto]`, `set_update_auto` | `test-router-update-*`, `test-signed-install-rollback` | ДИФ |
| `tg-heal`, `tg-stop-rules` | `S99d2k:1621-1622` | `S99r2o:1124-1125` | Совпадает по смыслу | `test-router-tg-firewall`, `tg-mark` | ДИФ |
| `ppe-ensure/remove/status` | `S99d2k:1639-1645` | `S99r2o:1101-1107` | Коды 0/2/3 сохранены | `ppe-removal-error`, `ppe-service` | ДИФ |
| `panel_start` | `S99d2k:1358-1373` | `S99r2o:911-927` | R2O передаёт `--live-extra`, `--manager`, `--manager-root`; panel не входит в engine lifecycle | `test-router-panel-bind-install` | ДИФ/EXT |
| Health-wait обновления | `d2k-update.sh:137-151` (`HEALTH_WAIT=60`, PID datapath/controller/panel) | `S99r2o:949-973` (60 с и повторная проверка datapath/controller/queue/panel/IPv6) | R2O строже (двойная проверка), D2O только PID | `update-panel-disabled`, `update-lifecycle` | ДИФ |
| Supervisor disable/enable | нет | `S99r2o:230-240` | Маркер в `/tmp/r2o`; `engine-stop`/`stop` ставят, `engine-start` снимает | `test-router-process-supervisor` | EXT |

### B.2 Firewall: backend, правила, коды возврата

| Контракт | D2O | R2O | Поведение/коды | Тест | Статус |
|---|---|---|---|---|---|
| Выбор backend | `S99d2k:135-143`: `/etc/openwrt_release` + `nft` → nft, иначе iptables; `FW_BACKEND` override | `r2o-firewall.sh:115-125`: то же + `R2O_PLATFORM=openwrt` | Совпадает; R2O добавляет override платформы | `flowoffload-fw3-fallback` | ДИФ |
| Модули | `load_modules:1247` | `load_modules:157` | Наборы nft/iptables различаются по backend | `ipv6-fallback-differential` | ДИФ |
| nft main table | `nft_ruleset:693`, `fw_nft_up:781` | `nft_up:186`, `firewall_status_nft:876` | Таблицы/цепочки переименованы (`d2k`→`r2o`); правило очередей и счётчики проверяются | `firewall-status`, `firewall-nft-*` | ДИФ |
| iptables rules | `fw_family_up:385` | `xt_family_up:626` | broadcast/multicast/ICMP/loopback/DNAT, CONNBYTES+1, PORTS scope, marks | `firewall-port-scope`, `connbytes-boundary`, `broadcast`, `icmp-guard` | ДИФ |
| Код ошибки отдельного правила | `fw_family_up` возвращает 1 на любой неудачной команде | `xt_family_up`/`iptables_up` | Совпадает; `test-firewall-rule-error-differential.sh` | ДИФ |
| nft rollback | При отказе `nft -f` удаляет свою main table; RST — только если создана в этой попытке | `firewall_up:819-849` | Совпадает; `test-firewall-nft-failure` | ДИФ |
| Legacy iptables cleanup | `fw_iptables_down:641`, `fw_family_down:611` | `xt_legacy_d2k_family_down:597` | D2K_OUT/IN, D2K_HTTP, MARK/HTTPUP mark, MASQUERADE; R2O сохраняет чужие правила | `firewall-nft-legacy-iptables` | ДИФ |
| RST table lifetime | `fw_down` не удаляет `d2k_rst`; `rst_rules_down all` при полном stop (`S99d2k:1511,1523`) | `firewall_down` не удаляет `r2o_rst`; `rst-down` в `S99r2o:946` | Совпадает; `test-firewall-nft-down-rst-lifetime` | ДИФ |
| Проверка status nft | `fw_nft_installed:791` | `firewall_status_nft:876` | R2O требует 12 out + 14 in queue rules, 6+6/7+7 по очередям | `firewall-status-differential` | ДИФ |
| Проверка status iptables | `fw_family_installed:1012` | `xt_family_installed:705` | R2O проверяет полный контракт, включая DNS exclusions и PORTS | `iptables-status-differential`, `port-scope` | ДИФ |
| IPv6 fallback | `fw_up_unlocked:595-608`, маркер `FW_V4ONLY`, код 3 | `iptables_up:789-817`, `IPV6_ENABLED`/`FW_V4ONLY`, код 3 | Совпадает; D2O проверяет `ip6tables` при каждом up | `ipv6-fallback-differential` | ДИФ |
| IPv6 re-enable | `fw_up_unlocked` при следующем up снимает маркер | `S99r2o` каждый start заново проверяет runtime-capability | Совпадает по результату | `ipv6-fallback-differential` | ДИФ |
| DNS-upstream exclusions | `dns_upstreams:900`, `dns_excl_*:924-973` | `dns_upstreams:482`, `dns_excl_*:507-567` | Только iptables, `ndmc show dns-proxy`, A/AAAA, plain/DoH/DoT, localhost skip, сохранение при ошибке resolve | `dns-exclusion-differential` | ДИФ |
| DNS refresh | `dns_excl_sync` под `fw_lock`; heal вызывает `dns-ensure` | `dns_excl_sync` под тем же lock; heal вызывает `dns-ensure` | Совпадает | `dns-exclusion`, `heal-concurrency` | ДИФ |
| Flow-offload success | `flowoffload_off:1176`, `restore:1192` | `flowoffload_ensure_unlocked:400`, `restore:415` | UCI `1→0→1`, commit/reload, `flow_offloading_hw` не трогается, fw3 no-op | `flowoffload-d2o-differential` | ДИФ |
| Flow-offload write failure | `uci set`/`commit` fail → сообщение, продолжение | `r2o-firewall.sh:407-412` | Совпадает: возврат успеха, работа без offload, состояние `flow-offloading.saved` | `flowoffload-d2o-differential` (failure cases) | ДИФ |
| Flow-offload selective | D2O не делает | **R2O не делает**; остался только `flowoffload_hook_remove` для старой установки | `test-router-flowoffload-d2o-differential.sh:166-169` прямо запрещает `ct mark`/`mark_flow`/`flow offload @` | `flowoffload-lifecycle` | ДИФ; примечания 26/28/66/67/81/83/84/85/86/88/92 устарели |
| Fastnat | `fastnat_off:1116`, `restore:1124` | `fastnat_off:366`, `restore:374` | `nf_conntrack_fastnat`, saved state, восстановление | `fastnat-lifecycle-differential` | ДИФ |
| PPE rule generation | `_d2k_ppe_rules:94`, `ppe_up:575` | `_r2o_ppe_rules:123`, `ppe_ensure_unlocked:463` | 8 правил, порядок, PORTS/voice/HTTP | `ppe-rule-generation-differential` | ДИФ |
| PPE removal errors | `d2k_ppe_remove:162` best-effort → 0 | `r2o_ppe_remove:188` сохраняет коды D2O | 0/1/2/3 | `ppe-removal-error-differential` | ДИФ |
| PPE backend/gate/lock | `ppe_ensure:851`, firewall lock `862-899` | `r2o-firewall.sh:448-481`, lock `361-386` | Совпадает; реальный PPE kernel не проверялся | `ppe-backend`, `ppe-ensure-running`, `ppe-firewall-lock`, `ppe-legacy-cleanup` | ДИФ (mock) |
| Общий firewall-lock | `fw_lock_acquire:862` / `release:883` | `fw_lock_acquire:361` / `release:382` | R2O использует lock для up/down/DNS/flowoffload/PPE | `ppe-firewall-lock`, `dns-exclusion` | ДИФ |
| RST suppression | `nft_rst_ruleset:765`, `rst_owner_removable:820` | `nft_rst_up:285`, `nft_rst_down:322` | R2O добавляет comment/owner; снятие только своей таблицы | `firewall-nft-down-rst-lifetime` | ДИФ |
| Broadcast/multicast/ICMP TE | `fw_return_broadcast:346`, `fw_return_local:356`, `fw_icmp_te_rule:375` | `xt_broadcast_return:569`, inline в `xt_family_up` | Совпадает; fallback без `xt_addrtype` | `firewall-broadcast`, `icmp-guard` | ДИФ |
| `CONNBYTES` late window | `late_rst_from:330` | `late_rst_from:45` | `upper+1`; default 0:8 | `connbytes-boundary` | ДИФ |
| `PORTS` scope | `fw_family_up:385` | `xt_family_up:626` | `multiport` для базовых и поздних правил | `port-scope` | ДИФ |

### B.3 Heal/watchdog, NDM, procd

| Контракт | D2O | R2O | Поведение | Тест | Статус |
|---|---|---|---|---|---|
| Периодический heal | `S99d2k:1341-1353` запускает `d2k-fw-heal.sh` каждые `HEAL_EVERY` (60 с) | `r2o-firewall-watchdog.sh:10-42` каждые `HEAL_EVERY` (60 с), `S99r2o:582-610` | Совпадает по периоду; R2O проверяет cmdline процесса | `firewall-watchdog-differential` | ДИФ |
| Heal-скрипт | `d2k-fw-heal.sh:47-94`: status→если datapath жив; если rules стоят → ppe-ensure + dns-ensure; иначе lock 15 с/60 с → reapply | `S99r2o:888-902`: status→dns-ensure или `heal_reapply`; затем flowoffload-ensure + ppe_ensure | R2O добавляет `flowoffload-ensure` и при его отказе останавливает datapath | `heal-concurrency`, `reapply` | ДИФ/ПРОБЕЛ |
| Lock/cooldown | `HEAL_LOCK` mkdir, `MIN_INTERVAL=15`, `LOCK_STALE=60` | `heal_reapply:858-875` те же 15/60 | Совпадает | `heal-concurrency-differential` (10 прогонов) | ДИФ |
| NDM hook | `001-d2k.sh:25-35`: mangle/nat → heal; nat → дополнительно `telegram-reapply` | `001-r2o.sh:4-9`: nat/mangle → `S99r2o heal` | R2O не разделяет nat/mangle, но heal включает оба; побочный запуск Telegram см. B.1 | — | ДИФ/ПРОБЕЛ |
| OpenWrt procd waiter | `d2k-openwrt-init:23-37`: одноразовый wait `/opt`, `S99d2k start` | `openwrt-init:35-49`: wait, `start`, затем бесконечный `supervise` + `respawn 3600 5 0` | R2O — расширение восстановления; D2O waiter одноразовый | `test-router-openwrt-init.sh`, `test-router-procd-lifecycle-qemu.py` | ДИФ + EXT |
| Crash recovery | D2O полагается на ручной/внешний перезапуск | R2O procd supervise + persisted catalog reapply | Заявлено QEMU-прогоном; C-oracle для автоматического recovery нет | `test-controller-process-reapply-qemu.py` | EXT; не паритет |
| Telegram watchdog | `d2k-tg-watchdog.sh:47-68`: health-файл `D2KH1`, PID/start_ticks/boot_id/heartbeat, max age 15 с; restart через `telegram-restart` | `r2o-telegram-watchdog.sh:70-81`: PID + exe path + `manager --stats` `listener_ready`; restart через `telegram-reapply` | Разные health-контракты. R2O не проверяет boot_id/start_ticks/heartbeat age. `telegram-reapply` может запустить процесс | `test-router-telegram-service` (косвенно) | **ПРОБЕЛ** |
| Watchdog restart limits | 3/900 с, backoff 60→300, limited marker | те же значения и backoff | Совпадает; R2O нормализует ведущие нули/длину | — | ДИФ (по коду) |

### B.4 Обновление, установка, release

| Контракт | D2O | R2O | Поведение | Тест | Статус |
|---|---|---|---|---|---|
| Ночное окно | `d2k-update.sh:223-246`: 03:00–04:59, marker, `AUTOUPDATE` перечитывается | `r2o-update-scheduler.sh:37-68`: 03/04, marker, `auto_update_enabled` | Совпадает | `test-router-update-scheduler.sh` | ДИФ |
| Проверка релиза | `check:95-111`: latest.json + Ed25519 `pkeyutl`, 64-байтная подпись | manager `check_update_in:633`, `verify_manifest` | Совпадает по смыслу | `update-availability`, `update-scheduler` | ДИФ |
| Пропуск текущего | `rid == current` → успех без установки | `already_current` | Совпадает | `update-availability` | ДИФ |
| Bad release | manual разрешён, auto — нет | `auto_retry_blocked`, `should_skip_failed_release` | Совпадает | `update-scheduler`, `update-lifecycle` | ДИФ |
| Скачивание | до stop, `curl`/`wget`, SHA-256 | до stop, manager `download_*`, signed manifest | Совпадает по порядку; R2O использует `--noproxy '*'` | `update-availability` | ДИФ |
| Резервная копия | `previous.tar` всех установленных путей | release slots + previous slot | Разная механика, одинаковая цель | `update-lifecycle`, `signed-install-rollback` | ДИФ |
| Активация | installer `install.sh` + stop/start | `update-stage` → stop → `update-activate` → start → health | R2O разделяет stage/activate; D2O делает внутри installer | `update-availability`, `update-lifecycle` | ДИФ |
| Rollback | tar previous + `S99 start` | manager rollback + router install previous + `start` + health | Совпадает по цели; R2O фиксирует bad previous | `update-lifecycle`, `signed-install-rollback` | ДИФ |
| Подписанная установка | `install.sh:457-490` и `d2k-update.sh:95-111` проверяют manifest и SHA-256 | `scripts/install.sh:429-518` проверяет manifest, SHA-256, listing и размеры; manager `install-archive` проверяет подпись | Оба подписывают bootstrap/release; R2O дополнительно проверяет listing, RAM/flash и слоты | `test-signed-install-rollback.sh` | ДИФ |
| OpenWrt/reboot update | `install.sh` + `S99d2k` | `router/install.sh`, `S99r2o`, procd | Реальный OpenWrt update/reboot не прогонялся; QEMU покрывает procd, не signed update | `test-router-procd-lifecycle-qemu.py` | ПРОБЕЛ |
| Package manifest | `package-release.sh:24-44`: 5 бинарей, 9 арок | `package-release.sh:34-117`: 6 бинарей, 5 арок, meta-ranges | Разные target-наборы; манифест и SHA совпадают по формату | `test-package-release.sh` | ДИФ |
| Bootstrap installer | `scripts/install.sh`: OpenWrt/Keenetic deps, ABI, archive | `scripts/install.sh`: signed manifest, RAM/flash checks, archive listing, rollback | R2O строже; функциональная установка покрыта fixture | `test-router-install-bootstrap.sh`, `test-router-install-lifecycle.sh` | ДИФ |
| Router install | `scripts/install.sh:627+` | `router/install.sh:40+` | Symlink-safe, slots, shim, NDM hook, fw3 include | `test-router-install-lifecycle` | ДИФ |
| Uninstall | `scripts/uninstall.sh`: снимает TG/DNS/PPE/fastnat/flowoffload/RST даже без init | `router/uninstall.sh`: требует активный adapter для stop, иначе отказ; затем удаляет файлы | R2O безопаснее, но не имеет fallback-очистки при отсутствующем адаптере | — | **ПРОБЕЛ** |

### B.5 Telegram/Meta DNS на роутере и конфигурация

| Контракт | D2O | R2O | Поведение | Тест | Статус |
|---|---|---|---|---|---|
| Telegram config export | `tg_config_read` читает файл; S99 не экспортирует env | `export_telegram_config:686-701` экспортирует allowlist env; `--dc-map-path`, `--stats-socket-path`, `--default-domains` | R2O не читает `TG_DIAGNOSTIC_DIRECT_TCP`, `TG_CF_DOMAIN_CACHE_PATH`; `TG_RELAY_*` не поддерживаются | `test-router-tg-firewall` | ДИФ/ПРОБЕЛ |
| Telegram start | `S99d2k:1414-1453`: check-config→pid→firewall start→watchdog | `S99r2o:713-775`: enabled/mode local→manager→firewall→start→listener_ready→firewall start→sync-dc-map→watchdog | R2O ждёт `listener_ready`, пишет `connecting` до готовности | `test-router-telegram-service` | ДИФ/EXT |
| Telegram stop | watchdog→pid→firewall stop | то же + удаление stats socket | Совпадает; R2O удаляет сокет | `test-telegram-stop-order-differential.sh` | ДИФ |
| Telegram restart | stop pid→firewall stop→start | `telegram_stop` (с watchdog)→start | R2O останавливает watchdog, D2O — нет | — | ПРОБЕЛ (безопаснее) |
| Telegram reapply | `telegram_reapply:1470-1474`: disabled/не запущен → 0; иначе TG_FIREWALL heal | `S99r2o:877-886`: disabled → 0; если listener готов → heal + sync-dc-map + watchdog; иначе `telegram_start` | R2O запускает процесс; D2O только лечит правила | `tg-heal` | **ПРОБЕЛ** |
| Mark | `TG_OUTBOUND_SOCKET_MARK=0x31`, firewall `OUTBOUND_MARK=0x31` | `config.rs:509` `0x31`, `r2o-tg-firewall.sh:17`, legacy `0x40000000` | Совпадает; `test-router-tg-mark-differential.sh` | `tg-mark` | ДИФ |
| Telegram firewall nft | `d2k-tg-firewall.sh:39-83` | `r2o-tg-firewall.sh:51-123` | R2O добавляет pair-sets `tg4_pairs/tg6_pairs` и `sync-dc-map` | `test-router-tg-firewall.sh` | ДИФ + EXT |
| Telegram firewall iptables | `ensure4/ensure6:84-125`, `ipt_stop:149` | `ensure4/ensure6:124-177`, `ipt_stop:205` | CIDR/ports/marks совпадают; R2O снимает legacy mark | `test-tg-firewall-nft.sh` | ДИФ |
| Telegram DC-map sync | `tg_dc_write_endpoint_manifest` есть, но в production не вызывается (только `test_dc_map_store.c`) | `dc_discovery::sync_platform_adapter`, `dc_map::write_endpoint_manifest`; S99 `sync-dc-map` | R2O подключил неиспользованную C-функцию; поведение — EXT | `test-router-telegram-service` | EXT |
| Meta DNS scheduler start/stop | `S99d2k:1380-1383` запускает `d2k-instagram-dns-scheduler.sh`, pid, stop `1517` | `S99r2o:519-532` запускает `r2o-telegram --meta-dns-scheduler`, pid, stop `940` | R2O требует `ndmc` и файл ranges; D2O запускает скрипт и тот сам решает | `meta-dns-scheduler-differential` | ДИФ |
| Meta DNS tick | `d2k-instagram-dns-scheduler.sh:100-145`: offset 0–239, 01:00, backoff 30 мин ×2 до 86400, attempt marker | `meta_dns.rs:903-976`: offset 0–239, 01:00, `backoff_after`, attempt marker | Код совпадает; **тест проверяет только start/stop/prerequisites/23 CIDR, не tick/backoff/offset** | `meta-dns-scheduler-differential` | ДИФ/ПРОБЕЛ |
| Meta DNS refresh | `d2k-instagram-dns.sh:177+`: VPS `/resolve` + Meta ranges + TLS verify + 2 pins/host + owned manifest | `meta_dns.rs:309+`: прямой DNS + Meta ranges + TLS verify + manifest | R2O не использует VPS; прямое разрешение — документированная граница | `test-router-meta-dns-remove`, `test-meta-edge-differential` | ДИФ |
| Meta DNS remove | `remove_owned:153-175` | `remove_from_env:836`, `MetaDnsManager::remove` | Совпадает по owned-парам; `test-router-meta-dns-remove-differential.sh` | ДИФ |
| Meta ranges asset | `files/meta-ranges.txt` | `router/files/meta-ranges.txt` | Побайтно совпадает (23 IPv4 CIDR) | `meta-dns-scheduler`, `test-package-release` | ДИФ |
| Meta edge TLS | `d2ktg --check-instagram-ip`, нейтральный SNI | `meta_edge::check_meta_edge`, `--check-instagram-ip` | Совпадает по exit codes 0/1/2; `test-meta-edge-differential.sh` | ДИФ |
| `KEENETIC_POLICY` | `S99d2k:1137-1165`: `ndmc show ip policy` → `--only-mark 0x.../0xffffffff`, при отсутствии — `--only-mark none` | **нет**; только ручной `ONLY_MARK` | **ПРОБЕЛ:** выбор политики Keenetic не перенесён | — | **ПРОБЕЛ** |
| `MEASURE_MARK` | `0x2f`, контроль в firewall | firewall `0x2f`; controller использует `--mark`/`--probe-mark` | Значение сохраняется; в datapath нет отдельного `--measure-mark` | `route-gate-config` | ДИФ/ИСХ |
| `PROBE_MARK` | `0x2e`, distinct от MARK | config default `46`; S99 передаёт controller при !=0 | Заявлено `test-router-route-gate-config.sh` | ДИФ |
| Log maintenance | `d2k-log-maintenance.sh:68-75`: 9 имён, включая `instagram-dns.log`, `instagram-dns-scheduler.log`, `update.log` | `r2o-log-maintenance.sh:63-70`: 7 имён, **без Meta DNS логов** | **ПРОБЕЛ:** неограниченный рост `instagram-dns*.log` | `test-router-log-maintenance.sh` | ДИФ/ПРОБЕЛ |
| Config defaults | `S99d2k:83-123`: `MODE=apply`, `MARK=0x2d`, `PROBE_MARK=0x2e`, `MEASURE_MARK=0x2f`, `PORTS`, `CONNBYTES`, `VOICE_*`, `HTTP_KEEPALIVE` | `S99r2o:30-85` + `config.default`: `MODE=observe` fallback, `MARK=45`, `PROBE_MARK=46`, `QUEUE_NUM6`, `IPV6_ENABLED`, `ONLY_MARK`, `AUTOUPDATE`, `FW_BACKEND`, `DNS_PORTS` | При **отсутствующем** конфиге D2O применяет (`apply`), R2O наблюдает (`observe`) | `route-gate-config` | ПРОБЕЛ (edge) |
| Old `d2khttp` cleanup | `legacy_http_pid/present/stop:222-245`; вызовы в start/stop/reapply | нет (R2O — отдельный продукт; firewall снимает D2K_HTTP-цепочки) | Процесс старого продукта не останавливается; правила снимаются | — | N/A (миграция) |

### B.6 Тесты router: фактическое покрытие

В CI shell-job запускаются все 40 `scripts/test-router-*.sh`. Большинство — shell/command-fixture с mock `nft`/`iptables`/`uci`/`procd`, а не live kernel. Live-прогоны: `test-router-firewall.sh` (root), `test-meta-edge-differential.sh`, QEMU procd/process-reapply. В этом окружении ни один не запускался (нет `git`/`cargo`, нужен donor-clone).

Ключевые скрипты по заявленным контрактам:

- nft/iptables: `test-router-firewall.sh`, `test-router-firewall-status-differential.sh`, `test-router-iptables-status-differential.sh`, `test-firewall-rule-error-differential.sh`, `test-firewall-nft-failure-differential.sh`, `test-firewall-nft-legacy-iptables-differential.sh`, `test-firewall-nft-down-rst-lifetime-differential.sh`.
- flow-offload: `test-router-flowoffload-d2o-differential.sh`, `test-router-flowoffload-lifecycle-differential.sh`, `test-router-flowoffload-fw3-fallback-differential.sh`. Selective-скрипта нет.
- fastnat: `test-router-fastnat-lifecycle-differential.sh`.
- PPE: `test-router-ppe-rule-generation-differential.sh`, `-backend-`, `-ensure-running-`, `-legacy-cleanup-`, `-firewall-lock-`, `-removal-error-`, `test-router-ppe-deoffload.sh`, `test-router-ppe-service.sh`.
- DNS: `test-router-dns-exclusion-differential.sh`.
- heal/watchdog: `test-router-reapply-differential.sh`, `test-router-heal-concurrency-differential.sh`, `test-router-firewall-watchdog-differential.sh`, `test-router-firewall-status-differential.sh`.
- update: `test-router-update-availability-differential.sh`, `test-router-update-lifecycle.sh`, `test-router-update-scheduler.sh`, `test-router-update-panel-disabled-differential.sh`, `test-signed-install-rollback.sh`, `test-router-update-auto.sh`.
- procd: `test-router-openwrt-init.sh`, `test-router-process-supervisor.sh`, `test-router-procd-lifecycle-qemu.py`, `test-controller-process-reapply-qemu.py`.
- IPv6: `test-router-ipv6-fallback-differential.sh`.
- Telegram: `test-router-tg-firewall.sh`, `test-router-tg-mark-differential.sh`, `test-router-route-gate-config.sh`, `test-router-telegram-service.sh`, `test-telegram-stop-order-differential.sh` (последний **не** входит в CI-glob `test-router-*`).
- Meta DNS: `test-router-meta-dns-scheduler-differential.sh`, `test-router-meta-dns-remove-differential.sh`, `test-meta-edge-differential.sh`.

## 4. C. Telegram: C-модули и Rust-реализация

### C.1 Карта модулей

| C D2O (функций по `function-index.md`) | Rust R2O | Что покрыто | Тест/проверка | Статус |
|---|---|---|---|---|
| `config.c` (9): `tg_config_read/clean`, shell-value, domain/boolean/uint | `config.rs:426+` (clap/env), `with_defaults:458`, `normalize_cf_worker_domain:476`; router `export_telegram_config` | Ключи через env, не через файл; domain lists нормализуются/отбрасываются, а не валидируются фатально | `tests/config.rs`, `config.rs` unit | ИСХ/ПРОБЕЛ |
| `identity.c` (12): load/mint, public key, sign/verify, HMAC hex | `identity.rs:20+` (Ed25519, формат `R2OTGID1`) | Создание identity; **нет** enroll-proof/HMAC | `--init-identity`, unit | ИСХ/ПРОБЕЛ (нет потребителя) |
| `dc_map.c` (13): builtin endpoints, validate, resolve | `dc_map.rs:353-466` | builtin/validate/lookup/merge | `tests` + donor | ИСХ |
| `dc_map_json.c` (16) | `dc_map.rs:61-99` (serde) | JSON parse/encode | `dc_map.rs` unit | ИСХ |
| `dc_map_store.c` (27): load/install/refresh, merge, endpoint manifest | `dc_map.rs:125-580`; `write_endpoint_manifest:155` | Persist/merge/manifest; R2O вызывает manifest в production (D2O — только тест) | `dc_discovery` unit | ИСХ + EXT |
| `dc_discovery`/`mtproto_config.c` (11): `help.getConfig`, dcOption | `dc_discovery.rs:47` `fetch_config`, `config_to_snapshot`; grammers TL | Полный getConfig/DC options | `dc_discovery.rs` unit | ИСХ |
| `mtproto_auth.c` (27): step2/3/4 | `dc_discovery.rs:342` `grammers_mtproto::Encrypted` | Аутентификация через grammers | `tests` + mock DC | ИСХ (donor) |
| `mtproto_crypto.c` (12): CTR, AES-IGE, obfuscated2, secret, relay init | `crypto.rs:82` `parse_handshake`, `direct_stream_ciphers:233`, `generate_relay_init:139` | obfuscated2/secret/DC/proto | Rust unit; **нет C-векторов** | ТЕСТ/ПРОБЕЛ |
| `mtproto_encrypted.c` (4): v2 encrypt/decrypt | `grammers_mtproto::mtp::Encrypted` | v2-обмен | donor unit; **нет C-векторов** | ИСХ/ПРОБЕЛ |
| `mtproto_splitter.c` (12) | `splitter.rs` + `tests/splitter.rs` | intermediate/abridged, partial, flush | Rust unit 8 тестов; **нет C-дифференциала** | ТЕСТ/ПРОБЕЛ |
| `mtproto_probe.c` (39): resPQ/TCP/WSS/matrix | `dc_discovery.rs:103` `probe_res_pq`, `ws_client`; `diagnostics.rs` | resPQ и маршрутная матрица; D2O-матрицы как CLI отсутствуют | `--check`, unit | ИСХ |
| `route_dns.c` (49): DoH/DoT/H2/DNS cache/prefetch | `cf_proxy_doh.rs`, `routing.rs`, system DNS | CF-proxy DoH + system DNS; **не** полноценный DoH/DoT-резолвер D2O | `d2o_route_dns_public_ip_differential.c`, fixture | ДИФ (узкий) |
| `route_plan.c` (6): WS DC, CF hostname, plan | `config::websocket_dc:115`, `routing.rs`, `ws_client::cf_*` | DC→WSS/CF | `ws_client` unit | ИСХ |
| `tls.c` (4): client ctx/connect/SNI | `ws_client.rs` rustls, `meta_edge.rs` | TLS verification/handshake | `tests/ws_client`, `tls-verify` | ИСХ |
| `listener.c` (8): SO_ORIGINAL_DST, self-dial | `transparent.rs:95` `original_destination`, `supports_destination_port:24`, `is_telegram_destination:29` | v4/v6 original dst + policy | `tests/transparent.rs` 13 тестов | ТЕСТ |
| `transparent.c` (6): destination/policy/handshake/select | `transparent.rs`, `transparent_proxy.rs:246` | ports/CIDR, self-dial, secret, DC/media/proto, TCP-only | `tests/transparent.rs` | ТЕСТ |
| `epoll_proxy.c` (101): listener, buffers, retries, stats, lifecycle | `server.rs`, `transparent_proxy.rs`, `bridge.rs`, `routing.rs`, `stats.rs`, `ws_client.rs` | Tokio-архитектура вместо epoll; донорское покрытие | donor tests + service harness | ИСХ |
| `cf_domains.c` (19): remote/cache/fallback | `cf_domain_pool.rs`, `default_domains.rs` | remote/cache/fallback/refresh | `cf_domain_pool` unit | ИСХ |
| `net.c` (2) | `outbound/connector.rs` | TCP connect + SO_MARK + timeout; R2O добавляет IPv6 | `tests/outbound.rs` | ИСХ |
| `limits.c` (3): nofile, auto max, memory budget | `limits.rs:47` `auto_max_connections` | Только nofile/hedge; **memory budget отсутствует** | `tests/limits.rs` | **ПРОБЕЛ** |
| `memory_budget.c` (2) | нет | — | — | **ПРОБЕЛ** |
| `stats_socket.c` (10) | `stats.rs:127-720` | JSON snapshot + Unix socket; другая схема | `test-router-telegram-service` | ДИФ/EXT |
| `ws.c` (18): frame encode/decode, upgrade | `ws_client.rs` (tungstenite) | TLS/Upgrade/frames | `tests/ws_client` 3 теста | ИСХ |
| `ws_pump.c` (20): pump/reassembly | `bridge.rs`, `ws_client.rs` | ASCII/binary pump, reassembly | donor tests | ИСХ |
| `enroll.c` (1): `tg_enroll_proof` | нет | — | — | **N/A (VPS)** |
| `main.c` (29): local daemon, checks, matrices | `main.rs` + `server.rs` | `--check`, `--stats`, `--resolve-meta`, scheduler, identity | `--check` (исторический прогон) | ИСХ/ПРОБЕЛ |

### C.2 CLI и конфигурация

| D2O | R2O | Комментарий |
|---|---|---|
| `--config FILE` | `--config` нет; конфиг читает shell и экспортирует env | R2O config.rs не парсит `/opt/r2o/config`; `TG_*` env |
| `--check-config` | `--check` (диагностика) | Разные вещи: D2O проверяет только конфиг, R2O — маршруты |
| `--check-telegram-dc[-matrix]`, `--discover-telegram-dc[-matrix]` | нет прямых аналогов; `--check` по 5 DC | Частичное покрытие |
| `--check-telegram-wss-matrix` | `--check` (tcp-fallback/direct-wss/cf-worker/cf-proxy) | CF-маршруты в историческом прогоне `unverified` |
| `--check-instagram-ip` | `--check-instagram-ip` | Совпадает |
| `--health-file`, `--log` | `--log-file`, env; health пишет сервер | Формат `R2OH1` |
| `--version` | `--version` | R2O печатает release/wire/features |
| `TG_PORT` только 1443 | любой 1..65535 | **ПРОБЕЛ/EXT** |
| `TG_CF_DOMAIN` ≤32, ошибка валидации | без лимита; `--cf-domain` не валидируется на старте | **ПРОБЕЛ** |
| `TG_CF_WORKER_DOMAIN` ≤8, ошибка валидации | ≤8; clap-валидатор отвергает невалидное имя, `with_defaults` дополнительно дедуплицирует/усекает | Отличие в моменте/форме ошибки |
| `TG_DIAGNOSTIC_DIRECT_TCP` | нет | **ПРОБЕЛ** |
| `TG_CF_DOMAIN_CACHE_PATH` | путь выводится из `--dc-map-path` | Отличие конфигурации |
| `D2K_TG_CA_BUNDLE` | `TG_CA_BUNDLE` | Совпадает по смыслу |

### C.3 Что реально проверено

- **Unit/integration:** `cargo test -p r2o-telegram` (CI job). Покрывает config, crypto, limits, splitter, transparent, ws_client, outbound, runtime, server, product name. Это тесты Rust-реализации, не C/Rust паритет.
- **Узкие C/Rust дифференциалы:** route-DNS public IP filter и MTProto response observer (fixtures, `clang-18`, cargo). В этом окружении не запускались; ширина — только эти два контракта.
- **Service harness:** `test-router-telegram-service.sh` (x86_64 Linux release): запуск, stats/data-plane, DC-map sync, SIGKILL recovery, лимит двух перезапусков. Матрица заявляет успешный прогон; здесь не воспроизводился.
- **`--check`:** по матрице, под root на release: `tcp-fallback` и `direct-wss` healthy для всех пяти DC, MTProto 76–511 мс; CF-worker/CF-proxy `unverified`. Длительная transparent-сессия и реальные CF-маршруты не проверены.
- **C-оракулы D2O Telegram:** `make test` в чистом дереве проходил (по матрице). C-тесты `test_mtproto_auth`, `test_mtproto_encrypted`, `test_mtproto_splitter`, `test_epoll_proxy` не сопоставлены с Rust дифференциалами; используется только source-сравнение донора.

### C.4 Неперенесённые C-функции и Rust-only расширения

**Неперенесено/заменено архитектурно:**
- `memory_budget.c` целиком; `tg_limits_runtime_memory_budget`; жёсткий `configured_max_connections=64` (`main.c:415-416`). R2O считает лимит только по `nofile` и hedge, без memory cap. На 128-МиБ роутере это может дать ~495 соединений против 64 у D2O.
- `enroll.c::tg_enroll_proof`, `tg_register_hmac_hex` (нет потребителя; relay вне области).
- Полный файловый парсер `tg_config_read` (shell-value, duplicate-key rejection, `TG_PORT=1443`).
- `route_dns.c` как самостоятельный DoH/DoT/H2-резолвер с кэшем/префетчем; R2O использует system DNS и CF-proxy DoH.
- `TG_DIAGNOSTIC_DIRECT_TCP` и D2O-матрицы `--check-telegram-*-matrix`.
- `stats_socket.c` legacy-схема: R2O выдаёт donor-схему (`mtproto_success`, `wss_established`, `dc_map`, `cf_domain_pool`, `workers`, `sessions_by_dc_transport`, `failures`, `ttfb`); панель принимает обе.

**Rust-only расширения:**
- directional byte telemetry в `transparent_proxy`/`stats`;
- MTProto response validator в `bridge.rs`;
- platform DC-map sync (`sync_platform_adapter`, pair-sets в Telegram firewall);
- `telegram-check`, `--resolve-meta`, `--refresh-meta-dns`, `--remove-meta-dns`, `--meta-dns-scheduler`;
- meta edge TLS checker и direct Meta DNS без VPS;
- dual-schema приём stats в panel.

### C.5 Пробелы Telegram

1. Memory budget/лимит 64 соединения не перенесён; фактический лимит зависит от `ulimit -n`.
2. Stats-сокет R2O читает запрос без таймаута: локальный клиент, подключившийся и молчащий, блокирует accept-loop и может провоцировать watchdog-restart.
3. `--cf-domain` (CF proxy) не валидируется и не ограничен 32 именами, тогда как D2O отказывает в конфигурации; `TG_CF_WORKER_DOMAIN` валидируется clap-парсером, но список после разбора дедуплицируется/усекается.
4. `TG_PORT` restriction 1443 не сохранён (R2O расширяет диапазон; не потеря функциональности, но расхождение).
5. `TG_DIAGNOSTIC_DIRECT_TCP` отсутствует.
6. C-векторы `mtproto_encrypted`/`mtproto_splitter`/`mtproto_auth` не используются в Rust-дифференциалах.
7. Полный `transparent` data path с реальным Telegram-клиентом, CF-worker/CF-proxy и длительной сессией не проверялся.
8. `identity` не имеет production-потребителя (создаётся, но не участвует в протоколе).

## 5. D. Исключённые VPS: `relay-enroll` и `relay-gate`

### D.1 `relay-enroll`

Назначение: публичная саморегистрация установок и выдача адресов Meta для роутера. Отдельный C-бинарник, TLS 9443, systemd unit.

| Компонент/функции | Назначение | R2O | Статус |
|---|---|---|---|
| `main.c` 45 production-функций: `rate_allow`, `shared_limits_create`, `dead`, `shared_unlock`, `limits_lock/unlock`, `conn_admit/set_pid/release_*`, `conn_route`, `route_status`, `valid_proof`, `parse_headers` | TLS/HTTP-сервер, пулы соединений, rate-limit 6/IP/мин + 120/мин, proof 120 байт, bootstrap | нет | N/A (unported) |
| `system_resolve`, `dns_build_query`, `dns16`, `dns_read_name`, `dns_parse_reply`, `udp_open/send/recv/close`, `addr_add`, `answer_cache_*`, `cache_get/put`, `public_phase` | `/resolve`: union VPS getaddrinfo + UDP 1.1.1.1/8.8.8.8/9.9.9.9, allowlist 18 имён, cache 10 мин, бюджет 1.5 с | нет | N/A |
| `json_space/char/name`, `allowed_host`, `handle_resolve`, `socket_write_all` | Строгий разбор `/resolve` (≤2048 байт, ≤32 имени, без escape/лишних ключей) | нет | N/A |
| `forward_registration`, `ssl_write_all`, `reply_json`, `reply`, `serve_client`, `stop_server`, `child_exited`, `main` | `/register`, `/resolve`, `/health`, fork-модель, TLS | нет | N/A |
| `test.c` 34 функции | Юнит-тесты proof/rate/pools/DNS/HTTP/upstream | нет | N/A |
| `d2k-enroll.service` | `User=nobody`, `LoadCredential=bootstrap`, `Restart=on-failure`, `MemoryMax=128M`, `TasksMax=64`, `LimitNOFILE=256` | нет | N/A |
| `install-server.sh` | Копирует bootstrap из `/etc/z2k/secrets.env`, ставит бинарник/unit, `systemctl enable/restart` | нет | N/A |

### D.2 `relay-gate`

Назначение: allowlisted CONNECT/HTTP-прокси для установки/обновления на VPS. C-бинарник, порт 9444, systemd unit.

| Компонент/функции | Назначение | R2O | Статус |
|---|---|---|---|
| `host_allowed`, `host_syntax_ok`, `parse_port`, `split_hostport` | Allowlist 8 хостов (GitHub, Entware, OpenWrt) | нет | N/A |
| `parse_head`, `request_allowed`, `header_is`, `build_origin_request` | Только CONNECT:443 и GET/HEAD http:80; origin-form, удаление Proxy-* | нет | N/A |
| `v4_public`, `addr_public` | Запрет приватных upstream-адресов | нет | N/A |
| `rate_allow` | 128 соединений, 180/IP/мин, 6000/мин, 15 с head, 10 с connect, 120 с idle | нет | N/A |
| `write_all`, `reply`, `connect_timeout`, `dial`, `relay`, `serve`, `main` | Прозрачный relay, журнал, лимиты | нет | N/A |
| `test.c` 11 функций | Hosts/parse/allowed/rebuild/addresses/rate | нет | N/A |
| `d2k-gate.service` | `User=nobody`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, `MemoryMax=64M`, `TasksMax=160`, `LimitNOFILE=1024` | нет | N/A |
| `install-server.sh` | Установка бинарника/unit, `systemctl enable/restart` | нет | N/A |

### D.3 Подтверждение области и скрытые аналоги

- `README.md:5`: «главный сценарий: локальный обход на роутере… без обязательного VPS, удалённого relay или WARP».
- `README.md:145`: Telegram не требует VPS/WARP; listener local.
- `README.md:310`: «Основной обход не требует VPS, relay или WARP».
- `router/README.md:52-55`: `D2K_GATE` сохраняется только как исключение IPv4 TCP endpoint из NFQUEUE; «само по себе не задаёт транспорт обновлений R2O».
- `docs/functional-parity-matrix.md:9` и `parity-function-inventory.md:9`: серверные реализации relay не перенесены и не оцениваются.
- Проверка дерева R2O: нет `relay-enroll`/`relay-gate`, нет `systemctl`/systemd-юнитов, нет портов 9443/9444, `/register`, `nip.io`, `enroll_proof`, `tg_register_hmac_hex`. `r2o-manager` использует `--noproxy '*'` и не применяет gate.
- **Вывод:** скрытого/частичного аналога VPS нет. Единственные следы: (1) совместимое исключение `D2K_GATE` в firewall, (2) `identity.rs` без потребителя, (3) `release_download_hosts` — allowlist GitHub для скачивания, не прокси. Все функции D — `N/A (unported)`, баллы не начисляются.

## 6. Дубли и слишком широкие пункты матрицы

1. **Panel «control/actions, прочие status branches, настройки и assets» (1 балл)** объединяет 22 дифференциала и 8 route-групп, включая control, workers, update, diagnostics, static, telegram. Один балл не отражает ни объём, ни найденные пробелы.
2. **Telegram «config/DC map, handshake, MTProto/WebSocket retries и full service lifecycle» (1 балл)** объединяет конфиг, DC-map, crypto, splitter, auth, WSS, CF, service lifecycle и stats; статус «реализовано, паритет частичный» скрывает 8 конкретных пробелов.
3. **«Update activation ordering, rollback recovery and signed Linux/OpenWrt install» (1 балл)** объединяет stage/activate, rollback, signed install, health wait, OpenWrt/procd. Signed x86_64 test не доказывает OpenWrt ABI/reboot.
4. **«Firewall: static packet rules and backend» (1 балл)** дублирует «Firewall: error code per rule» (1) и частично «IPv4-only fallback / modules / marker» (2). Один и тот же генератор правил фигурирует в трёх строках.
5. **Flow-offload** разбит на success (1) и write-failure (1), но примечания 20/26/28/66/67/81/83/84/85/86/88/92 описывают selective-реализацию, которой в коде нет; это дублирующиеся/устаревшие пункты.
6. **«Firewall service: heal/watchdog, reapply и ошибки» (1 балл)** объединяет heal, reapply, cooldown, watchdog, NDM hook и status; разные контракты с разной степенью доказанности.
7. **PPE (1 балл)** объединяет rule generation, backend, gate, legacy cleanup, lock и failure codes; тесты mock, реальный PPE kernel не проверялся.
8. **Telegram «route/DNS» и «Meta DNS scheduler»** частично пересекаются: DNS exclusions на роутере, Meta resolver, firewall route gate. Сейчас это разные строки с разными oracle.
9. **Panel «bind» и «select-panel-ip»** дублируются в installer-тестах; один контракт разрезан на bind-default, select-panel-ip, panel-bind-install.
10. **S99/procd (1)** и **crash/restart (1)** пересекаются: waiter dispatch и автоматическое восстановление — разные контракты, но evidence-скрипты частично одни и те же.

## 7. Предлагаемое разбиение контрактов

Веса предложены по критичности (3 — сетевой/сохраняемый контракт, 2 — жизненный цикл/повтор, 1 — вспомогательный). **Баллы не начисляются:** колонка «факт» фиксирует только наличие доказательства в дереве, а не результат прогона.

### A. Panel

| # | Контракт | Вес | Факт (в аудите) |
|---|---|---:|---|
| A1 | Bind по умолчанию и выбор LAN IP при установке | 1 | ДИФ-скрипты есть; не перезапускались |
| A2 | Пустой `PANEL_LISTEN` отключает панель и health update | 1 | ДИФ есть |
| A3 | Парсер: комментарии, кавычки, хвостовые комментарии | 1 | ДИФ есть; незакрытая кавычка — пробел |
| A4 | Парсер: unknown keys, не-UTF-8, ignored bytes | 1 | ДИФ есть |
| A5 | Совместимость known-list с D2O-конфигом | 1 | **не доказано/пробел** |
| A6 | Лимит заголовка 32 КиБ и код 431 | 1 | ДИФ; точная граница не проверена |
| A7 | Абсолютный дедлайн заголовка 5 с / 408 | 1 | ДИФ |
| A8 | Абсолютный дедлайн ответа 5 с | 1 | **нет дифференциала** |
| A9 | Устойчивость к обрыву клиента/IO-ошибке | 1 | **нет дифференциала; расхождение** |
| A10 | Неизвестный маршрут/метод/HTTP-версия | 1 | ТЕСТ |
| A11 | `/api/status`: unavailable-контракт | 1 | ДИФ |
| A12 | `/api/status`: live shape и catalog revision | 1 | ДИФ (семантика) |
| A13 | `/api/status`: snapshot/stages/unknown_keys | 1 | частично; порядок ключей/`unknown_keys` не доказаны |
| A14 | `/api/control`: список действий, коды, gates | 2 | ДИФ для stop/success/busy/500 |
| A15 | Action state machine и timeout (включая 124) | 2 | ДИФ timeout; 124 — пробел |
| A16 | Workers GET и байты конфига | 1 | ДИФ |
| A17 | Workers POST: Content-Type/TE/CL/JSON/8 доменов | 2 | ДИФ |
| A18 | Workers POST: busy до записи | 2 | ДИФ |
| A19 | Атомарная запись и сохранение режима | 1 | ДИФ по байтам; режим/umask не доказан |
| A20 | Telegram config gate/status | 1 | ДИФ |
| A21 | Telegram stats: лимит, схема, таймаут | 1 | ДИФ по размеру; абсолютный таймаут — пробел |
| A22 | `/api/update` absent/never/raw | 1 | ДИФ |
| A23 | Diagnostics GET/POST/download | 1 | ДИФ |
| A24 | Static assets: ETag/304/1 МиБ | 1 | ДИФ |
| A25 | Static assets: missing/symlink/embedded fallback | 1 | ТЕСТ; C 404 vs Rust fallback |
| A26 | CLI `--version`/`serve`/`--self-check`/`--release-id` | 1 | частично; self-check отсутствует |

### B. Router

| # | Контракт | Вес | Факт |
|---|---|---:|---|
| B1 | Config defaults и совместимость ключей | 1 | частично; `MODE` fallback и `KEENETIC_POLICY` — пробелы |
| B2 | Start order: engine→telegram→panel→schedulers | 2 | ДИФ |
| B3 | Stop order и восстановление fastnat/offload | 2 | ДИФ |
| B4 | Engine start: queue wait, firewall, controller, watchdog | 2 | ДИФ |
| B5 | Engine stop: порядок и коды | 2 | ДИФ |
| B6 | `engine-restart`/`settings-restart` | 1 | ДИФ/пробел `MODE=off` |
| B7 | Panel lifecycle и disabled panel | 1 | ДИФ |
| B8 | `status` (поля и коды) | 1 | ДИФ; текстовый формат отличается |
| B9 | `clear-found`: все state-файлы | 2 | **пробел (`https-cache.json`)** |
| B10 | nft backend: генерация и postconditions | 3 | ДИФ (mock) |
| B11 | iptables backend: генерация и postconditions | 3 | ДИФ (mock) |
| B12 | Код ошибки отдельного правила | 1 | ДИФ |
| B13 | nft rollback и RST-table cleanup | 2 | ДИФ |
| B14 | Legacy D2K cleanup | 2 | ДИФ |
| B15 | RST table lifetime | 2 | ДИФ |
| B16 | Status nft completeness | 2 | ДИФ |
| B17 | Status iptables completeness | 2 | ДИФ |
| B18 | IPv6 fallback + marker + reapply | 2 | ДИФ |
| B19 | DNS upstream exclusions/refresh | 2 | ДИФ |
| B20 | Flow-offload disable/restore | 2 | ДИФ |
| B21 | Flow-offload write-failure | 1 | ДИФ |
| B22 | Fastnat lifecycle | 1 | ДИФ |
| B23 | PPE rule generation/order | 2 | ДИФ |
| B24 | PPE removal error codes | 1 | ДИФ |
| B25 | PPE backend/gate/lock | 2 | ДИФ (mock) |
| B26 | Firewall lock/reapply | 1 | ДИФ |
| B27 | Heal: status/ppe/dns | 2 | ДИФ |
| B28 | Heal concurrency/cooldown | 2 | ДИФ |
| B29 | Firewall watchdog period/start-stop | 1 | ДИФ |
| B30 | NDM hook nat/mangle | 1 | ДИФ |
| B31 | S99/procd waiter и detach | 1 | ДИФ |
| B32 | Automatic crash recovery/reapply | 2 | EXT; C-oracle нет |
| B33 | Update guard/availability | 2 | ДИФ |
| B34 | Stage→stop→activate→start порядок | 2 | ДИФ |
| B35 | Rollback + bad release + health | 2 | ДИФ |
| B36 | Signed bootstrap/install | 2 | ДИФ (x86_64) |
| B37 | OpenWrt ABI/reboot update | 2 | **не доказано** |
| B38 | Package release manifest/assets | 1 | ДИФ |
| B39 | Router install lifecycle | 2 | ДИФ |
| B40 | Uninstall и аварийная очистка | 1 | **пробел** |
| B41 | Telegram start/stop/restart | 2 | ДИФ |
| B42 | Telegram reapply semantics | 2 | **пробел (запускает процесс)** |
| B43 | Telegram mark/gate | 1 | ДИФ |
| B44 | Telegram firewall nft/iptables | 2 | ДИФ |
| B45 | Telegram DC-map sync | 1 | EXT |
| B46 | Telegram watchdog health contract | 2 | **пробел** |
| B47 | Meta DNS scheduler lifecycle | 1 | ДИФ |
| B48 | Meta DNS offset/backoff/tick | 2 | **не доказано** |
| B49 | Meta DNS ranges asset | 1 | ДИФ |
| B50 | Meta DNS edge verification | 1 | ДИФ |
| B51 | Meta DNS owned-record removal | 1 | ДИФ |
| B52 | Log maintenance: все owned-логи | 1 | **пробел** |
| B53 | `KEENETIC_POLICY` → `--only-mark` | 2 | **не перенесено** |
| B54 | Migration cleanup старого `d2khttp` | 1 | N/A/пробел |

### C. Telegram

| # | Контракт | Вес | Факт |
|---|---|---:|---|
| C1 | Config file/env mapping и валидация | 2 | частично; CF-домены/TG_PORT/диагностика — пробелы |
| C2 | Identity/ed25519 и его потребитель | 1 | EXT; потребителя нет |
| C3 | DC map persist/merge/validate | 2 | ИСХ + unit |
| C4 | `help.getConfig` и dcOption | 2 | ИСХ + unit |
| C5 | obfuscated2/secret/DC/media/proto | 2 | ТЕСТ; C-векторов нет |
| C6 | MTProto splitter | 2 | ТЕСТ; C-дифференциала нет |
| C7 | v2 encrypted | 1 | ИСХ; C-векторов нет |
| C8 | resPQ probe | 1 | ИСХ |
| C9 | DC→WSS/CF route plan | 2 | ИСХ |
| C10 | Route DNS/DoH/DoT | 2 | ДИФ (узкий) |
| C11 | TLS verification/SNI | 1 | ИСХ/ТЕСТ |
| C12 | WS upgrade/frames | 2 | ИСХ |
| C13 | CF domain pool refresh/cache | 2 | ИСХ |
| C14 | CF proxy DoH | 2 | ИСХ |
| C15 | Transparent listener/SO_ORIGINAL_DST | 2 | ТЕСТ |
| C16 | Transparent policy ports/CIDR/self-dial | 2 | ТЕСТ |
| C17 | Official secret/DD | 2 | ТЕСТ |
| C18 | Retry/cooldown/routing policy | 2 | ИСХ |
| C19 | Stats schema и Unix socket | 2 | ДИФ/EXT |
| C20 | Stats request protocol robustness | 1 | **пробел (нет таймаута)** |
| C21 | Response observer | 1 | ДИФ (fixture) |
| C22 | Connection/memory limits | 2 | **пробел (memory budget)** |
| C23 | Diagnostics `--check` | 2 | ИСХ; CF unverified |
| C24 | Service lifecycle/recovery | 2 | ТЕСТ (harness) |
| C25 | Meta DNS direct resolve/scheduler | 2 | ДИФ |
| C26 | Panel/shell integration | 1 | ДИФ |

### D. VPS (вне области, без баллов)

| # | Контракт | Вес | Факт |
|---|---|---:|---|
| D1 | relay-enroll `/register` proof/rate/TLS | 0 | N/A (unported) |
| D2 | relay-enroll `/resolve` DNS allowlist/cache | 0 | N/A (unported) |
| D3 | relay-gate allowlisted CONNECT/HTTP proxy | 0 | N/A (unported) |
| D4 | Router-side D2K_GATE как транспорт обновления | 0 | N/A; R2O использует `--noproxy '*'`, сохранено только NFQUEUE-исключение |

## 8. Блокеры и следующие проверки

1. **Воспроизвести panel-дифференциалы** в Linux с D2O `304ba893` и текущим R2O: все 22 `test-panel-*.sh` + `r2o-panel-bind-default-differential.sh`. Отдельно добавить:
   - `test_response_deadline` (медленный клиент на теле ответа);
   - reset во время чтения заголовка;
   - незакрытая кавычка в `PANEL_LISTEN`/`STATE_DIR`;
   - known-list D2O-конфига (`TG_RELAY_*`, `TG_ENROLL_PORT`, `D2K_PPE_DEOFFLOAD`);
   - `unknown_keys` на `config.default` R2O;
   - точная граница 32 КиБ, non-UTF-8 заголовок, path >255.
2. **Router:** прогнать все 40 `test-router-*.sh` в CI-режиме с `d2o-current`; отдельно добавить:
   - `clear-found` с `https-cache.json`/`measurements`;
   - `KEENETIC_POLICY` (наличие/отсутствие политики и `--only-mark none`);
   - heal при остановленном Telegram (D2O не запускает, R2O запускает);
   - `engine-restart` при `MODE=off`;
   - `dns-tick/dns-refresh/dns-remove` интерфейс;
   - log rotation для `instagram-dns*.log`;
   - uninstall при отсутствующем adapter;
   - Meta DNS tick/offset/backoff (сейчас тест только lifecycle).
3. **Flow-offload:** привести примечания 20/26/28/66/67/81/83/84/85/86/88/92 в соответствие с текущим кодом (глобальное выключение); удалить/пометить отсутствующий `test-router-flowoffload-selective-differential.sh`; добавить отдельный контракт «write-failure + восстановление UCI» если он нужен.
4. **Telegram:** добавить differential C-векторов для `mtproto_encrypted`, `mtproto_splitter`, `mtproto_auth`; решить, нужен ли memory budget; добавить таймаут чтения запроса stats-сокета; выровнять валидацию CF-доменов; проверить длительную transparent-сессию и CF-маршруты.
5. **VPS:** оставить `N/A (unported)`; не начислять баллы. Если когда-либо понадобится совместимость с D2O-инфраструктурой, отдельно описать `D2K_GATE` и `TG_RELAY_URL` как миграционные ключи, не как паритет.

## 9. Приложение: что именно проверялось в исходниках

- Panel C: `E:\d2o\panel\server.c` (1480 строк), `main.c` (494), `test_server.c`, `test_*` fixtures; Rust: `crates/r2o-panel/src/server.rs` (3183), `main.rs`, `tests/http.rs`, `tests/cli.rs`, `tests/d2o_*.c`, `tests/browser.cjs`.
- Router C: `files/S99d2k` (1647), `d2k-openwrt-init`, `config`, `d2k-fw-heal.sh`, `d2k-update.sh`, `d2k-ppe-deoffload.sh`, `d2k-tg-firewall.sh`, `d2k-tg-watchdog.sh`, `d2k-instagram-dns*.sh`, `scripts/install.sh`, `package-release.sh`, `select-panel-ip.sh`; Rust: `router/S99r2o` (1127), `openwrt-init`, `r2o-firewall.sh`, `r2o-ppe-deoffload.sh`, `r2o-tg-firewall.sh`, `r2o-telegram-watchdog.sh`, `r2o-update-scheduler.sh`, `r2o-log-maintenance.sh`, `install.sh`, `uninstall.sh`, `select-panel-ip.sh`, `r2o-manager/src/*`.
- Telegram C: `telegram/src/*.c` (26 модулей, 460 функций по индексу), `include/*.h`, `test_*.c`; Rust: `crates/r2o-telegram/src/*.rs` (24 модуля + подмодули), `tests/*.rs`.
- VPS: `relay-enroll/main.c`, `test.c`, `Makefile`, `README.md`, `d2k-enroll.service`, `install-server.sh`; `relay-gate/main.c`, `test.c`, `Makefile`, `README.md`, `d2k-gate.service`, `install-server.sh`.
- CI: `.github/workflows/ci.yml` (panel/telegram/shell/datapath jobs), `scripts/ci-differential-shards.sh`.

**Ограничение:** это аудит исходников и тестовой инфраструктуры. Ни один C/Rust differential, cargo-тест, QEMU-прогон или shell-harness в этом окружении не выполнялся. Утверждения «ДИФ» означают наличие проверяемого сценария, а не подтверждённый результат.
