# Карта владения файлами для параллельных агентов

Точка старта: `b4e3983` (main). Донор C: `/mnt/e/d2o-a378w`,
`a378e230947ebfd011439e1cac0f1e994d883aae`.

Правила:

- Каждый агент работает только в своём worktree и только в перечисленных
  файлах. Общие файлы (`docs/audit/header.md`,
  `docs/function-parity-audit.md`, `scripts/audit/*`) правит только
  координатор.
- Агент не пушит и не мержит. Он коммитит изменения в своей локальной ветке
  и пишет `AGENT_REPORT-<name>.md` в корне worktree.
- Если для доказательства нужен файл из чужого владения, агент описывает
  точное изменение в отчёте, но не редактирует файл.
- Координатор интегрирует коммиты последовательно через `cherry-pick`,
  сам обновляет аудит и пересчитывает E/P/N.

| Агент | Worktree | Владение |
|---|---|---|
| Core Network | `/mnt/e/r2o-agent-corenet` | `crates/r2o-datapath/src/raw.rs`, `r2o_route.rs`, `netlink.rs`, `nfqueue.rs`, `conntrack.rs`, `proc_nat.rs`, `r2o_conntrack_gate.rs`, `r2o_resource_limit.rs`; соответствующие `tests/d2o_{route,nfq,conntrack,raw}*`, `scripts/test-{route,nfq,conntrack,raw}*` |
| Controller & State | `/mnt/e/r2o-agent-controller` | `crates/r2o-controller/src/{catalog,discovery,ask,domain,classify_json,plan_text,raw_probe,main,voice_measure,voice_targets,voice_discovery}.rs`; `crates/r2o-controller/tests/*` кроме HTTP Search/TLS; `scripts/test-{catalog,discovery,live,groups,binding,plan-ident}*` |
| Datapath | `/mnt/e/r2o-agent-datapath` | `crates/r2o-datapath/src/{engine,hold,capture,r2o_udp_sessions,r2o_udp_hold,r2o_quic,r2o_voice,flow_journal,r2o_icmp_guard,control,main}.rs`, `crates/r2k-core/src/{wire,packet,plan}.rs`, `crates/r2k-core/src/plan/apply.rs`; `tests/d2o_{session_packet,handle_udp,hold,capture,icmp,tcp,udp}*`; `scripts/test-{session-packet,handle-udp,hold,capture,icmp,tcp,udp,wire}*` |
| Detection | `/mnt/e/r2o-agent-detection` | `crates/r2k-core/src/{tls,httpup,quic,stun}.rs`; `crates/r2o-controller/src/{http_search,classify,https_probe,fetch,r2o_tls,r2o_late_rx,response,quic_replay}.rs`; `crates/r2k-core/tests/*`, `crates/r2o-controller/tests/*http*`; `scripts/test-{http,tls,quic,classify,httpsprobe}*` |
| Differential QA | `/mnt/e/r2o-agent-qa` | Только чтение production; может добавлять `scripts/verify-*` и `AGENT_REPORT-qa.md`. Проверяет main/кандидатов независимо. |

Запрещено всем агентам: `git push`, `git merge`, force-push, правка
`docs/audit/header.md`, `docs/function-parity-audit.md`, `scripts/audit/*`,
чужих файлов из таблицы.
