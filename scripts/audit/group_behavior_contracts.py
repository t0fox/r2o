#!/usr/bin/env python3
"""Сгруппировать оставшиеся P по поведенческим контрактам.

Скрипт не переносит код и не меняет статусы аудита. Он читает канонические
таблицы docs/audit/*.md тем же способом, что и scripts/audit/render_audit.py,
и раскладывает каждую P-строку ровно в один контракт. Выход:
  docs/behavior-contracts/p-contract-map.tsv
  docs/behavior-contracts/inventory.md
"""
from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "docs" / "audit"
OUT = ROOT / "docs" / "behavior-contracts"
PARTS = ["core-net", "core-state", "datapath-core", "datapath-plan", "detect"]
STATUS_RE = re.compile(r"^(?:\*\*)?([EPN?])(?:\*\*)?\*?$")
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")


def split_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [cell.strip().replace("\\|", "|") for cell in CELL_SPLIT_RE.split(stripped)]


def table_status(line: str) -> str | None:
    if not line.lstrip().startswith("|"):
        return None
    cells = split_row(line)
    if len(cells) < 7 or not re.match(
        r"^`?[A-Za-z_][A-Za-z0-9_]*`?(?:\s|\||$)", cells[0]
    ):
        return None
    match = STATUS_RE.match(cells[5])
    return match.group(1) if match else None


def read_p_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for part in PARTS:
        section = ""
        for line in (AUDIT / f"{part}.md").read_text(encoding="utf-8").splitlines():
            heading = re.match(r"^#{1,4} (.+)$", line)
            if heading:
                text = heading.group(1)
                if re.search(r"(core|datapath|detect)/", text):
                    section = text
                continue
            if table_status(line) != "P":
                continue
            cells = split_row(line)
            rows.append(
                {
                    "part": part,
                    "section": section,
                    "function": cells[0].strip("`").strip(),
                    "purpose": cells[3] if len(cells) > 3 else "",
                    "rust": cells[4] if len(cells) > 4 else "",
                    "evidence": cells[6] if len(cells) > 6 else "",
                }
            )
    return rows


# --- Контракты -------------------------------------------------------------

CONTRACTS = {
    "CN-QUIC-WIRE": (
        "QUIC wire: long header, PN length, seal/open, packet ranges",
        "Побайтовые операции над QUIC long-header/PN/AEAD/ranges.",
        "quicwire: 0 P; pn_len — 14 значений, long header — 27, hdr_parse — 120, ranges — 24, seal/open — 96 кейсов C/Rust PASS.",
    ),
    "CN-QUIC-INITIAL": (
        "QUIC Initial: snapshot, reseal, rename, split, assembly",
        "Подготовка/перезапечатывание Initial, SNI/split, сборка датаграмм.",
        "quichello/quicsnap/quicsnap_reseal/quic: 0 P; prepare_target/rename — 8, hello_ask/split — 16, hello_incomplete — 10, profile/longer — 4, qsnap_recid+form — 15 строк, assembly — 17 шагов C/Rust PASS.",
    ),
    "CN-QUIC-PROBE-SEND": (
        "QUIC probe send: socket, prefix TTL, copies, fragments, refused",
        "Открытие/маркировка сокета, приманка/хвост, TTL/copies/split/frag, ECONNREFUSED.",
        "quicprobe send-функции: 20 P; qp_now_ms — 31-line C/Rust PASS и бюджет trial; r2o-quic-send-one PASS 10 кейсов, остаются longer/IPv6/real handshake.",
    ),
    "CN-QUIC-PROBE-RUN": (
        "QUIC probe run: question ladder, budget, classify",
        "Вопросы junk/frames/datagrams/bit/lowport/length, бюджет и итоговый verdict.",
        "quicprobe run-функции: 6 P; reason_set/append, budget_left, qp_outcome, qp_progress, budget_ms — 30 строк C/Rust PASS и проводка base-result/таймаута/прогресса/бюджета; нужен differential полного вопроса.",
    ),
    "CN-QUIC-ARM-STRATEGY": (
        "QUIC arm strategy and plan text",
        "Лестница TTL/clearance/split/udplen/frag/fallback и текст arm-плана.",
        "quicarms + udpplan: 0 P; ask_q — 8, ask/ask_frag — 69, original_arms — 56, strategy_ask — 9, strategy_arms — 58, question_plan — 23 строки C/Rust PASS; append_fmt — String+checked_text (8191), delay_plan — мёртв в C.",
    ),
    "CN-QUIC-CONNECTION": (
        "QUIC connection/data stage",
        "TLS-over-QUIC, transport params, ACK/frames, streams, RTT/close.",
        "quicconn: 30 P; r2o_quic_http3/quinn; app_progress — 6 потоков C/Rust PASS; полный побайтовый differential не заявлен.",
    ),
    "CN-TLS-RECORD-IO": (
        "TLS record I/O and helpers",
        "Чтение/запись записей, EINTR/EAGAIN, nonce/AAD, dispose/free.",
        "tls12/tls13 record-хелперы: r2o-tls12-io PASS 13 кейсов; sealed TLS1.2 — exact 34 байта C/Rust PASS; tls13 put16/get16 — 65536 значений C/Rust PASS; TLS1.3 record layer — нет.",
    ),
    "CN-TLS13-HANDSHAKE": (
        "TLS 1.3 handshake and keys",
        "CH/SH, HKDF traffic keys, Finished, ECH, downgrade.",
        "tls13/tls13core: 6 P; d2k_t13_random — 10 строк C/Rust PASS и общий fill_exact; rustls; C/Rust побайтового handshake/ECH нет.",
    ),
    "CN-TLS-VERIFY": (
        "TLS/HTTP verify and contact",
        "Проверка TLS1.2/1.3/ECH, тела ответа, контакта по family.",
        "verify.c TLS-часть: 5 P; request_complete_page — 13, props_contact — 11, body_byte/HTTP framing — 16/16 кейсов C/Rust PASS (verify-режим парсера); остальные verify-* частичные.",
    ),
    "CN-QUIC-VERIFY": (
        "QUIC/HTTP3 verify and replay",
        "QUIC probe on/path/mark, replay, H3 headers/chunks, qb request/recv.",
        "verify.c QUIC-часть + replay: 10 P; нужен e2e DoQ/HTTP3 differential.",
    ),
    "CN-HTTP-SEARCH": (
        "HTTP search lifecycle and candidates",
        "Задачи, кандидаты, judge, fallback, runner, diagnostics, persist.",
        "httpsearch: 21 P; plan_poisons+measured_poison — 215 строк, build_cands/build_fallback/вопросы — 50 строк C/Rust PASS и production candidate_ladder с rec.key после отзыва; test-http-search-response PASS 13; diagnostic_end — event JSON PASS; judge_trial — 13 переходов PASS; переходы/таймеры/live — нет.",
    ),
    "CN-VOLUME": (
        "Response volume probe",
        "TLS/plain drain, rx volume, bounded connect, path probe.",
        "volume: 7 P; RX differential 13 кейсов PASS, retry-условие rx_short теперь как C; полный path — нет.",
    ),
    "CN-VOICE": (
        "Voice/STUN discovery",
        "STUN request, DNS/voice blob, prefix, local failure.",
        "voice/voice_discovery/stun: 8 P; d2k_stun_request/t13_random — 10 строк C/Rust PASS и production STUN-префикс; voice_resolve-порт теперь как C strtoul; voice differentials частичные.",
    ),
    "CS-SCHED-TASK-LIFECYCLE": (
        "Scheduler task/worker lifecycle",
        "Слоты, worker permits, reset/done/fail/join, retire, queue wake, guards.",
        "sched.c: worker/task/queue/guard; Rust R2oDiscoverySearches/Queue/Life; box_injects_rst/rst_guard_wanted/plan_arm_rst_guard — 32 кейса C/Rust PASS и проводка в candidate+sync; sched_quic_progress — 7 кейсов и проводка в QUIC worker; ask_settle — 9 кейсов и проводка в base/full; worker_type — 16 кейсов C/Rust PASS и живой worker_oldest_type из gate; stall_budgets_push — dedup и базовое поле 25 как C; полная матрица T_* не доказана.",
    ),
    "CS-SCHED-SUSPECT-ADMISSION": (
        "Scheduler suspect admission and refusal",
        "on_suspect, cooldown, dead/refusal, shape/family, refused outcomes.",
        "sched.c: admission/refusal; Rust queue/cooldown/family recovery; refuse_is_damage — 256 кодов C/Rust PASS и ветка DAMAGED в REFUSED; clear_binding_matches — 9216 кейсов, binding_wire_shape — 126 кейсов, measured trigger profile, client_tcp_profile — 4112 кейсов и drop_client_opts — 6 кейсов C/Rust PASS; cooldown_victim — 4 состояния кольца 128 C/Rust PASS; clean-handshake differential — коды/IP/family/name/TTL PASS; полный differential кодов/порядка.",
    ),
    "CS-SCHED-CANDIDATE-VERIFY": (
        "Scheduler candidate verification",
        "verify_confirm, partial_finish, ACK/APPLIED, own plan, exchange.",
        "sched.c: verify/applied/exchange; production verify_confirm 30 cases, props_text — 243 кейса C/Rust PASS, остальные ветви P.",
    ),
    "CS-SCHED-PLAN-GENERATION": (
        "Scheduler plan generation",
        "verdict_to_plans, own_first, area/resource path, plan identity, RX bootstrap.",
        "sched.c: plans/area/resources/identity; signal_human, task_phase, live_binding, live_autopick — full live.json 12 состояний PASS; verdict_name — 14 кодов C/Rust PASS и NO_QUIC/LOCAL_ADDRESS в QUIC-логах; group_exception_status — live-тест active/pending/retrying/rejected/removing; Rust candidates/compose; порядок и поля не сверены.",
    ),
    "CS-SCHED-VOLUME-VOICE": (
        "Scheduler volume ladder and voice trials",
        "volume bucket/ladder/room, rx pending, voice trial/observe/fail.",
        "sched.c: volume/voice; volume_bucket — 28 кейсов, voice_ip_fmt/text/text2 — 9 адресов, voice_trial_same_context — 13 кейсов C/Rust PASS; budget/voice differentials частичные, поля plan_boxes/rx queue иные.",
    ),
    "CS-SCHED-ECH-QUIC": (
        "Scheduler ECH witness and QUIC initial/address control",
        "ECH witness, quic own initial/address/multi.",
        "sched.c: ECH/QUIC; Rust ech/quic initial; quic_text_is_split — 11 текстов C/Rust PASS; ECH RR cache — 12 строк C/Rust PASS (TTL/ring); e2e DoQ и полный порядок не доказаны.",
    ),
    "CS-SCHED-DIAGNOSTICS": (
        "Scheduler diagnostics/live output",
        "progress/diagnostics/counts, live binding/phase, say/level/time/hex.",
        "sched.c: diagnostics/helpers; live 12 states PASS, level_name — 10 значений, is_hex_digit — 256 байт, progress_note — 11 кейсов C/Rust PASS; редкие counters/поля P.",
    ),
    "CS-CRYPTO-ECC": (
        "ECC primitives P-256/X25519",
        "Полевая арифметика, point/scalar, public/keypair/ecdh.",
        "2026-11-18: C/Rust vector differential PASS 72 (X25519) + 42 (P-256) строки; production TLS — rustls/ring.",
    ),
    "CS-CLI-TOOLS": (
        "CLI tools d2kc/d2kask/d2kfetch/d2kvoice",
        "Флаги, stdout/exit, snapshot wire, usage.",
        "d2kc/d2kask/d2kfetch/d2kvoice: pval_str — 42-строчный C/Rust PASS; step/ack/seen — тексты сверены, production CLI не переведён; d2kvoice main/usage PASS; snapshot_wire C-путь недостижим; diagnostic_limit/event/tick, http_search_portal и sched_say — PASS; остальные CLI.",
    ),
    "CS-PROPS": (
        "QUIC properties text",
        "original/strategy measure and wire properties.",
        "props: 5 P; quic props findings текстовый контракт не полный.",
    ),
    "DP-SESSION-LIFECYCLE": (
        "Datapath session lifecycle",
        "d2kd main/usage, session_new, UDP handle, session_packet.",
        "session/d2kd: 4 P; usage — d2kd help-блок C/Rust PASS; session_packet/handle_udp live не сверены.",
    ),
    "DP-NFQ": (
        "Datapath NFQUEUE error text",
        "nfq say static helper.",
        "nfq: 1 P; error text/ветви NFQUEUE.",
    ),
    "DT-BRIDGE": (
        "Detect bridge scheduler",
        "base/tcp/white/seeded/progress/stop bridge.",
        "bridge: 8 P; bridge differential 8 cases, progress_seen — 6 кейсов C/Rust PASS; seeded/white ветви P.",
    ),
    "DT-RAW-HANDSHAKE": (
        "Detect raw handshake/probe",
        "flush pending, poison family, handshake_as.",
        "raw: 3 P; raw probe live/ветви.",
    ),
}


# --- Раскладка sched.c -----------------------------------------------------

SCHED_TASK_LIFECYCLE = {
    "worker_arg_alloc", "worker_arg_free", "worker_run_body", "worker_run",
    "worker_type", "join_worker", "task_budget", "note_worker_start_failure",
    "task_reset", "task_fail", "task_done", "question_retire", "candidate_retire",
    "trial_retire", "box_ensure", "box_injects_rst", "rst_guard_wanted",
    "plan_arm_rst_guard", "quic_deny_install", "quic_deny_recheck", "quic_deny_tick",
    "sched_quic_yield", "sched_quic_progress", "stall_budgets_push",
    "d2k_sched_wake_fd", "d2k_sched_active", "wake_loop", "launch_task",
    "queued_measurements", "d2k_sched_free", "d2k_sched_tick",
}

SCHED_SUSPECT_ADMISSION = {
    "refuse_is_permanent", "refuse_is_damage", "cooldown_clear_nonchallenge",
    "cooldown_victim", "flowkey_same", "drop_client_opts", "client_tcp_profile",
    "probe_shape", "binding_wire_shape", "addr_binding_shape", "clear_measured_shape",
    "clear_binding_matches", "has_other_family_target_plan", "binding_covering",
    "family_recovery_eligible", "family_recovery_start", "newer_name_binding",
    "is_voice_class", "on_suspect", "on_shape", "group_record", "record_shape",
    "verdict_proves_block", "claim_early_refusal", "local_refusal_verdict",
    "exec_refusal", "on_refused", "on_refused_foreign", "on_refused_unfit",
    "note_clean_handshake", "clean_handshake_recent", "on_exchange",
}

SCHED_CANDIDATE_VERIFY = {
    "on_applied", "applied_of_candidate", "candidate_trial_matches", "verify_confirm",
    "partial_finish", "install_next", "binding_for", "bound_plan_here", "own_rank_before",
    "own_first_plans", "props_text", "probes_word", "ask_settle", "quic_text_is_split",
    "verify_default", "verify_rx_default", "verify_rx_gzip_default", "bind_default",
    "mark_default", "classify_unconfigured", "voice_default", "client_alpn_nonhttp",
}

SCHED_PLAN_GENERATION = {
    "verdict_to_plans", "area_plan", "desired_area", "area_exceptions_ready",
    "area_exception_groups_suspended", "group_exception_status", "remember_resources",
    "remember_measured_path", "select_resource_path", "start_search", "candidate_path",
    "signal_human", "task_phase", "live_binding_for", "live_autopick_status",
    "verdict_name", "d2k_sched_ech_baseline_result", "prop_close", "contact_close",
    "ver_close", "prop_send_next", "prop_finish", "fill_hellos", "stamp_plan_id",
    "rx_saved_bootstrap",
}

SCHED_ECH_QUIC = {
    "ech_rr_known", "ech_rr_store", "ech_pick_witness", "ech_witness_untried",
    "ech_witness_reject", "ech_witness_add", "quic_own_initial", "quic_note_multi",
    "quic_addr_start",
}

SCHED_VOLUME_VOICE = {
    "volume_bucket", "worker_volume", "worker_volume_cut", "vol_cut_kb",
    "rx_ladder_pending", "next_rx_volume_plan", "budget_uncountable_note",
    "budget_cut_reject", "ladder_candidate_at", "ladder_candidate", "voice_ip_fmt",
    "voice_ip_text", "voice_ip_text2", "voice_trial_owned", "voice_trial_same_context",
    "voice_finish_measure", "voice_observe", "voice_fail", "voice_pending_dispatch",
}

SCHED_DIAGNOSTICS = {
    "say", "d2k_sched_set_say", "d2k_sched_progress_note", "d2k_sched_diagnostics",
    "d2k_sched_limit_diagnostics", "d2k_sched_diagnostic_counts", "d2k_sched_new",
    "level_name", "sched_mono_ms", "wall_s", "is_hex_digit", "say_question_trace",
}


def sched_contract(name: str) -> str:
    for contract, names in (
        ("CS-SCHED-TASK-LIFECYCLE", SCHED_TASK_LIFECYCLE),
        ("CS-SCHED-SUSPECT-ADMISSION", SCHED_SUSPECT_ADMISSION),
        ("CS-SCHED-CANDIDATE-VERIFY", SCHED_CANDIDATE_VERIFY),
        ("CS-SCHED-PLAN-GENERATION", SCHED_PLAN_GENERATION),
        ("CS-SCHED-VOLUME-VOICE", SCHED_VOLUME_VOICE),
        ("CS-SCHED-ECH-QUIC", SCHED_ECH_QUIC),
        ("CS-SCHED-DIAGNOSTICS", SCHED_DIAGNOSTICS),
    ):
        if name in names:
            return contract
    raise SystemExit(f"sched function without contract: {name}")


# --- Раскладка остальных ---------------------------------------------------

QUIC_PROBE_SEND = {
    "nap_us", "qp_open_fresh", "qp_send_one", "qp_send_fragmented", "qp_progress",
    "qp_arm_first_send", "qp_now_ms", "quic_ask_core", "quic_ask_ex", "quic_fragment",
    "quic_ask_arm", "quic_arm_data", "quic_ask", "qp_ask_vn", "quic_ask_ttl",
    "quic_ask_copies", "quic_ask_srcport", "quic_ask_split", "quic_ask_longer",
    "quic_ask_frames", "quic_ask_control",
}
TLS13_RECORD_HELPERS = {
    "tls_dispose", "say", "read_exact", "write_all", "put16", "get16",
}
TLS_VERIFY = {
    "body_byte", "request_complete_page", "verify_contact",
    "d2k_props_contact_on_family_tcp_profile", "verify_probe13_internal",
    "d2k_verify_probe_ech_on", "d2k_verify_probe_ech_origin_on",
    "verify_probe12_internal",
}


def contract_for(row: dict[str, str]) -> str:
    part = row["part"]
    section = row["section"]
    name = row["function"]
    if part == "core-net":
        if "quicwire" in section:
            return "CN-QUIC-WIRE"
        if any(key in section for key in ("quichello", "quicsnap", "core/quic.c")):
            return "CN-QUIC-INITIAL"
        if "quicprobe" in section:
            return "CN-QUIC-PROBE-SEND" if name in QUIC_PROBE_SEND else "CN-QUIC-PROBE-RUN"
        if "quicarms" in section or "udpplan" in section:
            return "CN-QUIC-ARM-STRATEGY"
        if "quicconn" in section:
            return "CN-QUIC-CONNECTION"
        if "tls12" in section:
            return "CN-TLS-RECORD-IO"
        if "tls13core" in section:
            return "CN-TLS-RECORD-IO" if name in {"put16", "get16"} else "CN-TLS13-HANDSHAKE"
        if "tls13" in section:
            return "CN-TLS-RECORD-IO" if name in TLS13_RECORD_HELPERS else "CN-TLS13-HANDSHAKE"
        if "verify_quic_replay" in section:
            return "CN-QUIC-VERIFY"
        if "verify.c" in section:
            return "CN-TLS-VERIFY" if name in TLS_VERIFY else "CN-QUIC-VERIFY"
        if "httpsearch" in section:
            return "CN-HTTP-SEARCH"
        if "volume" in section:
            return "CN-VOLUME"
        if "voice" in section or "stun" in section:
            return "CN-VOICE"
        if "ip6frag" in section:
            return "CN-IP6FRAG"
    if part == "core-state":
        if "sched.c" in section:
            return sched_contract(name)
        if "p256" in section or "x25519" in section:
            return "CS-CRYPTO-ECC"
        if "compose.c" in section:
            return "CS-CATALOG-TLV"
        if any(key in section for key in ("d2kc", "d2kask", "d2kfetch", "d2kvoice")):
            return "CS-CLI-TOOLS"
        if "link.c" in section:
            return "CS-LINK-IO"
        if "meas" in section:
            return "CS-MEASUREMENT"
        if "props.c" in section:
            return "CS-PROPS"
        if "verdict.c" in section:
            return "CS-VERDICT"
    if part == "datapath-core":
        if "session" in section or "d2kd" in section:
            return "DP-SESSION-LIFECYCLE"
        if "track" in section:
            return "DP-TRACK"
        if "nfq" in section:
            return "DP-NFQ"
    if part == "detect":
        if "bridge" in section:
            return "DT-BRIDGE"
        if "main.c" in section:
            return "DT-CLI-OUTPUT"
        if "raw.c" in section:
            return "DT-RAW-HANDSHAKE"
    raise SystemExit(f"unmapped P row: {part} / {section} / {name}")


def main() -> int:
    rows = read_p_rows()
    for row in rows:
        row["contract"] = contract_for(row)
    counts = Counter(row["contract"] for row in rows)
    if len(rows) != 214:
        raise SystemExit(f"expected 214 P rows, got {len(rows)}")
    unknown = sorted(set(counts) - set(CONTRACTS))
    if unknown:
        raise SystemExit(f"contracts without metadata: {unknown}")

    OUT.mkdir(parents=True, exist_ok=True)
    map_path = OUT / "p-contract-map.tsv"
    with map_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["contract", "part", "section", "function", "purpose", "rust", "evidence"])
        for row in rows:
            writer.writerow(
                [
                    row["contract"],
                    row["part"],
                    row["section"],
                    row["function"],
                    row["purpose"],
                    row["rust"],
                    row["evidence"],
                ]
            )

    by_part = Counter(row["part"] for row in rows)
    lines = [
        "# Инвентарь поведенческих контрактов по оставшимся P",
        "",
        "Дата: 2026-11-18. Это не перенос и не заявление паритета: 1982 C-функции",
        "остаются справочным реестром, а P-строки сгруппированы в проверяемые",
        "поведенческие контракты. Источник — канонические таблицы",
        "`docs/audit/{core-net,core-state,datapath-core,datapath-plan,detect}.md`.",
        "",
        f"Строк P: **{len(rows)}**; контрактов: **{len(counts)}**; без контракта: **0**.",
        "",
        "| Группа | P |",
        "|---|---:|",
        *[f"| {part} | {by_part[part]} |" for part in PARTS],
        "",
        "## Контракты",
        "",
        "| ID | Контракт | Наблюдаемое поведение | P | Текущее доказательство / следующий шаг |",
        "|---|---|---|---:|---|",
    ]
    for contract in CONTRACTS:
        title, behavior, evidence = CONTRACTS[contract]
        lines.append(
            f"| `{contract}` | {title} | {behavior} | {counts.get(contract, 0)} | {evidence} |"
        )
    lines += [
        "",
        "## Правила",
        "",
        "- Контракт описывает входы, выходы, ошибки, таймауты и побочные эффекты.",
        "- Внутренние C-хелперы не являются обязательными единицами переноса.",
        "- Для wire/NFQUEUE/TLV/сетевых форматов сохраняется побайтовая совместимость.",
        "- Статус E/P в `docs/function-parity-audit.md` не меняется этим инвентарём.",
        "- Карта «контракт → функция»: `p-contract-map.tsv`.",
        "",
        "## Закрытые контракты",
        "",
        "| ID | Контракт | Доказательство |",
        "|---|---|---|",
        "| `DT-CLI-OUTPUT` | Detect CLI JSON/human/usage/exit | 2026-11-16: `r2o-detect` добавлен в `package-release.sh` и release-артефакт; `r2o-manager` активирует его как необязательный компонент; `test-detect-release-artifact.sh` распаковывает архив и даёт `6 triggers / 19 exits / json=equal / human=equal` на packaged binary. `r2o-controller --classify` остаётся отдельным CLI-путём. |",
        "| `CS-MEASUREMENT` | Measurement transport helpers | 2026-11-16: `connect_bounded` success/refused/badfd, `send_all` send-timeout/EINTR/10 ветвей, `d2k_arm_plan_measured` 28 кейсов, `nap_us` 20 мс/EINTR — все C/Rust differential PASS; production nap переведён на `libc::nanosleep` с C-семантикой. |",
        "| `CS-CATALOG-TLV` | Catalog TLV plan encoding | 2026-11-16: `r2o-compose-tlv-differential.sh` — overlap/reorder/badsum/badsum_gap/checksum и `plan_tlv_stamp_ident` (id + stamped D2KP, guard'ы layout'а) совпали с C; оба ask-пути удостоверяют план по TLV. |",
        "| `CS-LINK-IO` | Link/control I/O helpers | 2026-11-16: send_area_key 11, wait_readable 8, hex_decode 6, say 4+3 — все C/Rust differential PASS; `r2o_link_open` даёт те же тексты пустого/длинного/отсутствующего сокета. |",
        "| `DP-TRACK` | Datapath flow table key hash | 2026-11-17: `test-datapath-tcp-capacity-differential.sh` PASS (capacity/refusal/reverse/duplicate/remove/expiry); `key_hash` осознанно заменён на `HashMap` RandomState — внутренний порядок коллизий не наблюдаем, HashDoS-устойчивость не ослаблена. |",
        "| `CN-IP6FRAG` | IPv6 fragment probe helper | 2026-11-17: `test-datapath-ip6frag-sender-state-differential.sh` PASS (init/close/send-after-close, fd); production sender uses `Instant` for the same 1s cache and 200ms neighbor deadline. |",
        "| `CS-VERDICT` | Classify verdict | 2026-11-17: C `d2k_classify` — обёртка `d2k_classify_cancelable(...,NULL)` без production-вызова в D2O; Rust `run` без отмены, дерево cancelable E* (`test-classifier-clear-confirm-differential.sh` + unit). Ограничение — отдельного differential обёртки нет. |",
        "| `CS-CLI-TOOLS` | CLI tools d2kc/d2kask/d2kfetch/d2kvoice | 2026-11-18: `r2o-ask-cli-differential.sh` PASS 28 сценариев `d2kask main` (no-trigger, полный отказ датапата, save-файлы, CLI/hex/сокет-ошибки); `r2o-serve-cli-differential.sh` PASS 9 сценариев `d2kc main` (version/usage/битый и отсутствующий каталог/приветствие/timeout/SIGTERM). Production-отчёт ask переведён на формат C. |",
        "| `DP-NFQ` | Datapath NFQUEUE error text | 2026-11-18: C `say` — внутренний `vsnprintf` в буфер; Rust возвращает `io::Error`/`String` и логирует причину у вызывающего. Ветви вердиктов/ENOBUFS/timestamp/ICMP покрыты профильными C/Rust differential'ами; отдельного поведенческого контракта у буфера нет. |",
        "| `DT-RAW-HANDSHAKE` | Detect raw handshake/probe non-Linux stubs | 2026-11-18: три не-Linux заглушки (`flush_pending`, `poison_family`, `handshake_as`) закрыты как E*: R2O выпускается только для Linux/OpenWrt, raw-слой вне Linux не компилируется, а Linux-путь покрыт production differential 5 cases. |",
        "| `CN-TLS-RECORD-IO` | TLS record I/O and helpers | 2026-11-18: record/handshake-слой заменён rustls; dispose/free — RAII, `say` — внутренний форматтер. Байты ClientHello TLS1.2 сверены `test-tls12-ch12-differential.sh`, sealed-запись — `test-tls12-record-differential.sh` (34 байта + sequence), поля ServerHello — `d2o_verify_differential`, ключи/IV — `hkdf-*`. **Ограничение:** побайтового differential TLS1.3 record-слоя нет. |",
        "| `CN-TLS13-HANDSHAKE` | TLS 1.3 handshake and keys | 2026-11-18: TLS1.3-стек заменён rustls; ClientHello/ECH и поля ServerHello сверены `d2o_verify_differential`/`r2o-ech-*`, app-data — живыми TLS-проверками. **Ограничение:** побайтового differential handshake/record-слоя нет. |",
        "| `CS-CRYPTO-ECC` | ECC primitives P-256/X25519 | 2026-11-18: C/Rust vector differential — `test-x25519-differential.sh` PASS 72 строки, `test-p256-differential.sh` PASS 42 строки (production C против x25519-dalek/p256, все скаляры и пары). TLS/ECH используют rustls/ring с теми же RFC; ClientHello/рукопожатия покрыты отдельными differential'ами. **Ограничение:** прямого scalar-API у ring нет; production проверяется завершёнными TLS-сессиями. |",
        "| `CS-PROPS` | QUIC properties text | 2026-11-18: C-хуки замера заменены раздельными кандидатами и trial-runner; path/SNI/port/wait/mark — явные аргументы. Кандидаты/вопросы сверены `r2o-quic-*` differential'ами. **Ограничение:** отдельного hook-символа нет. |",
        "| `DT-BRIDGE` | Detect bridge scheduler | 2026-11-18: C-крючки заменены DiscoveryWorker/run_discovery; поля trigger/control/white/seed/mark/repeats/gap/wait/stop и base-ответ выражены задачей. Ветви сверены progress-seen (6), bridge (8) и classify/queue-тестами. **Ограничение:** отдельного hook-символа нет. |",
        "| `CS-SCHED-DIAGNOSTICS` | Scheduler diagnostics/live output | 2026-11-18: C-инъекция say/observer заменена общим logger/Recorder; счётчики диагностики сверены 7 полей, live/status — r2o-live-*, время — Instant/SystemTime. **Ограничение:** дословный формат всех лог-строк не является сетевым контрактом. |",
        "| `DP-SESSION-LIFECYCLE` | Datapath session lifecycle | 2026-11-18: TCP-путь — 36-кейсовый session-packet differential, UDP — path/prepost/release differentials, probe-флаги — controller-probe differential. Конструктор — типизированные таблицы/RAII, бюджет 25, журнал. **Ограничение:** полной матрицы всех ветвей и live-NFQUEUE main-loop нет. |",
        "",
        "## Следующий шаг",
        "",
        "Закрыты `CS-LINK-IO`, `CS-MEASUREMENT`, `CS-CATALOG-TLV`, `DP-TRACK`,"
        "`CN-IP6FRAG`, `CS-VERDICT`, `CS-CLI-TOOLS` и `DP-NFQ`. Следующие приоритеты —",
        "TLS record/handshake, QUIC connection/verify, volume и voice; тяжёлые",
        "live-контракты требуют стенда с датапатом и реальным сетевым путём.",
        "",
        "## Ограничение TTL-контракта",
        "",
        "`quic-server-ttl-in` закрывает только приём TTL/hop limit",
        "(`qp_recv_ttl`/`recv_with_ttl`) и не заявляет полный `d2k_quic_run`",
        "qprops pipeline. Полная проводка `server_ttl_in` в verdict/props —",
        "отдельный контракт `CN-QUIC-VERIFY`/`CS-PROPS`, а не закрытая часть",
        "TTL receive-контракта.",
        "",
    ]
    (OUT / "inventory.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"P rows: {len(rows)}; contracts: {len(counts)}; map: {map_path}")
    for contract in CONTRACTS:
        print(f"{counts.get(contract, 0):4d}  {contract}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
