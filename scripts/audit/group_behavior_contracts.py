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
        "quicwire: 11 P; Rust r2k_core::quic; нужны C/Rust vectors на ranges/seal/open.",
    ),
    "CN-QUIC-INITIAL": (
        "QUIC Initial: snapshot, reseal, rename, split, assembly",
        "Подготовка/перезапечатывание Initial, SNI/split, сборка датаграмм.",
        "quichello/quicsnap/quicsnap_reseal/quic: 14 P; r2o-quic-hello и quic-* differential частичные.",
    ),
    "CN-QUIC-PROBE-SEND": (
        "QUIC probe send: socket, prefix TTL, copies, fragments, refused",
        "Открытие/маркировка сокета, приманка/хвост, TTL/copies/split/frag, ECONNREFUSED.",
        "quicprobe send-функции: 21 P; r2o-quic-send-one PASS 10 кейсов, остаются longer/IPv6/real handshake.",
    ),
    "CN-QUIC-PROBE-RUN": (
        "QUIC probe run: question ladder, budget, classify",
        "Вопросы junk/frames/datagrams/bit/lowport/length, бюджет и итоговый verdict.",
        "quicprobe run-функции: 12 P; нужны C/Rust differential полного вопроса и бюджета.",
    ),
    "CN-QUIC-ARM-STRATEGY": (
        "QUIC arm strategy and plan text",
        "Лестница TTL/clearance/split/udplen/frag/fallback и текст arm-плана.",
        "quicarms + udpplan: 14 P; r2o-quic-plan-text частично, adaptive/порядок не сверены.",
    ),
    "CN-QUIC-CONNECTION": (
        "QUIC connection/data stage",
        "TLS-over-QUIC, transport params, ACK/frames, streams, RTT/close.",
        "quicconn: 31 P; r2o_quic_http3/quinn; полный побайтовый differential не заявлен.",
    ),
    "CN-TLS-RECORD-IO": (
        "TLS record I/O and helpers",
        "Чтение/запись записей, EINTR/EAGAIN, nonce/AAD, dispose/free.",
        "tls12/tls13 record-хелперы: 14 P; r2o-tls12-io PASS 13 кейсов, tls13 record layer — нет.",
    ),
    "CN-TLS13-HANDSHAKE": (
        "TLS 1.3 handshake and keys",
        "CH/SH, HKDF traffic keys, Finished, ECH, downgrade.",
        "tls13/tls13core: 7 P; rustls; C/Rust побайтового handshake/ECH нет.",
    ),
    "CN-TLS-VERIFY": (
        "TLS/HTTP verify and contact",
        "Проверка TLS1.2/1.3/ECH, тела ответа, контакта по family.",
        "verify.c TLS-часть: 8 P; verify-* differentials частичные.",
    ),
    "CN-QUIC-VERIFY": (
        "QUIC/HTTP3 verify and replay",
        "QUIC probe on/path/mark, replay, H3 headers/chunks, qb request/recv.",
        "verify.c QUIC-часть + replay: 10 P; нужен e2e DoQ/HTTP3 differential.",
    ),
    "CN-HTTP-SEARCH": (
        "HTTP search lifecycle and candidates",
        "Задачи, кандидаты, judge, fallback, runner, diagnostics, persist.",
        "httpsearch: 26 P; test-http-search-response PASS 13; diagnostic_end — event JSON differential PASS; переходы/таймеры/live — нет.",
    ),
    "CN-VOLUME": (
        "Response volume probe",
        "TLS/plain drain, rx volume, bounded connect, path probe.",
        "volume: 8 P; budget volume differentials частичные, полный path — нет.",
    ),
    "CN-VOICE": (
        "Voice/STUN discovery",
        "STUN request, DNS/voice blob, prefix, local failure.",
        "voice/voice_discovery/stun: 10 P; voice differentials частичные.",
    ),
    "CN-IP6FRAG": (
        "IPv6 fragment probe helper",
        "Единый monotonic timestamp для IPv6-fragment probe.",
        "d2k_ip6frag_send.h: 1 P; helper-level, нужен вызов в живом probe.",
    ),
    "CS-SCHED-TASK-LIFECYCLE": (
        "Scheduler task/worker lifecycle",
        "Слоты, worker permits, reset/done/fail/join, retire, queue wake, guards.",
        "sched.c: worker/task/queue/guard; Rust R2oDiscoverySearches/Queue/Life; полная матрица T_* не доказана.",
    ),
    "CS-SCHED-SUSPECT-ADMISSION": (
        "Scheduler suspect admission and refusal",
        "on_suspect, cooldown, dead/refusal, shape/family, refused outcomes.",
        "sched.c: admission/refusal; Rust queue/cooldown/family recovery; полный differential кодов/порядка.",
    ),
    "CS-SCHED-CANDIDATE-VERIFY": (
        "Scheduler candidate verification",
        "verify_confirm, partial_finish, ACK/APPLIED, own plan, exchange.",
        "sched.c: verify/applied/exchange; production verify_confirm 30 cases, остальные ветви P.",
    ),
    "CS-SCHED-PLAN-GENERATION": (
        "Scheduler plan generation",
        "verdict_to_plans, own_first, area/resource path, plan identity, RX bootstrap.",
        "sched.c: plans/area/resources/identity; Rust candidates/compose; порядок и поля не сверены.",
    ),
    "CS-SCHED-VOLUME-VOICE": (
        "Scheduler volume ladder and voice trials",
        "volume bucket/ladder/room, rx pending, voice trial/observe/fail.",
        "sched.c: volume/voice; budget/voice differentials частичные, поля plan_boxes/rx queue иные.",
    ),
    "CS-SCHED-ECH-QUIC": (
        "Scheduler ECH witness and QUIC initial/address control",
        "ECH witness, quic own initial/address/multi.",
        "sched.c: ECH/QUIC; Rust ech/quic initial; e2e DoQ и полный порядок не доказаны.",
    ),
    "CS-SCHED-DIAGNOSTICS": (
        "Scheduler diagnostics/live output",
        "progress/diagnostics/counts, live binding/phase, say/level/time/hex.",
        "sched.c: diagnostics/helpers; live 12 states PASS, редкие counters/поля P.",
    ),
    "CS-CRYPTO-ECC": (
        "ECC primitives P-256/X25519",
        "Полевая арифметика, point/scalar, public/keypair/ecdh.",
        "p256/x25519: 33 P; ring/hpke/dalek; прямых C/Rust векторов нет.",
    ),
    "CS-CLI-TOOLS": (
        "CLI tools d2kc/d2kask/d2kfetch/d2kvoice",
        "Флаги, stdout/exit, snapshot wire, usage.",
        "d2kc/d2kask/d2kfetch/d2kvoice: 2 P; d2kvoice main/usage PASS; snapshot_wire C-путь недостижим; diagnostic_limit/event/tick, http_search_portal и sched_say — C/Rust differential PASS; остальные CLI.",
    ),
    "CS-PROPS": (
        "QUIC properties text",
        "original/strategy measure and wire properties.",
        "props: 5 P; quic props findings текстовый контракт не полный.",
    ),
    "CS-VERDICT": (
        "Classify verdict",
        "C d2k_classify verdict mapping.",
        "verdict: 1 P; C-путь в d2kc мёртв, Rust classify иной API.",
    ),
    "DP-SESSION-LIFECYCLE": (
        "Datapath session lifecycle",
        "d2kd main/usage, session_new, UDP handle, session_packet.",
        "session/d2kd: 5 P; session_packet/handle_udp live не сверены.",
    ),
    "DP-TRACK": (
        "Datapath flow table key hash",
        "key_hash static helper.",
        "track: 1 P; helper-level.",
    ),
    "DP-NFQ": (
        "Datapath NFQUEUE error text",
        "nfq say static helper.",
        "nfq: 1 P; error text/ветви NFQUEUE.",
    ),
    "DT-BRIDGE": (
        "Detect bridge scheduler",
        "base/tcp/white/seeded/progress/stop bridge.",
        "bridge: 9 P; bridge differential 8 cases, seeded/white ветви P.",
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
    if len(rows) != 396:
        raise SystemExit(f"expected 396 P rows, got {len(rows)}")
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
        "Дата: 2026-11-16. Это не перенос и не заявление паритета: 1982 C-функции",
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
        "",
        "## Следующий шаг",
        "",
        "`CS-LINK-IO`, `CS-MEASUREMENT` и `CS-CATALOG-TLV` закрыты;",
        "`send_area_key` (11), `wait_readable` (8), `hex_decode` (6) и",
        "`say` (4+3) сверены C/Rust differential. Следующий кандидат —",
        "`CS-CLI-TOOLS` (`d2kask`/`d2kfetch`), отдельный CLI-контракт.",
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
