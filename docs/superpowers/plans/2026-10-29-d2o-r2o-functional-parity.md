# D2O to R2O Functional Parity Plan

> **For agentic workers:** follow the read-only audit assignments first. A confirmed mismatch is handled on `main` as reproduce in C → differential regression → minimal Rust fix → targeted/full verification → commit.

**Goal:** Maximize proven branch-level functional parity between current `t0fox/d2o` C and `t0fox/r2o` Rust, report the evidence-weighted percentage and remaining unverified behavior.

**Architecture:** Preserve R2O's existing Rust crates and service boundaries. D2O C is the behavioral oracle and remains test-only; no C runtime path is added. All edits and commits happen directly on `main` as the user explicitly required.

**Tech Stack:** C11 donor harnesses, Rust/Cargo workspace, NFQUEUE/netlink, OpenWrt service scripts, QEMU and target ABI builds.

**Spec:** User-provided active goal in this Codex thread; there is no separate repository spec.

## Global Constraints

- Compare current `t0fox/d2o/main` and `t0fox/r2o/main` before scoring; starting baseline is d2o `304ba893dd37197128ac8799c0495b035f6a38c0` and r2o `0bd1e1bee134425643a8a01f57a95afbde2c406a`.
- Keep Telegram on its existing Rust z2kOW-derived implementation; do not replace or rewrite it.
- Do not use a physical router, VPS, relay, or WARP; do not put C back into runtime.
- Preserve the R2O architecture and OpenWrt 128 MB RAM target.
- Keep user-owned `.audit/`, `captures/`, and the D2O oracle checkout untouched.
- Do not rerun already-passed upstream differential scenarios unless an inspected code path exposes a concrete reason.

## Review Focus

- Partial writes, queue saturation, cancellation, and local socket errors must keep donor verdicts and accounting.
- ACK/APPLIED/PERSIST must preserve ordering, retries, idempotence, timeout, and restart behavior.
- Parallel flows and endpoint changes must not cross-contaminate discovery, QUIC, or RTC state.
- Service restarts must reapply persisted state without losing or duplicating plans/rules.
- Constrained memory and ABI differences must not change packet handling or create unbounded state.

## Tasks

### Task 1: Establish current source and test inventory

**Files:** inspect D2O `core/`, `detect/`, `datapath/`, `telegram/`, service/config/firewall sources and R2O `crates/`, `router/`, `scripts/`, `.github/`.

- [x] Record current remote main SHAs and clean-source paths; preserve user-owned dirty D2O files.
- [ ] Enumerate production C functions, Rust counterparts/callers, and tests; tag behavior branches, state transitions, timers, errors, and side effects.
  - Inventory slices cover datapath/NFQUEUE, core HTTP/TLS/ECH/verification and HTTP-search, QUIC/HTTP3, Discord voice/STUN, catalog/Discovery/classification/diagnostics, detect trigger/poison/raw-probe, protected Telegram Rust integration, and router/service/config/firewall/release entry points in `docs/parity-function-inventory.md`. Core files still lacking a dedicated module/API slice are compose, d2kask, d2kfetch, d2kvoice, ipfrag, link, net4, plantlv, sched, udpruntime and volume; crypto, p256, x25519, props, udpplan and d2kc are partial. Function-level helper/error review, complete classifier/Discovery integration, full detect branches, Telegram runtime/config/service integration and router/service/config/firewall branch review remain open.
- [x] Read existing 51-scenario upstream differential manifest as prior evidence without rerunning it wholesale.
- [x] Define the matrix denominator from unique observable behavior contracts. The audit matrix uses weight 3 for packet/plan safety and persistence, weight 2 for lifecycle/retry/measurement and operator-facing panel/service contracts. No credit for code presence alone; partial/unverified rows score zero until proven. See `docs/functional-parity-matrix.md` for the current weighted result.

### Task 2: Sequential independent source audits

Follow the user's sequential workflow on the shared `main` checkout. Finish one subsystem's source trace, evidence and any required fix/commit before moving to the next. Return C function → Rust function → branch coverage → exact existing test evidence, plus bounded reproductions for candidate mismatches.

- [ ] Datapath/NFQUEUE/conntrack/journal/raw packet execution and OpenWrt memory/ABI.
  - Evidence slice: clean D2O datapath `make -B check` and Zig-backed `make cross` passed; R2O datapath crate passed 344/344 active tests (5 ignored). Official OpenWrt 25.12.5 release/QEMU scripts passed for aarch64, armv7 and mipsel. A full-system AArch64 QEMU TCG gateway FORWARD smoke passed at 256 MiB: IPv6 SO_MARK/table 100, 4-KiB UDP request/reply through NFQUEUE, conntrack, 33rd fail-open packet with a stopped consumer and queue length 32, then all 100 requests/replies after resume. ARMv5 release/QEMU ABI smoke passed for six binaries; a 300-s 128-MiB production-shaped OpenWrt QEMU mixed-load soak now passes on current R2O main (see the matrix and REA_EVIDENCE); physical-router calibration remains untested and out of scope. Bounded 128-MiB full-system QEMU TCG mixed traffic (5000 IPv6 UDP echoes plus a concurrent 64-KiB TCP echo) passed with R2O VmHWM 1592 KiB and zero kernel-reported NFQUEUE loss. Function mapping and the IPv6-oracle/resource limits are in `docs/parity-function-inventory.md`. A fresh Rust release build plus `scripts/test-nfq-ipv6-forward-netns.sh` in Debian 13 WSL2 now also passes 4-KiB UDP and exact 64-KiB TCP gateway FORWARD/NFQUEUE request/reply, nonzero TCP queue counters, IPv6 conntrack, SO_MARK `0x123`, and stopped-consumer queue-32 fail-open (33rd packet); 100 UDP exchanges pass after resume. Log: `/mnt/e/r2o-tooling/tests/r2o-nfq-ipv6-forward-tcp-2026-11-01.log`. These are runtime integration checks, not C parity; the C IPv6 oracle remains unavailable because D2O NFQUEUE binds AF_INET only. The 300-s 128-MiB OpenWrt QEMU soak now passes on current R2O main; one earlier UDP timeout is unresolved and documented in REA_EVIDENCE.md. Source-audited and fixed NFQUEUE error recovery: R2O distinguishes poll errors from recv errors; poll errors, EINTR and EAGAIN continue without flushing, while ENOBUFS and other recv errors release held/deferred verdicts and continue. RED/GREEN policy test `receive_error_policy_preserves_poll_and_empty_queue_cases` passes; full crate 347 passed / 0 failed / 6 ignored; release IPv6 FORWARD smoke passed. Live injected EIO passed in scripts/test-nfq-ipv6-recv-error-recovery.sh and the release IPv6 gateway scenario succeeded; no C IPv6 runtime oracle exists.
- [ ] TCP/TLS/HTTP/ECH/classifier/verify and their C↔Rust call paths.
  - Evidence slice: clean D2O core tests for HTTP-search, HTTPS probe/response, ECH, TLS 1.2, H3, STUN/voice, and QUIC wire/Initial/Hello passed before test_quicprobe stopped make -B check; R2O workspace tests and formatting gates passed. The HTTP response-reader audit aligned the 127/128-byte chunk-line boundary, opaque malformed chunk extensions/trailers, and colonless header handling with five C/Rust vectors; the focused R2O parser target passes 10/10. Header control bytes, buffered body bytes after framing, and other call-path branches remain open. Core `d2k_verify_probe*` maps to R2O `fetch.rs`; reverse-direction TLS 1.2 maps from D2O `detect/response.c` to R2O `response.rs`, where shared scan/decision vectors pass but socket resolution/retry remains partial.
  - Classifier slice completed 2026-11-01: full-tree/control, candidate-filter, clear-confirm, white-decoy, and raw-production C/Rust differentials passed. The unfiltered production path also matched after 11 property misses, compose miss, and one poison miss before disorder-pos2 succeeded; see the promoted matrix row. No live-DPI effectiveness is claimed.
- [ ] QUIC and Discord RTC/UDP lifecycle, endpoint changes, reconnects, expiry, and long sessions.
  - QUIC HTTP/3 2026-11-01: clean pinned D2O `304ba893dd37197128ac8799c0495b035f6a38c0` and production R2O passed the full-stage harness 9/9 before the latest fixture extension. After adding a pre-header H3 RESET_STREAM case, the updated main stage test passed 1/1 in Debian 13 WSL2 (44.77 s).
  - The new C/Rust pre-header reset case returns NotRun on both sides, with matching app_bytes/requests; Rust reports an explicit error and no false stall. No production code changed.
  - The isolated `/budget-slow` replay returned NotRun on both sides (C app_bytes=9/requests=1/packets=32; Rust app_bytes=9/requests=1/33 datagrams, 7 PINGs sent and ACKed). The earlier single C Cut/Rust NotRun did not recur; its cause remains unproven.
  - Existing coverage includes repeated budgets, growth before/past RTO, HTTP 451, delayed body/total deadline, reply drop/close, Content-Length mismatch, mid-body RESET_STREAM, and live one-way activity. The row remains partial at 0/2; other transport errors, timing-sensitive stall and lifecycle remain open.
  - Discord C scheduler 2026-11-01: pinned D2O was rebuilt from an isolated archive in Debian 13 WSL2; `make -C core test_sched` and `test_sched --voice-only` passed. Process restart, automatic recovery, endpoint changes, and long RTC remain open (matrix entry #121).
### Task 3: Root audit of Discovery, scheduler, catalog, services, and full apply cycle

- [ ] Trace packet → detection → classification → candidate search → verify → ACK → APPLIED → persistence → reapply after restart in both repos.
  - Evidence 2026-11-01: the opt-in QEMU procd lifecycle differential now compares pinned D2O and production R2O waiters through rc.d links, delayed /opt, cancellation and stop/restart. It uses stub Entware service scripts; automatic flash boot, real daemon crash recovery and reboot-persisted reapply remain open, so this task stays unchecked.
- [ ] Cover failures, interrupts, retries, concurrent targets, stale generations, service restarts, settings/firewall/panel control surfaces.
- [ ] Protect the z2kOW-derived Telegram implementation and audit only its Rust integration and evidence.

### Task 4: Resolve each confirmed parity gap on main

For each gap, before moving to the next:

- [ ] Reproduce donor behavior with a bounded C fixture/harness.
- [ ] Add a C/Rust differential regression that asserts the affected branch and state/output.
- [ ] Implement the smallest Rust-side fix in the existing architecture.
- [ ] Run targeted C/Rust and relevant Rust tests; record command and result in the matrix.
- [ ] Commit the verified fix directly on `main`; do not include unrelated user data.

### Task 5: Cross-system verification

- [x] Run the complete Cargo workspace tests and formatting/check gates.
- [ ] Run full applicable D2O C suites and all registered upstream differential scenarios affected by changes.
  - Evidence 2026-11-01: clean-source upstream manifest 53/53 passed; datapath, detect, and telegram C suites passed. The full core suite failed twice at upstream test_quicprobe. Earlier isolated retries and one strace run passed; this follow-up reproduced one failure, then five direct reruns and one instrumented replay passed. The root cause remains unresolved, so this gate stays open. D2O datapath `make cross` linked aarch64, big-endian MIPS and mipsel through Zig; R2O OpenWrt release/QEMU gates passed for aarch64, armv7 and mipsel. ARMv5 release/QEMU ABI smoke passed for six binaries; a current-source 300-s full-system OpenWrt QEMU mixed-load profile passed at 128 MiB; physical-router calibration remains untested and out of scope. A bounded 128-MiB full-system mixed-load follow-up passed: 5000 IPv6 UDP request/reply pairs and a concurrent 64-KiB TCP echo; R2O VmHWM 1592 KiB, MemAvailable 21372 KiB, kernel-reported NFQUEUE loss 0.
- [ ] Run NFQUEUE/runtime integration, QEMU and required ABI builds, plus bounded resource/performance checks for the 128 MB target.
- [ ] Do not claim hardware calibration or live-router behavior without physical hardware; state that limitation.

### Task 6: Publish the evidence-weighted matrix

**Create:** `docs/functional-parity-matrix.md`.

- [ ] Include every scoped production C function/group, its Rust counterpart, row weight, status (`proven equivalent`, `partial`, `unverified`), and supporting test/evidence.
- [ ] Compute percentage as `sum(weights of proven-equivalent rows) / sum(weights of all in-scope rows) × 100`; show numerator and denominator.
- [ ] List partial/unverified requirements and exact limits of fixtures, platform builds, NFQUEUE, QEMU, and hardware coverage.
