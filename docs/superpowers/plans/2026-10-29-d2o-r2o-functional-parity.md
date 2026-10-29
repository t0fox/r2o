# D2O to R2O Functional Parity Plan

> **For agentic workers:** follow the read-only audit assignments first. A confirmed mismatch is handled on `main` as reproduce in C → differential regression → minimal Rust fix → targeted/full verification → commit.

**Goal:** Maximize proven branch-level functional parity between current `t0fox/d2o` C and `t0fox/r2o` Rust, report the evidence-weighted percentage and remaining unverified behavior.

**Architecture:** Preserve R2O's existing Rust crates and service boundaries. D2O C is the behavioral oracle and remains test-only; no C runtime path is added. All edits and commits happen directly on `main` as the user explicitly required.

**Tech Stack:** C11 donor harnesses, Rust/Cargo workspace, NFQUEUE/netlink, OpenWrt service scripts, QEMU and target ABI builds.

**Spec:** User-provided active goal in this Codex thread; there is no separate repository spec.

## Global Constraints

- Compare current `t0fox/d2o/main` and `t0fox/r2o/main` before scoring; starting baseline is d2o `304ba893dd37197128ac8799c0495b035f6a38c0` and r2o `1d2fbdc05bef418def9dc3283d5837ac17e516c5`.
- Keep Telegram on its existing Rust z2kOW-derived implementation; do not replace or rewrite it.
- Do not use a physical router, VPS, relay, or WARP; do not put C back into runtime.
- Preserve the R2O architecture and OpenWrt 128 MB RAM target.
- Keep user-owned `.audit/`, `captures/`, and the dirty D2O checkout untouched.
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

- [ ] Record current remote main SHAs and clean-source paths; preserve user-owned dirty D2O files.
- [ ] Enumerate production C functions, Rust counterparts/callers, and tests; tag behavior branches, state transitions, timers, errors, and side effects.
- [ ] Read existing 51-scenario upstream differential manifest as prior evidence without rerunning it wholesale.
- [ ] Define the matrix denominator from unique observable C behavior branches; assign weight 3 to packet/plan safety and persistence branches, 2 to lifecycle/retry/measurement branches, and 1 to diagnostics/UI branches. No credit for code presence alone; partial/unverified rows score zero until proven.

### Task 2: Parallel independent source audits

Each Luna agent is read-only on the shared `main` checkout; no branch/worktree creation or file edits. Return C function → Rust function → branch coverage → exact existing test evidence, plus minimal reproductions for confirmed candidate mismatches.

- [ ] Datapath/NFQUEUE/conntrack/journal/raw packet execution and OpenWrt memory/ABI.
- [ ] TCP/TLS/HTTP/ECH/classifier/verify and their C↔Rust call paths.
- [ ] QUIC and Discord RTC/UDP lifecycle, endpoint changes, reconnects, expiry, and long sessions.

### Task 3: Root audit of Discovery, scheduler, catalog, services, and full apply cycle

- [ ] Trace packet → detection → classification → candidate search → verify → ACK → APPLIED → persistence → reapply after restart in both repos.
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

- [ ] Run the complete Cargo workspace tests and formatting/check gates.
- [ ] Run full applicable D2O C suites and all registered upstream differential scenarios affected by changes.
- [ ] Run NFQUEUE/runtime integration, QEMU and required ABI builds, plus bounded resource/performance checks for the 128 MB target.
- [ ] Do not claim hardware calibration or live-router behavior without physical hardware; state that limitation.

### Task 6: Publish the evidence-weighted matrix

**Create:** `docs/functional-parity-matrix.md`.

- [ ] Include every scoped production C function/group, its Rust counterpart, row weight, status (`proven equivalent`, `partial`, `unverified`), and supporting test/evidence.
- [ ] Compute percentage as `sum(weights of proven-equivalent rows) / sum(weights of all in-scope rows) × 100`; show numerator and denominator.
- [ ] List partial/unverified requirements and exact limits of fixtures, platform builds, NFQUEUE, QEMU, and hardware coverage.
