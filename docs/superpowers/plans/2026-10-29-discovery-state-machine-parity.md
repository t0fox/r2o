# Discovery State-Machine Parity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the 1:1 functional transfer of D2O `core/sched.c`, `detect/classify.c`, `detect/bridge.c`, `core/verify.c`, and `core/httpsearch.c` into the current Rust Discovery/Controller before moving to the remaining detectors and services.

**Architecture:** Keep R2O's Discovery, Controller, persistence, raw-probe, and worker architecture. Change only branches proven to differ from the pinned C donor. Add C/Rust differential coverage for each gap. Do not access the physical router or add VPS, relay, or WARP paths.

**Baselines:** D2O `304ba893dd37197128ac8799c0495b035f6a38c0`; R2O starts at `43cd905` on `main`.

**Spec:** User request in this Codex session and repository rules in `AGENTS.md`.

## Review Focus

- Scheduler cooldown keys, signal gating, capacity/eviction, concurrent endpoint admission, saved-address rechecks, timers, queues, cancellation, and ACK/APPLIED/PERSIST ordering match donor behavior.
- Classifier acceptance, transport timeout budgets, split writes/cancellation, raw self-test decisions, control/neutral-ACK handling, and unplannable poison outcomes match donor behavior.
- Verification preserves the client's negotiated TLS protocol and donor ECH replay fallback; only the same proof (including ServerHello and execution evidence) can confirm a candidate.
- HTTP search preserves partial bytes, portal classification, HTTPS gating, distinct APPLIED counts and deadlines, and immediate persistence after confirmation.
- Changes preserve existing R2O subsystem boundaries and introduce no router access or external relay path.

## Tasks

### Task 1: Match HTTP response and APPLIED state transitions

- [x] Add C/Rust differentials for a provider portal with a truncated body and for a partial status/header followed by timeout.
- [x] Make Rust classify those outcomes like donor C and preserve received bytes when a response-head read times out.
- [x] Collect distinct exact APPLIED events until the donor-required count is reached or the 500 ms donor window expires.
- [x] Add differential cases for two delayed unique APPLIED events and an event outside the donor window.
- [x] Run the pinned C HTTP-search harness and focused Rust tests.

### Task 2: Match HTTP HTTPS-gating and durability

- [x] Add a C/Rust caller differential proving HTTPS-served and TLS-blocked states suppress HTTP search.
- [x] Apply the donor HTTPS gate before queuing an HTTP-search task.
- [x] Add a C/Rust durable-state differential after a confirmed HTTP plan and before the normal 60-second catalog flush.
- [x] Persist a confirmed HTTP plan at the donor confirmation boundary without changing unrelated catalog cadence.
- [x] Run `scripts/r2o-http-search-differential.sh` against the pinned donor.

### Task 3: Match TLS verification protocol and ECH fallback

- [x] Add a C/Rust differential for candidate verification against a TLS server that accepts only the captured non-HTTP ALPN or no ALPN.
- [x] Preserve the captured client's negotiated protocol when verifying candidates.
- [x] Add a C/Rust differential for replaying the captured ECH ClientHello when no compatible ECH configuration is available; require ServerHello proof.
- [x] Run `scripts/r2o-tls-verify-differential.sh` and focused ECH tests.

### Task 4: Match scheduler cooldown and endpoint admission

- [x] Differentially test challenge cooldown separation by transport and family.
- [x] Differentially test direct-CLEAR same-signal blocking, changed-signal bypass, and cooldown retention when the retry cannot run.
- [x] Match the late-RST-only bypass after an inconclusive paired RX result while preserving an active generic exhausted cooldown.
- [ ] Match ECH-witness exhaustion and the donor's endpoint-scoped late-only cooldown state.
- [x] Differentially test concurrent tasks sharing an endpoint when measurement slots remain available.
- [ ] Match the donor's 128-entry cooldown-ring eviction behavior under live-entry churn.
- [ ] Differentially test the saved-address neutral-ACK recheck before any trigger is sent.
- [x] Run the scheduler and queue-order differential suites against the pinned donor.

### Task 5: Match classifier and bridge probe branches

- [ ] Differentially test an unplannable accepted poison with failed control and successful neutral ACK; preserve donor Opaque ownership and fallback eligibility.
- [ ] Differentially test the `white-hello-ts` composite for a ClientHello without TCP timestamps.
- [ ] Make production connect/read deadlines follow the configured donor timeout, including its one doubled baseline retry.
- [ ] Make cancellation observable between split spans and while waiting through a split gap.
- [ ] Match donor raw self-test cache/recheck conditions after local probe errors.
- [ ] Compare donor raw packet splits with R2O's supported production split path and record an explicit ruling if preserving R2O architecture prevents exact transport parity.
- [ ] Run classifier, raw-profile, measured-split, and fallback differential suites.

### Task 6: Close out Discovery before other detectors

- [ ] Re-run the full Rust workspace suite, format check, and relevant C/Rust differential scripts.
- [ ] Review and commit each verified task; push each commit to `origin/main`.
- [ ] Record remaining findings before moving to network detectors, QUIC, Discord RTC, Telegram, and other services.
