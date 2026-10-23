# Discord RTP proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Require observed bidirectional RTP packet progression before persisting a Discord voice binding.

**Architecture:** The datapath retains an exact STUN/Discovery trial after its response, observes accepted RTP packets on that flow, and emits a separate proof event. The controller only persists that event and ignores legacy STUN/Discovery-only bindings when activating a catalog.

**Tech Stack:** Rust workspace, local control protocol, NFQUEUE datapath, existing unit and integration suites.

**Spec:** `docs/superpowers/specs/2026-10-23-discord-rtp-proof-design.md`

## Global Constraints

- Match the exact flow and trial ID; keep state bounded to the existing voice limit and 120-second TTL.
- Require three progressing RTP sequence numbers in both directions.
- Count only accepted packets and do not claim audio decoding or quality.
- Preserve STUN and Discord Discovery as prerequisites, never as RTP proof.

## Review Focus

- Malformed RTP and RTCP must not count as media packets.
- Retransmitted or out-of-order sequence numbers must not satisfy progression.
- Discovery SSRC mismatch, wrong tuple, expired trial, and duplicate proof must fail closed.
- Old catalog bindings verified by STUN/Discovery must not be installed.
- Deferred or dropped NFQUEUE packets must not count as forwarded RTP.

### Task 1: RTP proof state and packet parser

**Files:** Modify `crates/r2o-datapath/src/r2o_voice.rs` and its module tests.

- [x] Add tests for valid RTP, malformed headers/padding, exact tuple/SSRC matching, sequence progression, expiry/renewal, and the 3-per-direction threshold.
- [x] Implement a bounded parser/state tracker and retain pending trials after STUN/Discovery response.
- [x] Run focused and workspace datapath tests.

### Task 2: Control event and journal

**Files:** Modify `crates/r2k-core/src/control.rs`, `crates/r2k-core/tests/control.rs`, and `crates/r2o-datapath/src/flow_journal.rs`.

- [x] Add codec tests for an RTP proof with directional counts and invalid counts/flow IDs.
- [x] Add the RTP proof event kind and decoder, then include it in the flow journal.
- [x] Run the core control and datapath journal tests.

### Task 3: Count only forwarded packets

**Files:** Modify `crates/r2o-datapath/src/main.rs` and datapath integration tests.

- [x] Verify that the observation hook is reached only after `NF_ACCEPT`; deferred, dropped, and replaced paths do not invoke it. Unit tests reject wrong flows.
- [x] Observe RTP only after NFQUEUE accepts the original packet; emit one proof once both thresholds pass.
- [x] Run datapath tests and the NFQUEUE namespace integration with synthetic STUN and bidirectional RTP.

### Task 4: Persist only RTP-confirmed bindings

**Files:** Modify `crates/r2o-controller/src/main.rs`, `crates/r2o-controller/src/voice_discovery.rs`, and controller tests.

- [x] Add tests that STUN/Discovery cannot persist a voice binding and that the RTP proof does.
- [x] Keep the trial open after STUN/Discovery, require the RTP event, and persist verification value `5` only then.
- [x] Skip activation of legacy verification values `3` and `4`.
- [x] Run controller tests.

### Task 5: Full verification and documentation

**Files:** Update `ПРОГРЕСС.md` and the Discord section in `README.md` if needed.

- [x] Run local formatting, workspace tests, warning checks, NFQUEUE integration, and record the synthetic RTP proof boundary.
- [x] Run pinned baseline/upstream C/Rust differential CI and target QEMU smoke after pushing the reviewed commit.
- [x] Record that bidirectional RTP packet passage is confirmed while audio quality and physical-router acceptance remain field checks.
