# Discovery Classifier Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Match d2o's TCP classifier decision when a server replies with bytes that fail the trigger acceptance rule.

**Architecture:** Keep the existing Rust `ProbeBackend` and response parser. In the classifier decision tree, treat `ProbeOutcome::Unproven` as the rejected probe that d2o's `once_probe` returns when `d2k_trigger_accepts` is false. Prove the branch with an executable C/Rust differential using a local TCP fixture.

**Tech Stack:** Rust workspace tests, C99 donor source, Clang 18, shell differential runner.

**Spec:** User request in this Codex session; repository rules in `AGENTS.md`.

## Global Constraints

- Compare against `t0fox/d2o` `304ba893dd37197128ac8799c0495b035f6a38c0` and current `t0fox/r2o` `main`.
- Do not edit the donor checkout or touch the physical router.
- Preserve the existing R2O architecture; introduce no VPS, relay, or WARP path.
- Change only the mismatched classifier outcome handling; leave matching branches intact.

## Review Focus

- Received but unrecognized trigger bytes count as a failed probe and continue the C decision tree; pin with the new C/Rust differential.
- A recognized trigger response remains accepted; pin with existing classifier CLEAR tests.
- A dial timeout remains a distinct flaky result with one doubled retry; pin with `only_our_connect_deadline_gets_one_doubled_retry_and_stays_flaky`.
- A non-timeout transport error remains a failed measurement; pin with `partial_base_transport_error_stops_at_the_base_measurement_like_donor`.
- A valid baseline seed is reused only for the same trigger and endpoint; pin with `base_seed_is_reused_only_for_same_client_hello_and_endpoint`.

---

### Task 1: Add the donor differential for unrecognized replies

**Files:**
- Create: `crates/r2o-controller/tests/d2o_classify_unproven_differential.c`
- Modify: `crates/r2o-controller/tests/classify.rs`
- Modify: `scripts/test-d2o-shared-fixtures.sh`

**Interfaces:**
- The C fixture calls donor `d2k_classify_run` against a local TCP peer and prints `verdict=opaque` and `probes=3` for one unrecognized trigger reply, a rejected split, and an accepted control.
- The Rust test runs the same one-repeat decision sequence and writes the same two lines when `R2O_CLASSIFY_UNPROVEN_DIFF_OUTPUT` is set.

- [x] Add the C loopback fixture and Rust assertion; run the focused differential and observe C `opaque` versus Rust `inconclusive`.
- [x] Confirm the C fixture used only loopback and `no_raw=1`.

### Task 2: Match donor rejection semantics

**Files:**
- Modify: `crates/r2o-controller/src/classify.rs`
- Modify: `crates/r2o-controller/tests/classify.rs`

**Interfaces:**
- `measure` records `ProbeOutcome::Unproven` as `fail`, matching donor `once_probe` returning 0 when `d2k_trigger_accepts` returns false.

- [x] Remove the classifier-only early `Inconclusive` exit for `unproven` base/split replies.
- [x] Run the focused C/Rust differential and confirm both print `verdict=opaque` and `probes=3`.
- [x] Run `cargo +1.98.0 test --workspace --locked --offline` and `cargo +1.98.0 fmt --all -- --check`.
- [x] Commit the verified source and differential test.
