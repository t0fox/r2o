# NFQUEUE control reconnect regression plan

> **Goal:** Make voice control reconnect reliable under the Linux namespace acceptance test, without changing donor wire semantics.

**Base:** `271853e7b68fdfed2fc3b7d4bd9069e2e9d81aeb`

**Evidence:** CI run `39965287737` failed in `test-nfq-netns.sh` after receiving the reconnect greeting, when the control peer closed before the repeated voice suspicion. The same test passed in the preceding run `39962404252`; the failure is intermittent.

**Constraints:** Preserve control wire version and packet behavior. Do not install on a physical router. Diagnose the daemon exit before changing reconnect behavior.

- [x] **Step 1: Preserve datapath diagnostics on failed namespace acceptance** so the next failure identifies why the control peer closed. The first log showed two accepts and that the reconnect was closed while the old peer was still tracked; failure cleanup now prints the voice datapath log before removing it.
- [x] **Step 2: Reproduce the failing reconnect and add a focused regression** for the observed control-server state transition. The new Unix-socket test failed before the fix when the reconnect was queued as the previous peer closed.
- [x] **Step 3: Apply the smallest fix for the demonstrated cause** and retain the existing end-to-end voice proof flow. `ControlServer::poll` now detects and reports the old peer's disconnect before accepting the queued reconnect, leaving the disconnected state visible to the voice-suspicion rearm logic.
- [x] **Step 4: Run the focused regression repeatedly, the namespace acceptance, and the required workspace checks.** Full `r2o-datapath` tests passed (213 unit tests; integration suites passed), formatting and shell syntax checks passed, and three parallel NFQUEUE namespace runs passed through reconnect, voice proof, and cleanup.
- [x] **Step 5: Obtain final review, commit, fast-forward to `main`, and inspect CI for the exact commit.** The independent review found no actionable issues; commit `90cb0179d1eba8989874608b152e519bd95e5904` is on `main`, and CI run `39970453166` completed all 21 jobs successfully.
