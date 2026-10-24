# Keenetic PPE visibility support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the donor's optional Keenetic PPE visibility rules into R2O without changing router-wide acceleration settings.

**Architecture:** `r2o-ppe-deoffload.sh` owns only tagged `iptables`/`ip6tables` rules and is called from the existing service lifecycle. The manager maps the donor flag into a validated R2O config value; Lava exposes that boolean and triggers the existing settings restart. An optional NDM hook restores the service when Keenetic rebuilds netfilter. Release packaging carries both scripts.

**Tech Stack:** POSIX shell, Rust config/importer and HTTP panel, existing project shell and Cargo tests.

**Spec:** `docs/superpowers/specs/2026-10-24-keenetic-ppe-design.md`

## Global Constraints

- Keep global hardware acceleration enabled; alter only `r2o-ppe` tagged rules.
- Preserve existing OpenWrt `nftables` behavior and no-op when the PPE target is unavailable.
- Do not run commands on a physical router.
- Add no dependencies; use the existing test and release patterns.
- All changes and CI acceptance land on `main`.

## Review Focus

- Foreign PPE rules survive cleanup — mock `iptables` records rule ownership.
- Disabled mode removes owned rules and inserts none — shell lifecycle test.
- Missing PPE target is harmless — shell test with absent target file.
- IPv6 is attempted only when advertised — mock target files.
- Partial insertion remains visible and removable — injected command failure test.
- Invalid config values fail closed — importer and panel validation tests.
- NDM events outside `nat`/`mangle` must not mutate rules — hook test.

---

### Task 1: Import and validate the PPE setting

**Files:** `crates/r2o-manager/src/config.rs`, `crates/r2o-manager/tests/cli.rs`, `router/config.default`

**Interfaces:** Donor `D2K_PPE_DEOFFLOAD` maps to `R2O_PPE_DEOFFLOAD`; accepted values are `0` and `1`, with default `1`.

- [x] Add an importer regression proving donor value `0` is preserved as `R2O_PPE_DEOFFLOAD=0` and is not reported unsupported.
- [x] Run `cargo +1.98.0 test -p r2o-manager --test cli first_config_initialization_imports_supported_settings_without_evaluating_donor_file`; it failed as expected because the new key was rejected from defaults.
- [x] Add the R2O key to default/importable lists, map the donor key, validate the boolean, and add `R2O_PPE_DEOFFLOAD=1` to shipped defaults.
- [x] Run `cargo +1.98.0 test -p r2o-manager --test cli` (11/11) and `cargo +1.98.0 fmt --all -- --check`.
- [x] Commit as `feat: import Keenetic PPE setting`.

### Task 2: Add the isolated PPE rule adapter

**Files:** create `router/r2o-ppe-deoffload.sh` and `scripts/test-r2o-ppe-deoffload.sh`.

**Interfaces:** Helper commands are `ensure`, `remove`, and `status [IPv4-address]`; it reads `R2O_PPE_*`, `PORTS`, `VOICE_PORTS`, and `HTTP_KEEPALIVE_PORTS` from the service environment.

- [ ] Write mock-iptables tests for rule count/shape, repeat ensure, owner-only remove, disabled mode, missing PPE target, IPv6 gating, and failure cleanup; confirm they fail because the helper is absent.
- [ ] Implement the minimum POSIX-shell adapter using tag `r2o-ppe`, paired TCP/UDP rules, connskip 30, donor HTTP keep-alive window, and xtables-lock fallback.
- [ ] Run `sh scripts/test-r2o-ppe-deoffload.sh`, `sh -n router/r2o-ppe-deoffload.sh`, and ShellCheck on both scripts.
- [ ] Commit as `feat: add owned PPE deoffload adapter`.

### Task 3: Wire PPE into service and release lifecycle

**Files:** `router/S99r2o`, create `router/001-r2o.sh`, `router/install.sh`, `router/uninstall.sh`, `scripts/package-release.sh`, `scripts/test-package-release.sh`, `scripts/test-router-firewall.sh`, create `scripts/test-router-ndm-hook.sh`, `.github/workflows/ci.yml`.

**Interfaces:** Service start calls PPE `ensure` after firewall `up`; stop calls `remove`; reapply/heal restore owned rules; `status` prints adapter diagnostics. The installer adds the NDM hook only to an existing standard hook directory, and uninstall removes it only when its contents are still owned. The release archive includes both executable scripts.

- [ ] Add lifecycle assertions proving `ensure` runs after firewall setup, `remove` runs on stop, and heal/reapply restore rules; confirm red against current service.
- [ ] Add adapter path/config validation and nonfatal missing-target handling to `S99r2o`; ensure stop and uninstall remove R2O-owned rules.
- [ ] Add the NDM hook and safe conditional installer/uninstaller handling; confirm `nat`/`mangle` heal and unrelated events are ignored.
- [ ] Add both scripts to release packaging fixture expectations and run both PPE and NDM tests in existing mandatory router lifecycle CI.
- [ ] Run `sh scripts/test-router-firewall.sh`, `sh scripts/test-package-release.sh`, all `scripts/test-router-*.sh`, ShellCheck, and `git diff --check`.
- [ ] Commit as `feat: wire PPE adapter into router lifecycle`.

### Task 4: Expose the setting in Lava

**Files:** `crates/r2o-panel/src/server.rs`, `crates/r2o-panel/assets/index.html`, `crates/r2o-panel/assets/panel.js`, `crates/r2o-panel/tests/http.rs`, `crates/r2o-panel/tests/browser.cjs`.

**Interfaces:** `/api/config` reads/writes `ppe_deoffload` as a boolean backed by `R2O_PPE_DEOFFLOAD`; settings continue through the existing atomic save and `settings-restart` path.

- [ ] Add API/browser regressions for reading enabled/disabled values, saving each value, and rejecting non-booleans; confirm they fail because the setting is absent.
- [ ] Add the field to editable settings and a disabled-by-default-until-controls-enabled Lava checkbox labeled for router PPE visibility.
- [ ] Run `cargo +1.98.0 test -p r2o-panel --locked`, headless Chrome panel tests, full workspace tests, and `cargo +1.98.0 fmt --all -- --check`.
- [ ] Commit as `feat: expose PPE visibility setting in Lava`.

### Task 5: Full acceptance and review

**Files:** updated plan ledger and `ПРОГРЕСС.md`.

- [ ] Run all local CI-equivalent checks, including shell, manager, panel, packaging, NFQUEUE namespace, and C/Rust differential tests.
- [ ] Push `main`; wait for all mandatory jobs; record actual Actions result.
- [ ] Request one independent review of the whole change and fix any Critical/Important finding with TDD.
- [ ] Record acceptance and the physical Keenetic checks that remain in `ПРОГРЕСС.md`; confirm clean `main`.

## Execution ledger

- Ruling: Use a distinct `r2o-ppe` tag — D2O and R2O may share the same iptables table; owner-isolated cleanup is safer — cost if wrong: old `d2k-ppe` rules remain independently managed.
- Ruling: Keep PPE insertion failure nonfatal to ordinary NFQUEUE startup — this matches donor behavior and preserves service availability — cost if wrong: discovery may have lower visibility while status reports the incomplete adapter.
- Task 1: importer regression observed RED, manager CLI suite 11/11 and formatter passed GREEN.
