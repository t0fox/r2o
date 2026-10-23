# OpenWrt ARMv7 musl Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pinned OpenWrt ARMv7 hard-float musl workspace build with QEMU acceptance and release artifact.

**Architecture:** Follow the existing OpenWrt MIPS and AArch64 build scripts, using the official OpenWrt 25.12.5 `ipq40xx/generic` toolchain. CI will require the new build and publish the six validated executables.

**Tech Stack:** Rust `nightly-2026-10-17`, OpenWrt GCC 14.3.0 musl toolchain, `armv7-unknown-linux-musleabihf`, QEMU user mode.

**Spec:** `C:\Users\Kirill\.codex\attachments\18013f15-e17e-43af-9672-068059d07b0b\goal-objective.md`

## Global Constraints

- Pin SDK SHA-256 `2284afb56cbeef040372b02b721f1657ce1eee8e1c024fb1a0188374b472ae51`.
- Verify all six workspace binaries are ARM little-endian EABI5 hard-float and statically linked with musl.
- Run binaries and catalog operations under QEMU; do not install on a physical router.
- Preserve the existing signed-release key and ABI identifiers.

## Review Focus

- Missing or modified SDK archive: the build script verifies the pinned SHA-256 before extraction.
- An incorrect SDK override: the script requires its GCC and archiver at the documented paths.
- A binary with the wrong endian, ARM ABI, or dynamic dependency: the ELF checks reject it before QEMU.
- A workspace executable omitted from the build: the six-component loop checks each output.
- A binary that starts but fails its basic runtime contract: QEMU runs `--version` for each and controller catalog clear/check.
- A release packager that silently omits or mis-hashes the new ABI: the multi-ABI fixture checks its archive and manifest digest.
- Windows newline conversion of C-plan fixtures: keep those fixtures LF-terminated so their C/Rust differential remains stable under WSL.

---

### Task 1: OpenWrt ARMv7 build and CI release artifact

**Files:**
- Create: `scripts/r2o-build-openwrt-armv7-musl.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `scripts/package-release.sh`
- Modify: `scripts/test-package-release.sh`
- Modify: `.gitattributes`
- Modify: `README.md`
- Modify: `router/README.md`
- Modify: `crates/r2o-manager/README.md`
- Modify: `ПРОГРЕСС.md`

**Interfaces:**
- Consumes: `R2O_OPENWRT_TOOLCHAIN_CACHE`, `R2O_OPENWRT_CARGO_TARGET_DIR`, and optional `R2O_OPENWRT_ARMV7_SDK`, matching the existing OpenWrt scripts.
- Produces: six release binaries under `target/armv7-unknown-linux-musleabihf/release/`, with `SHA256SUMS`; release and installer ABI name `armv7-openwrt-musl`.

- [x] **Step 1: Create the build script** with pinned SDK URL/hash, `arm-openwrt-linux-gcc` and archiver discovery, Rust build-std, ELF checks, six QEMU `--version` runs, and controller catalog clear/check.
- [x] **Step 2: Run the build script locally** with the OpenWrt SDK and QEMU ARM; expected result is six passing runtime smokes and valid `SHA256SUMS`.
- [x] **Step 3: Extend `scripts/test-package-release.sh` first** so its multi-ABI fixture includes `armv7-openwrt-musl` and verifies the new archive digest; run it and observe rejection by the current package allowlist.
- [x] **Step 4: Add the ABI to `scripts/package-release.sh` and its signed-release build path** in `.github/workflows/release.yml`.
- [x] **Step 5: Keep the touched shell scripts LF-terminated** so the documented WSL build works with Windows `core.autocrlf=true`.
- [x] **Step 6: Add the CI job and required summary dependency**; upload all six binaries and `SHA256SUMS` as `r2o-openwrt-armv7-musl`.
- [x] **Step 7: Document the ABI and local build command** in the root, router, and manager READMEs; record the QEMU result and remaining CI/hardware/release checks in `ПРОГРЕСС.md`.
- [x] **Step 8: Run package-release tests, ShellCheck, format/status checks, and the full workspace**; expected result is a passing package test and clean local verification.
- [ ] **Step 9: Commit the completed implementation on `codex/openwrt-armv7`** after local verification.
- [ ] **Step 10: Obtain the final review, fast-forward the verified commit to `main`, and inspect its exact CI run**; expected result is a successful ARMv7 job and required-check summary.
