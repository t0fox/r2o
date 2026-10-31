#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-confirm-delete.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

c_remove=$(sed -n '/^static int addr_probe_remove(/,/^}/p' "$D2O_ROOT/core/sched.c")
c_confirm_cleanup=$(sed -n \
    '/^    if (t->addr_probe_identity_valid)/,/^    }/p' "$D2O_ROOT/core/sched.c")
c_free_cleanup=$(sed -n '/if (s->tasks\[i\].addr_probe_identity_valid)/,/^        }/p' \
    "$D2O_ROOT/core/sched.c")
[ -n "$c_remove" ] && [ -n "$c_confirm_cleanup" ] && [ -n "$c_free_cleanup" ] || {
    echo "could not extract D2O voice-confirmation cleanup" >&2
    exit 2
}

cat >"$TEMP/d2o.c" <<C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define D2K_TRIAL_ID_LEN 16
#define SCHED_MAX_TASKS 1
typedef struct {
    int family;
    char ip[64];
    unsigned port;
    uint8_t addr_probe_src_ip[16];
    uint16_t addr_probe_src_port_be;
    uint8_t addr_probe_trial_id[D2K_TRIAL_ID_LEN];
    int addr_probe_identity_valid;
    uint8_t addr_probe_dst_ip[16];
    uint16_t addr_probe_dst_port_be;
} task;
typedef struct { int link_fd; task tasks[SCHED_MAX_TASKS]; } d2k_sched;

static int d2k_link_del_addr_probe_family(
    int, const uint8_t *, uint16_t, const uint8_t *, uint16_t,
    uint8_t, int, const uint8_t *, char *, size_t);
$c_remove

static int delete_attempts;
static int d2k_link_del_addr_probe_family(
    int fd, const uint8_t *src, uint16_t sport, const uint8_t *dst, uint16_t dport,
    uint8_t protocol, int family, const uint8_t *trial, char *err, size_t errcap)
{
    (void)fd; (void)src; (void)sport; (void)dst; (void)dport;
    (void)protocol; (void)family; (void)trial;
    delete_attempts++;
    if (delete_attempts == 1) {
        snprintf(err, errcap, "simulated broken control socket");
        return -1;
    }
    return 0;
}

static void d2k_voice_confirm_cleanup(d2k_sched *s, task *t)
{
    char err[160];
$c_confirm_cleanup
}

static void d2k_sched_free_cleanup(d2k_sched *s)
{
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        char err[160];
$c_free_cleanup
    }
}

int main(void)
{
    d2k_sched scheduler = {0};
    task *t = &scheduler.tasks[0];
    t->family = 4;
    t->addr_probe_src_ip[0] = 192;
    t->addr_probe_src_ip[2] = 2;
    t->addr_probe_src_ip[3] = 10;
    t->addr_probe_dst_ip[0] = 198;
    t->addr_probe_dst_ip[1] = 51;
    t->addr_probe_dst_ip[2] = 100;
    t->addr_probe_dst_ip[3] = 20;
    t->addr_probe_dst_port_be = htons(50004);
    memset(t->addr_probe_trial_id, 0x5a, sizeof t->addr_probe_trial_id);
    t->addr_probe_identity_valid = 1;
    d2k_voice_confirm_cleanup(&scheduler, t); /* permanent plan succeeded; first DEL failed */
    if (delete_attempts != 1 || !t->addr_probe_identity_valid) return 1;
    d2k_sched_free_cleanup(&scheduler);
    printf("attempts=%d retained=%d\n", delete_attempts, t->addr_probe_identity_valid);
    return 0;
}
C_SOURCE

${CLANG:-clang-18} -std=c11 -Wall -Wextra -Werror "$TEMP/d2o.c" -o "$TEMP/d2o"
"$TEMP/d2o" >"$TEMP/c.out"

R2O_MAIN="$ROOT/crates/r2o-controller/src/main.rs"
rust_hold=$(sed -n '/^fn r2o_hold_voice_trial_until_expiry(/,/^}/p' "$R2O_MAIN")
rust_finish=$(sed -n '/^fn r2o_finish_voice_trial_confirmation(/,/^}/p' "$R2O_MAIN")
rust_shutdown=$(sed -n '/^fn r2o_cleanup_voice_trials_on_shutdown(/,/^}/p' "$R2O_MAIN")
rust_can_start=$(sed -n '/^fn r2o_voice_trial_can_start_search(/,/^}/p' "$R2O_MAIN")
rust_target_active=$(sed -n '/^fn r2o_voice_target_has_active_trial(/,/^}/p' "$R2O_MAIN")
if [ -z "$rust_hold" ] || [ -z "$rust_finish" ] || [ -z "$rust_shutdown" ] ||
   [ -z "$rust_can_start" ] || [ -z "$rust_target_active" ] ||
   ! grep -q 'r2o_finish_voice_trial_confirmation(' "$R2O_MAIN" ||
   ! grep -q '&mut r2o_voice_trials' "$R2O_MAIN"; then
    printf '%s\n' 'attempts=1 retained=0' >"$TEMP/rust.out"
else
    cat >"$TEMP/r2o.rs" <<'RUST_HEAD'
use std::collections::HashMap;
mod r2o_controller {
    pub mod voice_discovery { pub type R2oVoiceTarget = u8; }
}
#[derive(Clone)]
struct R2oVoiceTrialContext {
    target: u8,
    trial_id: [u8; 16],
    voice_flow_key: Option<[u8; 1]>,
    renew_at: u8,
    expires_at: u8,
    response_confirmed: bool,
}
RUST_HEAD
    printf '%s\n' "$rust_hold" "$rust_finish" "$rust_shutdown" "$rust_target_active" "$rust_can_start" >>"$TEMP/r2o.rs"
    cat >>"$TEMP/r2o.rs" <<'RUST_SOURCE'
fn main() {
    let trial = R2oVoiceTrialContext {
        target: 1,
        trial_id: [0x5a; 16],
        voice_flow_key: Some([1]),
        renew_at: 2,
        expires_at: 10,
        response_confirmed: true,
    };
    let mut trials = HashMap::from([(trial.trial_id, trial.clone())]);
    let attempts = std::cell::Cell::new(1); // The DEL in voice confirmation failed.
    r2o_finish_voice_trial_confirmation(&mut trials, trial, false);
    assert!(!r2o_voice_target_has_active_trial(&trials, &1));
    assert!(r2o_voice_trial_can_start_search(&trials));
    let errors = r2o_cleanup_voice_trials_on_shutdown(&mut trials, |_trial| {
        attempts.set(attempts.get() + 1);
        Ok::<(), String>(())
    });
    assert!(errors.is_empty());
    println!("attempts={} retained={}", attempts.get(), trials.len());
}
RUST_SOURCE
    rust_source_path=$(cygpath -w "$TEMP/r2o.rs")
    rust_binary_path=$(cygpath -w "$TEMP/r2o.exe")
    ${RUSTC:-rustc} --edition=2024 --target "${RUSTC_TARGET:-x86_64-pc-windows-gnu}" \
        "$rust_source_path" -o "$rust_binary_path"
    "$TEMP/r2o.exe" >"$TEMP/rust.out"
fi

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    echo "Discord confirmation lost the owned trial after DEL failure" >&2
    exit 1
fi
cat "$TEMP/rust.out"
