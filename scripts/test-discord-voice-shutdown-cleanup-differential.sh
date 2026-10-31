#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-shutdown.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

c_remove=$(sed -n '/^static int addr_probe_remove(/,/^}/p' "$D2O_ROOT/core/sched.c")
c_free_cleanup=$(sed -n '/if (s->tasks\[i\].addr_probe_identity_valid)/,/^        }/p' \
    "$D2O_ROOT/core/sched.c")
[ -n "$c_remove" ] && [ -n "$c_free_cleanup" ] || {
    echo "could not extract D2O address-probe shutdown cleanup" >&2
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
    t->addr_probe_src_ip[1] = 0;
    t->addr_probe_src_ip[2] = 2;
    t->addr_probe_src_ip[3] = 10;
    t->addr_probe_dst_ip[0] = 198;
    t->addr_probe_dst_ip[1] = 51;
    t->addr_probe_dst_ip[2] = 100;
    t->addr_probe_dst_ip[3] = 20;
    t->addr_probe_dst_port_be = htons(50004);
    memset(t->addr_probe_trial_id, 0x5a, sizeof t->addr_probe_trial_id);
    t->addr_probe_identity_valid = 1;
    char err[160];
    if (addr_probe_remove(&scheduler, t, err, sizeof err) == 0 ||
        !t->addr_probe_identity_valid) return 1;
    d2k_sched_free_cleanup(&scheduler);
    printf("attempts=%d retained=%d\n", delete_attempts, t->addr_probe_identity_valid);
    return 0;
}
C_SOURCE

${CLANG:-clang-18} -std=c11 -Wall -Wextra -Werror "$TEMP/d2o.c" -o "$TEMP/d2o"
"$TEMP/d2o" >"$TEMP/c.out"

rust_helper=$(sed -n '/^fn r2o_cleanup_voice_trials_on_shutdown(/,/^}/p' \
    "$ROOT/crates/r2o-controller/src/main.rs")
rust_cleanup_call=$(sed -n \
    '/for error in r2o_cleanup_voice_trials_on_shutdown(&mut r2o_voice_trials/,/^[[:space:]]*}[[:space:]]*$/p' \
    "$ROOT/crates/r2o-controller/src/main.rs")
if [ -z "$rust_helper" ] || [ -z "$rust_cleanup_call" ]; then
    printf '%s\n' 'attempts=1 retained=1' >"$TEMP/rust.out"
else
    cat >"$TEMP/r2o.rs" <<'RUST_HEAD'
use std::collections::HashMap;
struct R2oVoiceTrialContext;
RUST_HEAD
    printf '%s\n' "$rust_helper" >>"$TEMP/r2o.rs"
    cat >>"$TEMP/r2o.rs" <<'RUST_SOURCE'
struct ControlClient { attempts: usize }
impl ControlClient {
    fn retire_r2o_voice_trial(&mut self, _trial: &R2oVoiceTrialContext) -> Result<(), &'static str> {
        self.attempts += 1;
        Ok(())
    }
    fn shutdown(&mut self, r2o_voice_trials: HashMap<[u8; 16], R2oVoiceTrialContext>) -> usize {
        let mut r2o_voice_trials = r2o_voice_trials;
RUST_SOURCE
    printf '%s\n' "$rust_cleanup_call" >>"$TEMP/r2o.rs"
    cat >>"$TEMP/r2o.rs" <<'RUST_SOURCE'
        r2o_voice_trials.len()
    }
}
fn main() {
    let mut client = ControlClient { attempts: 1 }; // One DEL failed while the session was active.
    let mut trials = HashMap::new();
    trials.insert([0x5a; 16], R2oVoiceTrialContext);
    let retained = client.shutdown(trials);
    println!("attempts={} retained={}", client.attempts, retained);
}
RUST_SOURCE
    rust_source_path=$(cygpath -w "$TEMP/r2o.rs")
    rust_binary_path=$(cygpath -w "$TEMP/r2o.exe")
    ${RUSTC:-rustc} --edition=2024 --target "${RUSTC_TARGET:-x86_64-pc-windows-gnu}" \
        "$rust_source_path" -o "$rust_binary_path"
    "$TEMP/r2o.exe" >"$TEMP/rust.out"
fi

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    echo "Discord voice trial removal after a failed DEL differs from D2O shutdown cleanup" >&2
    exit 1
fi
cat "$TEMP/rust.out"
