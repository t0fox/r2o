#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected D2O $EXPECTED_D2O_SHA, got $ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-trial-clock.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

c_start=$(sed -n '/t->started_ms = s->clock_seen ? s->now_ms : 0;/p' "$D2O_ROOT/core/sched.c")
rust_start=$(sed -n '/let r2o_started_at = r2o_measure_started_at;/p' "$ROOT/crates/r2o-controller/src/main.rs")
rust_deadline=$(sed -n '/let expires_at = started_at + R2O_VOICE_TRIAL_TASK_LIFETIME;/p' "$ROOT/crates/r2o-controller/src/main.rs")
c_queue_expiry=$(sed -n 's/^[[:space:]]*if (\(now_ms - t->queued_ms > SCHED_TASK_LIFE_MS\)) {[[:space:]]*$/\1/p' "$D2O_ROOT/core/sched.c")
c_lifetime=$(sed -n 's/^#define SCHED_TASK_LIFE_MS (\(.*\))[[:space:]]*$/\1/p' "$D2O_ROOT/core/sched.c")
rust_queue_expiry=$(sed -n '/deadline.is_some_and(|deadline| now > deadline)/p' "$ROOT/crates/r2o-controller/src/r2o_resource_limit.rs")
rust_lifetime=$(sed -n 's/^const R2O_VOICE_TRIAL_TASK_LIFETIME: std::time::Duration = \(.*\);$/\1/p' "$ROOT/crates/r2o-controller/src/main.rs")
[ -n "$c_start" ] && [ -n "$rust_start" ] && [ -n "$rust_deadline" ] \
    && [ -n "$c_queue_expiry" ] && [ -n "$c_lifetime" ] \
    && [ -n "$rust_queue_expiry" ] && [ -n "$rust_lifetime" ] || {
    echo "voice lifecycle timestamp source changed; review this differential fixture" >&2
    exit 2
}

cat >"$TEMP/d2o.c" <<C_SOURCE
#include <stdint.h>
#include <stdio.h>
typedef struct { int64_t started_ms; int64_t queued_ms; } task;
typedef struct { int clock_seen; int64_t now_ms; } d2k_sched;
int main(void) {
    task task_storage = {0, 0};
    task *t = &task_storage;
    d2k_sched scheduler_storage = {1, 9 * 60 * 1000};
    d2k_sched *s = &scheduler_storage;
    $c_start
    int64_t now_ms = 18 * 60 * 1000;
    int64_t expires_ms = t->started_ms + 10 * 60 * 1000;
    printf("trial_at_nine_minutes_after_launch|%s\\n", now_ms < expires_ms ? "active" : "expired");
    task queue_storage = {0, 0};
    t = &queue_storage;
    int64_t SCHED_TASK_LIFE_MS = $c_lifetime;
    now_ms = SCHED_TASK_LIFE_MS + 1;
    int queue_expired = ($c_queue_expiry);
    printf("queued_after_ten_minutes|%s\\n", queue_expired ? "expired" : "active");
    return 0;
}
C_SOURCE

cat >"$TEMP/r2o.rs" <<RUST_HEAD
#![allow(dead_code)]
use std::time::{Duration, Instant};
const R2O_VOICE_TRIAL_TASK_LIFETIME: Duration = $rust_lifetime;
fn expired(now: Instant, deadline: Option<Instant>) -> bool { $rust_queue_expiry }
mod r2o_controller {
    pub mod voice_discovery {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct R2oVoiceTarget {
            pub client: std::net::Ipv4Addr,
            pub server: std::net::SocketAddrV4,
        }
    }
    pub mod voice_targets {
        pub use super::voice_discovery::R2oVoiceTarget;
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct R2oVoiceDiagnosticContext {
    report_id: Option<u64>,
    queued_at: Instant,
    started_at: Option<Instant>,
    probe_units: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
RUST_HEAD

sed -n '/^struct R2oVoiceDiscoveryJob {/,/^struct R2oVoiceDiscoveryOutcome {/ { /^struct R2oVoiceDiscoveryOutcome {/d; /^#\[cfg(unix)\]$/d; p; }' \
    "$ROOT/crates/r2o-controller/src/main.rs" >>"$TEMP/r2o.rs"

cat >>"$TEMP/r2o.rs" <<RUST_SOURCE
fn main() {
    let r2o_measure_started_at = Duration::from_secs(9 * 60);
    $rust_start
    let started_at = r2o_started_at;
    $rust_deadline
    let now = Duration::from_secs(18 * 60);
    println!("trial_at_nine_minutes_after_launch|{}", if now < expires_at { "active" } else { "expired" });
    let queued_at = Instant::now();
    let queue_deadline = queued_at + R2O_VOICE_TRIAL_TASK_LIFETIME;
    let queue_expired = expired(queue_deadline + Duration::from_nanos(1), Some(queue_deadline));
    println!("queued_after_ten_minutes|{}", if queue_expired { "expired" } else { "active" });

    let target = r2o_controller::voice_discovery::R2oVoiceTarget {
        client: "192.0.2.10".parse().unwrap(),
        server: "198.51.100.20:50004".parse().unwrap(),
    };
    let job = R2oVoiceDiscoveryJob {
        target,
        flow: None,
        known_prefix: None,
        queued_at,
        diagnostic: R2oVoiceDiagnosticContext {
            report_id: None,
            queued_at,
            started_at: None,
            probe_units: 0,
        },
    };
    let mut pending = R2oVoiceLatestQueue::default();
    assert_eq!(pending.offer(job, false), None);
    assert_eq!(pending.expire_pending(queue_deadline), None);
    assert_eq!(
        pending
            .expire_pending(queue_deadline + Duration::from_nanos(1))
            .map(|expired| expired.target),
        Some(target)
    );
}
RUST_SOURCE

${CLANG:-clang-18} -std=c11 -Wall -Wextra -Werror "$TEMP/d2o.c" -o "$TEMP/d2o"
rust_source_path=$(cygpath -w "$TEMP/r2o.rs")
rust_binary_path=$(cygpath -w "$TEMP/r2o.exe")
${RUSTC:-rustc} --edition=2024 --target "${RUSTC_TARGET:-x86_64-pc-windows-gnu}" "$rust_source_path" -o "$rust_binary_path"
"$TEMP/d2o" >"$TEMP/c.out"
"$TEMP/r2o.exe" >"$TEMP/rust.out"
diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/rust.out"
