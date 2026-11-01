#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${D2O_ROOT:-$(dirname "$ROOT")/d2o}
TEST_TMPDIR=${R2O_TEST_TMPDIR:-${TMPDIR:-/tmp}}
mkdir -p "$TEST_TMPDIR"
TEMP=$(mktemp -d "$TEST_TMPDIR/r2o-process-stats.XXXXXX")
case "$TEMP" in "$TEST_TMPDIR"/r2o-process-stats.*) ;; *) exit 2 ;; esac
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
export TMPDIR="$TEST_TMPDIR"
export R2O_PROCESS_STATS_STAT='4242 (r2o worker (test)) S 0 0 0 0 0 0 0 0 0 0 123 45'
export R2O_PROCESS_STATS_STATM='500 11 0 0 0 0 0'

python3 - "$D2O_ROOT/datapath/d2kd.c" "$TEMP/d2o-self-cost.c" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
start = source.index("static void self_cost(")
open_brace = source.index("{", start)
depth = 0
end = None
for position in range(open_brace, len(source)):
    if source[position] == "{":
        depth += 1
    elif source[position] == "}":
        depth -= 1
        if depth == 0:
            end = position + 1
            break
assert end is not None
function = source[start:end]
wrapper = r"""
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int stat_opened, statm_opened;
static size_t stat_bytes_read;

static FILE *fixture_fopen(const char *path, const char *mode)
{
    const char *contents = NULL;
    (void)mode;
    if (strcmp(path, "/proc/self/stat") == 0) {
        contents = getenv("R2O_PROCESS_STATS_STAT");
        stat_opened = contents != NULL;
    } else if (strcmp(path, "/proc/self/statm") == 0) {
        contents = getenv("R2O_PROCESS_STATS_STATM");
        statm_opened = contents != NULL;
    }
    if (!contents)
        return NULL;
    return fmemopen((void *)contents, strlen(contents), "r");
}

static size_t fixture_fread(void *ptr, size_t size, size_t count, FILE *stream)
{
    size_t read = fread(ptr, size, count, stream);
    stat_bytes_read += read * size;
    return read;
}

static long fixture_sysconf(int name)
{
    if (name == _SC_CLK_TCK)
        return 100;
    if (name == _SC_PAGESIZE)
        return 4096;
    return -1;
}

#define fopen fixture_fopen
#define fread fixture_fread
#define sysconf fixture_sysconf
"""
main = r"""
#undef fopen
#undef fread
#undef sysconf
int main(void)
{
    uint64_t cpu_ms = 0, rss_kb = 0;
    self_cost(&cpu_ms, &rss_kb);
    if (!stat_opened || !statm_opened || stat_bytes_read == 0) {
        fprintf(stderr, "D2O did not read both process-stat fixtures\n");
        return 3;
    }
    printf("%" PRIu64 ",%" PRIu64 "\n", cpu_ms, rss_kb);
    return 0;
}
"""
Path(sys.argv[2]).write_text(wrapper + function + main)
PY

cc -std=gnu11 -Wall -Wextra -Werror "$TEMP/d2o-self-cost.c" -o "$TEMP/d2o-self-cost"
d2o_value=$(timeout 3 "$TEMP/d2o-self-cost")
rust_output=$(cargo +1.98.0 test -p r2o-datapath --bin r2o-datapath --locked --offline process_cost_matches_d2o_proc_state_cursor_and_rss -- --nocapture 2>&1)
rust_value=$(printf '%s\n' "$rust_output" | grep 'R2O_PROCESS_COST=' | tail -n 1 | cut -d= -f2-)
if [ -z "$rust_value" ] || [ "$d2o_value" != "$rust_value" ]; then
    printf 'D2O process cost: %s\nR2O process cost: %s\n%s\n' "$d2o_value" "$rust_value" "$rust_output" >&2
    exit 1
fi
printf 'D2O/R2O process CPU ms and RSS KiB: %s; differential PASS\n' "$d2o_value"
