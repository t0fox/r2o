#!/bin/sh
# Keenetic sysctl и vendor targets моделируются. Rust CLI и lifecycle используются штатные.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HELPER=$ROOT/router/r2o-ppe-deoffload.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
export R2O_DATAPATH_BIN=${R2O_DATAPATH_BIN:-$ROOT/target/release/r2o-datapath}
export WORK R2O_DIR="$WORK" R2O_PROC_DIR="$WORK/proc" R2O_RUN_DIR="$WORK/run" R2O_CONFIG=/dev/null
export R2O_PLATFORM=keenetic FW_BACKEND=iptables IPV6_ENABLED=1 R2O_PPE_DEOFFLOAD=1
export PORTS=0:65535 HTTP_KEEPALIVE_PORTS=80
export PATH="$WORK/bin:$PATH"
proc=$R2O_PROC_DIR
fastnat=$proc/sys/net/netfilter/nf_conntrack_fastnat
journal=$R2O_RUN_DIR/fastnat.saved
mkdir -p "$WORK/bin" "$proc/net/netfilter" "$proc/sys/net/netfilter" \
    "$proc/sys/net/ipv6/conf/all" "$proc/driver/hw_nat/foe"
printf '%s\n' '2000 42 0 2 65535 0 0 0 1' '2001 43 0 2 65535 0 0 0 1' > "$proc/net/netfilter/nfnetlink_queue"
printf '1\n' > "$fastnat"
printf '1\n' > "$proc/sys/net/netfilter/nf_conntrack_acct"
printf '0\n' > "$proc/sys/net/ipv6/conf/all/disable_ipv6"
printf 'PPE\n' > "$proc/net/ip_tables_targets"
printf 'PPE\n' > "$proc/net/ip6_tables_targets"

cat > "$WORK/bin/fixture" <<'SCRIPT'
#!/usr/bin/env python3
import os
import pathlib
import sys

work = pathlib.Path(os.environ["WORK"])
v = "6" if pathlib.Path(sys.argv[0]).name.startswith("ip6") else "4"
args = sys.argv[1:]
if args == ["--version"]:
    print("iptables v1.4.21")
elif args[:2] == ["-w", "-t"] and args[3:] == ["-S"]:
    print((work / (v + args[2])).read_text(), end="")
elif args == ["--noflush"]:
    table, *ops, commit = sys.stdin.read().splitlines()
    assert commit == "COMMIT", commit
    if os.environ.get("FAIL_RESTORE") == "all":
        sys.exit(23)
    if os.environ.get("FAIL_RESTORE") == "ppe" and any(
        op.startswith("-I ") and "--comment r2o-ppe" in op for op in ops
    ):
        sys.exit(23)
    if os.environ.get("FAIL_RESTORE") == "addrtype" and any(
        op.startswith("-A ") and "-m addrtype " in op for op in ops
    ):
        sys.exit("unknown match addrtype")
    state = work / (v + table.removeprefix("*"))
    rules = state.read_text().splitlines()
    for op in ops:
        cmd, chain, *rest = op.split(maxsplit=2)
        prefix = f"-A {chain} "
        if cmd == "-D":
            rules.remove(prefix + rest[0])
        elif cmd == "-F":
            rules = [r for r in rules if not r.startswith(prefix)]
        elif cmd == "-X":
            rules.remove(f"-N {chain}")
        elif cmd == "-N":
            rules.append(op)
        elif cmd == "-A":
            rules.append(op)
        elif cmd == "-I":
            index, spec = rest[0].split(maxsplit=1)
            indices = [i for i, r in enumerate(rules) if r.startswith(prefix)]
            position = int(index) - 1
            assert 0 <= position <= len(indices), op
            offset = indices[position] if position < len(indices) else (
                indices[-1] + 1 if indices else len(rules)
            )
            rules.insert(offset, prefix + spec)
        else:
            raise AssertionError(op)
    state.write_text("".join(f"{r}\n" for r in rules))
else:
    sys.exit(2)
SCRIPT
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/modprobe"
chmod +x "$WORK/bin/fixture" "$WORK/bin/modprobe"
for name in iptables ip6tables iptables-restore ip6tables-restore; do
    ln -s fixture "$WORK/bin/$name"
done
cat > "$WORK/foreign" <<'RULES'
-P FORWARD ACCEPT
-A PREROUTING -p tcp -m comment --comment "other-ppe" -j PPE
-A FORWARD -p udp -m comment --comment "d2k-ppe" -j PPE
RULES
cp "$WORK/foreign" "$WORK/4mangle"
cp "$WORK/foreign" "$WORK/6mangle"
: > "$WORK/4nat"

platform() { "$R2O_DATAPATH_BIN" --platform "$@"; }
ppe() { grep -- '--comment r2o-ppe' "$WORK/${1}mangle"; }
expect_status() {
    pattern=$1
    shift
    "$HELPER" status "$@" > "$WORK/status"
    grep -q "$pattern" "$WORK/status"
}
compare_d2k() {
    [ -n "${R2O_PPE_D2K_ROOT:-}" ] || return 0
    test "$(git -C "$R2O_PPE_D2K_ROOT" rev-parse HEAD)" = 8c6bcdc28b3aedeca8618ff645215bfd6408047c
    (
        export D2K_PPE_TAG=r2o-ppe D2K_PPE_TCP_PORTS="${R2O_PPE_TCP_PORTS:-$PORTS}"
        export D2K_PPE_UDP_PORTS="${R2O_PPE_UDP_PORTS:-0:65535}"
        export D2K_PPE_HTTP_PORTS="${R2O_PPE_HTTP_PORTS:-$HTTP_KEEPALIVE_PORTS}"
        sed -n '/^_d2k_ppe_rules() {/,/^}/p' "$R2O_PPE_D2K_ROOT/files/d2k-ppe-deoffload.sh" >"$WORK/donor.sh"
        export D2K_PPE_CONNSKIP=30 D2K_PPE_HTTP_CONNSKIP=1000000 D2K_PPE_TARGET=PPE
        # shellcheck disable=SC1091
        . "$WORK/donor.sh"
        _d2k_ppe_rules | sed 's/^/-A /; s/|/ /' | sort > "$WORK/expected"
    )
    for family in 4 6; do
        ppe "$family" | sort | diff -u "$WORK/expected" -
    done
}

expect_status 'target=present.*ipv4_rules=missing(0/8).*lan_coverage=unverified'
if FAIL_RESTORE=all platform up; then exit 1; fi
test "$(cat "$fastnat")" = 1
test ! -e "$journal"
FAIL_RESTORE=addrtype platform up
test "$(cat "$fastnat")" = 0
test "$(cat "$journal")" = 1
grep -q '255\.255\.255\.255 -j RETURN' "$WORK/4mangle"
compare_d2k
expect_status 'ipv4_rules=installed(8/8).*ipv6_rules=installed(8/8) FastNAT=0'
platform flowoffload-restore
test "$(cat "$fastnat")" = 0

# Пропажа одного правила при том же количестве, затем пересборка NDM.
awk '/^-A FORWARD -p udp .*--sports .*r2o-ppe/ { sub("--sports", "--dports") } { print }' \
    "$WORK/4mangle" > "$WORK/missing"
mv "$WORK/missing" "$WORK/4mangle"
expect_status 'ipv4_rules=partial(7/8)'
cp "$WORK/foreign" "$WORK/4mangle"
printf '1\n' > "$fastnat"
FAIL_RESTORE=ppe "$HELPER" ensure
test "$(cat "$fastnat")" = 0
test "$(cat "$journal")" = 1
test -s "$R2O_RUN_DIR/platform.offload-error"
grep -q -- '^-A FORWARD -j R2O_IN$' "$WORK/4mangle"
"$HELPER" ensure
expect_status 'ipv4_rules=installed(8/8)'
test ! -e "$R2O_RUN_DIR/platform.offload-error"

rm "$fastnat"
"$HELPER" ensure
test -s "$R2O_RUN_DIR/platform.fastnat-error"
test "$(cat "$journal")" = 1
printf '1\n' > "$fastnat"
"$HELPER" ensure
test "$(cat "$fastnat")" = 0
test ! -e "$R2O_RUN_DIR/platform.fastnat-error"

printf '%s\n' 'PPE0:' 'IPv4_NAPT=802: 11.2.3.45:443 -> 192.0.2.10:40000' > "$proc/driver/hw_nat/foe/binds"
expect_status '^ppe_bind_address=1\.2\.3\.4 present=false$' 1.2.3.4
expect_status '^ppe_bind_address=192\.0\.2\.10 present=true$' 192.0.2.10
python3 - "$HELPER" <<'PY'
import os
import subprocess
import sys

reader, writer = os.pipe()
os.close(reader)
try:
    subprocess.run([sys.argv[1], "status"], stdout=writer, check=True)
finally:
    os.close(writer)
PY
if FAIL_RESTORE=all "$HELPER" remove; then exit 1; fi
ppe 4 >/dev/null
"$HELPER" remove
for family in 4 6; do
    if ppe "$family"; then exit 1; fi
    grep -q 'other-ppe' "$WORK/${family}mangle"
    grep -q 'd2k-ppe' "$WORK/${family}mangle"
done
"$HELPER" remove
rm "$fastnat"
if platform down; then exit 1; fi
test "$(cat "$journal")" = 1
printf '0\n' > "$fastnat"
platform down
test "$(cat "$fastnat")" = 1
test ! -e "$journal"
cmp "$WORK/foreign" "$WORK/4mangle"
cmp "$WORK/foreign" "$WORK/6mangle"

# Поддержка семейств независима. Отключение PPE не снимает защиту FastNAT.
rm "$proc/net/ip6_tables_targets"
platform up
expect_status 'ipv4_rules=installed(8/8).*ipv6_rules=unavailable'
platform down
R2O_PPE_DEOFFLOAD=0 platform up
test "$(cat "$fastnat")" = 0
if ppe 4 || ppe 6; then exit 1; fi
platform down
printf 'PPE\n' > "$proc/net/ip6_tables_targets"
export PORTS=443,8443 R2O_PPE_UDP_PORTS=1:65535 R2O_PPE_HTTP_PORTS=8080
printf '0\n' > "$fastnat"
platform up
compare_d2k
test "$(cat "$journal")" = 0
platform down
test "$(cat "$fastnat")" = 0
test ! -e "$journal"

printf '%s\n' 'Keenetic: PPE IPv4/IPv6, исключение чужих правил, FastNAT, восстановление после NDM и откат'
