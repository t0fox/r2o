#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 - "$ROOT/router/r2o-remove-legacy-rt.sh" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

helper = Path(sys.argv[1])
legacy_ip = "203.0.113.171"
owned_host = f"ip host rutracker.org {legacy_ip}"
owned_server = "ip name-server 127.0.0.1:5354 rutracker.org"
foreign = ["ip host rutracker.org 192.0.2.2", "ip name-server 127.0.0.1:53 archive.example"]
legacy_rules = f"""table ip r2o_rt {{
    chain prerouting {{
        type nat hook prerouting priority dstnat - 1; policy accept;
        ip daddr {legacy_ip} tcp dport 443 redirect to :1445
        return comment "r2o-rt-managed"
    }}
    chain output {{
        type nat hook output priority dstnat - 1; policy accept;
        meta mark 0x0000002d return
        ip daddr {legacy_ip} tcp dport 443 redirect to :1445
        return comment "r2o-rt-managed"
    }}
}}
"""
iptables_rules = """-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
-N R2O_RT_PRE
-N R2O_RT_OUT
-A PREROUTING -m comment --comment r2o-rt-hook -j R2O_RT_PRE
-A OUTPUT -m comment --comment r2o-rt-hook -j R2O_RT_OUT
-A R2O_RT_PRE -d 203.0.113.171/32 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 1445
-A R2O_RT_PRE -m comment --comment r2o-rt-managed -j RETURN
-A R2O_RT_OUT -m mark --mark 0x2d -j RETURN
-A R2O_RT_OUT -d 203.0.113.171/32 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 1445
-A R2O_RT_OUT -m comment --comment r2o-rt-managed -j RETURN
"""
mock = r"""
import json, os, sys
from pathlib import Path

root = Path(os.environ["TEST_ROUTER"])
args = sys.argv[1:]
kind = Path(sys.argv[0]).name

if kind == "ndmc":
    assert args[0] == "-c"
    command = args[1]
    config = root / "ndm"
    rows = config.read_text().splitlines()
    if command == "show running-config":
        print("system hostname test")
        print("\\n".join(rows))
    elif command == "system configuration save":
        if (root / "fail-save").exists():
            print("Core::Configurator error: flash write failed")
        else:
            (root / "saved").write_text(config.read_text())
    elif command.startswith("no "):
        rows.remove(command[3:])
        config.write_text("\\n".join(rows) + "\\n")
    else:
        sys.exit(2)
elif kind == "uci":
    assert args[:2] == ["-c", "/etc/config"]
    args = [arg for arg in args[2:] if not arg.startswith("-")]
    data = root / "uci-data"
    values = json.loads(data.read_text())
    match args:
        case ["show", "dhcp"]:
            print("dhcp.test=dnsmasq")
        case ["get", key]:
            print(" ".join(values[key]))
        case ["changes", "dhcp"]:
            if (root / "pending").exists():
                print("dhcp.test.local='/owner/'")
        case ["del_list", assignment]:
            key, value = assignment.split("=", 1)
            values[key].remove(value)
            data.write_text(json.dumps(values))
        case ["commit", "dhcp"]:
            (root / "committed").touch()
        case _:
            sys.exit(2)
elif kind == "dnsmasq-init":
    assert args == ["reload"]
    if (root / "fail-reload").exists():
        print("dnsmasq reload failed", file=sys.stderr)
        sys.exit(1)
    (root / "reloaded").touch()
elif kind == "nft":
    table = root / "nft-data"
    match args:
        case ["list", "tables"]:
            print("table inet fw4")
            if table.exists():
                print("table ip r2o_rt")
        case ["-n", "list", "table", "ip", "r2o_rt"]:
            print(table.read_text())
        case ["-f", script]:
            assert Path(script).read_text() == "delete table ip r2o_rt\\n"
            table.unlink()
        case _:
            sys.exit(2)
elif kind == "iptables":
    assert args == ["-t", "nat", "-S"]
    table = root / "iptables-data"
    print(table.read_text() if table.exists() else "-P PREROUTING ACCEPT")
elif kind == "iptables-restore":
    assert args == ["--noflush"]
    script = sys.stdin.read()
    assert "-D PREROUTING -m comment --comment r2o-rt-hook -j R2O_RT_PRE\\n" in script
    assert "-F R2O_RT_OUT\\n-X R2O_RT_OUT\\n" in script
    (root / "iptables-data").unlink()
else:
    sys.exit(2)
""".replace("\\\\n", "\\n")

with tempfile.TemporaryDirectory(prefix="r2o-legacy-rt-test.") as tmp:
    lab = Path(tmp)
    tools = lab / "bin"
    tools.mkdir()
    for name in ("ndmc", "uci", "dnsmasq-init", "nft", "iptables", "iptables-restore"):
        (tools / name).write_text(f"#!{sys.executable}\n" + mock)
        (tools / name).chmod(0o755)
    source = lab / "proc.c"
    source.write_text("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
    proc = lab / "proc"
    subprocess.run([os.environ.get("CC", "cc"), str(source), "-o", str(proc)], check=True)

    def create(name):
        router = lab / name
        router.mkdir()
        root = router / "r2o"
        journal = root / "state/rt-dns"
        runtime = router / "runtime"
        journal.mkdir(parents=True)
        (root / "run").mkdir()
        runtime.mkdir()
        env = os.environ | {
            "PATH": f"{tools}:{os.environ['PATH']}",
            "R2O_DIR": str(root),
            "R2O_RUNTIME_DIR": str(runtime),
            "R2O_RT_DNS_INIT": str(tools / "dnsmasq-init"),
            "TEST_ROUTER": str(router),
        }
        return router, root, journal, env

    def run(env, error=None, command=None):
        result = subprocess.run(
            command or ["sh", helper], env=env, capture_output=True, text=True, timeout=25
        )
        if error:
            assert result.returncode and error in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stderr

    router, root, journal, env = create("чистая")
    journal.rmdir()
    run(env)
    assert not (journal / "owned.tsv").exists()
    assert not (router / "reloaded").exists()

    router, root, journal, env = create("keenetic")
    (journal / "owned.tsv").write_text(
        f"ndm-host\trutracker.org\t{legacy_ip}\nndm-server\trutracker.org\t127.0.0.1:5354\n"
    )
    (router / "ndm").write_text("\n".join([owned_host, owned_server, *foreign]) + "\n")
    (router / "iptables-data").write_text(iptables_rules)
    (router / "fail-save").touch()
    (root / "config").write_text("TG_ENABLED=1\nR2O_RT_PROXY=1\nR2O_RT_CUSTOM=owner\n")
    (journal / "dnsmasq.conf").touch()
    bundle = router / "bundle"
    (bundle / "router").mkdir(parents=True)
    (bundle / "builds").mkdir()
    init = router / "init"
    ndm_hooks = router / "ndm-hooks"
    ndm_hooks.mkdir()
    env.update(R2O_INIT_DIR=str(init), R2O_NDM_DIR=str(ndm_hooks), R2O_PLATFORM="keenetic")
    for adapter in ("001-r2o.sh", "config.default", "r2o-firewall-fw3-include.sh",
                    "r2o-ppe-deoffload.sh", "select-panel-ip.sh", helper.name):
        shutil.copy2(helper.parent / adapter, bundle / "router" / adapter)
    shim = bundle / "router/S99r2o.shim"
    shim.write_text("#!/bin/sh\nexit 0\n")
    manager = bundle / "builds/r2o-manager-linux-mipsel"
    manager.write_text("""#!/bin/sh
set -eu
case "$1" in
    install-local) printf 'R2O-RELEASE-SLOTS-1\\nr2o-next\\n-\\n' >"$R2O_DIR/release-slots" ;;
    config-init) printf '{"created":false,"state_dir":"%s/state","donor_state_dir":null}\\n' "$R2O_DIR" ;;
    *) exit 2 ;;
esac
""")
    for executable in (shim, manager, bundle / "router" / helper.name):
        executable.chmod(0o755)
    install = ["sh", helper.parent / "install.sh", bundle, "r2o-next", "mipsel"]
    binary = root / "releases/old/builds/r2o-telegram-linux-mipsel"
    binary.parent.mkdir(parents=True)
    shutil.copy2(proc, binary)
    processes = [
        subprocess.Popen([binary, "--rt-proxy", "--listen=:1445"]),
        subprocess.Popen([binary, "--listen=:1445"]),
        subprocess.Popen([proc, f"--conf-file={journal}/dnsmasq.conf"]),
        subprocess.Popen([proc, "--conf-file=/tmp/owner-dnsmasq.conf"]),
    ]
    try:
        rt, telegram, dns, owner = processes
        (root / "run/r2o-rt-proxy.pid").write_text(str(telegram.pid))
        run(env, "flash write failed", install)
        assert not (root / "release-slots").exists() and not any(ndm_hooks.iterdir())
        assert rt.poll() is None and dns.poll() is None
        assert (journal / "owned.tsv").exists() and (router / "iptables-data").exists()
        (router / "fail-save").unlink()
        run(env, command=install)
        assert (root / "release-slots").read_text().splitlines()[1] == "r2o-next"
        assert (ndm_hooks / "001-r2o.sh").read_bytes() == (helper.parent / "001-r2o.sh").read_bytes()
        rt.wait(5)
        dns.wait(5)
        assert telegram.poll() is None and owner.poll() is None
        assert (router / "saved").read_text().splitlines() == foreign
        assert not journal.exists() and not (router / "iptables-data").exists()
        assert (root / "config").read_text() == "TG_ENABLED=1\nR2O_RT_CUSTOM=owner\n"
        run(env)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(5)

    router, root, journal, env = create("openwrt")
    env["R2O_PLATFORM"] = "openwrt"
    (journal / "backend").write_text("openwrt\n")
    address, server = "dhcp.test.address", "dhcp.test.server"
    owned_address = f"/rutracker.org/{legacy_ip}"
    owned_upstream = "/rutracker.org/"
    (journal / "owned.tsv").write_text(f"uci\t{address}\t{owned_address}\nuci\t{server}\t{owned_upstream}\n")
    kept = {address: ["/rutracker.org/192.0.2.2"], server: ["/example.org/192.0.2.53"]}
    (router / "uci-data").write_text(json.dumps({
        address: kept[address] + [owned_address], server: kept[server] + [owned_upstream],
    }))
    (router / "nft-data").write_text(legacy_rules)
    (router / "pending").touch()
    run(env, "чужие несохранённые изменения")
    assert not (router / "committed").exists()
    (router / "pending").unlink()
    (router / "fail-reload").touch()
    run(env, "dnsmasq reload failed")
    assert (journal / "owned.tsv").exists() and (router / "nft-data").exists()
    (router / "fail-reload").unlink()
    changed_rules = legacy_rules.replace('return comment "r2o-rt-managed"', 'counter\n        return comment "r2o-rt-managed"', 1)
    (router / "nft-data").write_text(changed_rules)
    run(env, "несовпадающие правила")
    assert (router / "nft-data").read_text() == changed_rules
    (router / "nft-data").write_text(legacy_rules)
    run(env)
    assert json.loads((router / "uci-data").read_text()) == kept
    assert (router / "reloaded").exists()
    assert not journal.exists() and not (router / "nft-data").exists()
    run(env)

print("PASS: чистый запуск, частичный Keenetic, OpenWrt, повтор, сохранение чужих настроек и Telegram")

PY
