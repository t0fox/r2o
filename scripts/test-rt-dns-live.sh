#!/bin/sh
# Настоящие UCI/dnsmasq и DNS-пакеты. NDM проверяется отдельно как контракт CLI,
# потому что этот тест не располагает работающим закрытым NDM-демоном Keenetic.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export RT_DNS_HELPER=$ROOT/router/r2o-rt-dns.sh
: "${R2O_TEST_DNSMASQ_BIN:?укажите настоящий dnsmasq}"
: "${R2O_TEST_UCI_BIN:?укажите настоящий uci}"
: "${R2O_TEST_NC_BIN:?укажите настоящий nc, допустим BusyBox под QEMU}"
export R2O_TEST_DNSMASQ_BIN R2O_TEST_UCI_BIN R2O_TEST_NC_BIN
python3 - <<'PY'
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

helper = os.environ['RT_DNS_HELPER']
dnsmasq = os.environ['R2O_TEST_DNSMASQ_BIN']
uci = os.environ['R2O_TEST_UCI_BIN']
nc = os.environ['R2O_TEST_NC_BIN']
processes = []

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def dns_query(port, host, qtype, udp=False):
    question = b''.join(bytes([len(x)]) + x.encode() for x in host.split('.')) + b'\0'
    wire = struct.pack('!6H', 0x5232, 0x100, 1, 0, 0, 0) + question + struct.pack('!2H', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        if udp:
            s.send(wire)
            response = s.recv(4096)
        else:
            s.sendall(struct.pack('!H', len(wire)) + wire)
            prefix = s.recv(2)
            assert len(prefix) == 2, prefix
            size = struct.unpack('!H', prefix)[0]
            response = b''
            while len(response) < size:
                block = s.recv(size - len(response))
                assert block
                response += block
    header = struct.unpack('!6H', response[:12])
    assert header[0] == 0x5232 and header[1] & 0x8000
    return header[1] & 15, header[3], response

def run(env, action, expected=0):
    started = time.monotonic()
    result = subprocess.run(['sh', helper, action], env=env, text=True, capture_output=True, timeout=35)
    print(f'TIMING: {env["R2O_PLATFORM"]} {action} {time.monotonic()-started:.3f}s rc={result.returncode}', flush=True)
    if (result.returncode == 0) != (expected == 0):
        raise AssertionError(f'{action}: rc={result.returncode}\n{result.stdout}{result.stderr}')
    return result

def write_exec(path, content):
    if content.startswith('#!/usr/bin/env python3\n'):
        content = '#!' + sys.executable + '\n' + content.split('\n', 1)[1]
    path.write_text(content)
    path.chmod(0o755)

def real_uci(env, *args):
    return subprocess.check_output([env['R2O_RT_DNS_UCI_BIN'], '-c', env['R2O_RT_DNS_UCI_CONFIG_DIR'], *args], env=env, text=True)

with tempfile.TemporaryDirectory(prefix='r2o-rt-dns-') as tmp:
    root = Path(tmp)
    config = root / 'config'
    config.mkdir()
    savedir = root / 'uci-delta'
    savedir.mkdir()
    uci_wrapper = root / 'uci'
    write_exec(uci_wrapper, '#!/bin/sh\nexec ' + shlex.quote(uci) + ' -t ' + shlex.quote(str(savedir)) + ' "$@"\n')
    port = free_port()
    env = os.environ.copy()
    env.update({
        'R2O_DIR': str(root / 'r2o'),
        'R2O_PLATFORM': 'openwrt',
        'R2O_RT_DOMAINS': 'rutracker.org api.rutracker.cc',
        'R2O_RT_DNSMASQ_BIN': dnsmasq,
        'R2O_RT_DNS_UCI_BIN': str(uci_wrapper),
        'R2O_RT_DNS_NC_BIN': nc,
        'R2O_RT_DNS_UCI_CONFIG_DIR': str(config),
        'R2O_RT_DNS_QUERY_PORT': str(port),
        'RT_TEST_PORT': str(port),
        'RT_TEST_ROOT': str(root),
    })
    (config / 'dhcp').write_text("""config dnsmasq 'main'
 option filter_aaaa '0'
 list address '/keep.example/198.51.100.80'
 list server '/keep.example/'
 list address '/api.rutracker.cc/203.0.113.171'
 list server '/api.rutracker.cc/'
config domain 'keepipv6'
 option name 'ipv6.example'
 option ip '2001:db8::77'
""")
    # Адаптер сервиса транслирует настоящие UCI-значения в параметры настоящего
    # dnsmasq. Он не подделывает ответы DNS и не считается OpenWrt procd/ubus.
    service = root / 'dnsmasq-service'
    write_exec(service, '''#!/usr/bin/env python3
import os, pathlib, shlex, signal, subprocess, sys, time
r=pathlib.Path(os.environ['RT_TEST_ROOT']); pidfile=r/'service.pid'
if pidfile.exists():
    try: os.kill(int(pidfile.read_text()), signal.SIGTERM)
    except ProcessLookupError: pass
    time.sleep(.1)
    pidfile.unlink(missing_ok=True)
text=subprocess.check_output([os.environ['R2O_RT_DNS_UCI_BIN'],'-c',os.environ['R2O_RT_DNS_UCI_CONFIG_DIR'],'export','dhcp'],text=True)
args=[os.environ['R2O_RT_DNSMASQ_BIN'],'--keep-in-foreground','--no-hosts','--no-resolv','--bind-interfaces','--listen-address=127.0.0.1','--port='+os.environ['RT_TEST_PORT'],'--pid-file='+str(pidfile),'--log-facility='+str(r/'service.log'),'--dns-rr=ipv6.example,65,00:01:00']
kind=None; fields={}
def finish():
    if kind in ('domain','hostrecord') and 'name' in fields and 'ip' in fields:
        args.append('--host-record='+fields['name']+','+fields['ip'])
for line in text.splitlines():
    words=shlex.split(line)
    if not words: continue
    if words[0]=='config':
        finish(); kind=words[1]; fields={}
    elif words[0] in ('option','list'):
        fields[words[1]]=words[2]
        if kind=='dnsmasq' and words[1] in ('address','server'):
            args.append('--'+words[1]+'='+words[2])
        if kind=='dnsmasq' and words[1]=='filter_aaaa' and words[2]=='1': args.append('--filter-AAAA')
finish()
log=(r/'service-stderr.log').open('ab')
p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
pidfile.write_text(str(p.pid))
time.sleep(.15)
if p.poll() is not None: sys.exit(1)
with (r/'reloads').open('a') as out: out.write('reload\\n')
''')
    env['R2O_RT_DNS_INIT'] = str(service)
    try:
        subprocess.check_call([str(service), 'reload'], env=env)
        assert dns_query(port, 'ipv6.example', 28)[:2] == (0, 1)
        assert dns_query(port, 'ipv6.example', 65)[:2] == (0, 1)
        run(env, 'apply')
        for host in ('rutracker.org', 'api.rutracker.cc', 'www.rutracker.org'):
            for udp in (False, True):
                assert dns_query(port, host, 1, udp)[:2] == (0, 1)
                for qtype in (28, 64, 65):
                    assert dns_query(port, host, qtype, udp)[:2] == (0, 0)
        assert dns_query(port, 'ipv6.example', 28)[:2] == (0, 1)
        assert dns_query(port, 'ipv6.example', 65)[:2] == (0, 1)
        assert real_uci(env, 'get', 'dhcp.main.filter_aaaa').strip() == '0'
        original = (config / 'dhcp').read_bytes()
        reloads = (root / 'reloads').read_bytes()
        run(env, 'apply')
        run(env, 'status')
        assert (config / 'dhcp').read_bytes() == original
        assert (root / 'reloads').read_bytes() == reloads
        real_uci(env, 'set', 'dhcp.main.user_pending=keep_unsaved')
        pending = real_uci(env, 'changes', 'dhcp')
        run(env, 'clear', expected=1)
        assert real_uci(env, 'changes', 'dhcp') == pending
        assert (config / 'dhcp').read_bytes() == original
        assert (root / 'r2o/state/rt-dns/owned.tsv').exists()
        real_uci(env, 'revert', 'dhcp.main.user_pending')
        run(env, 'status')
        run(env, 'clear')
        assert '/rutracker.org/' not in real_uci(env, 'get', 'dhcp.main.server').split()
        assert '/api.rutracker.cc/' in real_uci(env, 'get', 'dhcp.main.server').split()
        assert '/keep.example/' in real_uci(env, 'get', 'dhcp.main.server').split()
        assert dns_query(port, 'ipv6.example', 28)[:2] == (0, 1)
        run(env, 'clear')
        print('PASS: real UCI + dnsmasq; A sentinel, selective AAAA/SVCB/HTTPS NODATA over TCP/UDP, unrelated IPv6/HTTPS, idempotence, borrowed entries and pending user changes retained')

        # Реальный DNS-сервер отсутствует на указанном порту: применение обязано
        # провалиться и откатить свои записи, сохранив весь пользовательский UCI.
        baseline = real_uci(env, 'export', 'dhcp')
        broken = env | {'R2O_RT_DNS_QUERY_PORT': str(free_port())}
        run(broken, 'apply', expected=1)
        assert real_uci(env, 'export', 'dhcp') == baseline
        assert (root / 'r2o/state/rt-dns/owned.tsv').exists()
        run(env, 'clear')
        assert not (root / 'r2o/state/rt-dns/owned.tsv').exists()
        print('PASS: failed live DNS verification rolls back owned UCI values; journal retained until verified clear')

        run(env, 'apply')
        real_uci(env, 'del_list', 'dhcp.main.address=/rutracker.org/203.0.113.171')
        real_uci(env, 'add_list', 'dhcp.main.address=/rutracker.org/198.51.100.9')
        real_uci(env, 'commit', 'dhcp')
        run(env, 'clear')
        assert '/rutracker.org/198.51.100.9' in real_uci(env, 'get', 'dhcp.main.address').split()
        before = real_uci(env, 'export', 'dhcp')
        run(env, 'apply', expected=1)
        assert real_uci(env, 'export', 'dhcp') == before
        print('PASS: edited user values survive clear; conflicting user DNS is not overwritten')

        # Реальный UCI после старого S99: точные root/www-секции и сохранённое
        # значение filter_aaaa; изменённая владельцем старая секция сохраняется.
        real_uci(env, 'del_list', 'dhcp.main.address=/rutracker.org/198.51.100.9')
        for host in ('rutracker.org', 'www.rutracker.org'):
            section = 'r2o_rt_' + host.replace('.', '_')
            real_uci(env, 'set', f'dhcp.{section}=hostrecord')
            real_uci(env, 'set', f'dhcp.{section}.name={host}')
            real_uci(env, 'set', f'dhcp.{section}.ip=172.67.182.196')
            real_uci(env, 'add_list', f'dhcp.main.server=/{host}/')
        real_uci(env, 'set', 'dhcp.r2o_rt_static_rutracker_cc=hostrecord')
        real_uci(env, 'set', 'dhcp.r2o_rt_static_rutracker_cc.name=static.rutracker.cc')
        real_uci(env, 'set', 'dhcp.r2o_rt_static_rutracker_cc.ip=198.51.100.12')
        real_uci(env, 'add_list', 'dhcp.main.server=/static.rutracker.cc/')
        real_uci(env, 'set', 'dhcp.main.filter_aaaa=1')
        real_uci(env, 'commit', 'dhcp')
        legacy_backup = root/'r2o/run/r2o-rt-filter-aaaa.prev'
        legacy_backup.write_text('0\n')
        run(env, 'clear')
        exported = real_uci(env, 'export', 'dhcp')
        assert 'r2o_rt_rutracker_org' not in exported and 'r2o_rt_www_rutracker_org' not in exported
        assert 'r2o_rt_static_rutracker_cc' in exported
        assert real_uci(env, 'get', 'dhcp.r2o_rt_static_rutracker_cc.ip').strip() == '198.51.100.12'
        assert '/static.rutracker.cc/' in real_uci(env, 'get', 'dhcp.main.server').split()
        assert real_uci(env, 'get', 'dhcp.main.filter_aaaa').strip() == '0'
        assert not legacy_backup.exists()
        assert dns_query(port, 'ipv6.example', 28)[:2] == (0, 1)
        run(env, 'apply')
        for host in ('rutracker.org', 'www.rutracker.org'):
            assert dns_query(port, host, 1)[:2] == (0, 1)
            for qtype in (28, 64, 65): assert dns_query(port, host, qtype)[:2] == (0, 0)
        run(env, 'clear')
        legacy_backup.write_text('1\n')
        run(env, 'clear')
        assert real_uci(env, 'get', 'dhcp.main.filter_aaaa').strip() == '0'
        print('PASS: legacy root/www direct pins migrated; prior global AAAA restored; changed legacy/user values retained')

        # Отрицательные wire-тесты: намеренно неверный DNS-ответ передаётся по
        # настоящему TCP; это проверка парсера, а не имитация успешного NDM/DNS.
        functions = Path(helper).read_text().split('case "${1:-}" in apply|status|clear)')[0]
        for bad_kind in ('wrong-qname', 'truncated', 'compression-loop'):
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)
            bad_port = listener.getsockname()[1]
            qtype = 28 if bad_kind == 'truncated' else 1
            delivered = []
            def respond_bad():
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        prefix = conn.recv(2)
                        size = struct.unpack('!H', prefix)[0]
                        request = b''
                        while len(request) < size: request += conn.recv(size-len(request))
                        question = bytearray(request[12:])
                        if bad_kind == 'wrong-qname': question[1] = ord('z')
                        flags = 0x8380 if bad_kind == 'truncated' else 0x8180
                        answer = b''
                        if qtype == 1:
                            pointer = (0xC000 | len(request)) if bad_kind == 'compression-loop' else 0xC00C
                            answer = struct.pack('!HHHIH', pointer, 1, 1, 0, 4) + socket.inet_aton('203.0.113.171')
                        response = struct.pack('!6H', 0x5232, flags, 1, bool(answer), 0, 0) + question + answer
                        conn.sendall(struct.pack('!H', len(response)) + response)
                        delivered.append(True)
            worker = threading.Thread(target=respond_bad)
            worker.start()
            work = root/('bad-' + bad_kind)
            work.mkdir()
            probe_script = functions + '\nWORK=' + shlex.quote(str(work)) + '\nselect_clock\n'
            probe_script += f'dns_probe 127.0.0.1 {bad_port} rutracker.org {qtype}\n'
            checked = subprocess.run(['sh'], input=probe_script, env=env, text=True, capture_output=True, timeout=10)
            worker.join(timeout=5)
            assert delivered == [True], bad_kind
            assert checked.returncode != 0, bad_kind
        print('PASS: mismatched QNAME, truncated NODATA and compression loops are rejected')

        # Ниже только контракт документированного NDM CLI. Сервер DNS остаётся
        # настоящим dnsmasq, но маршрутизация закрытым NDM здесь не доказана.
        ndm_file = root / 'ndm-config'
        ndm_file.write_text('hostname keenetic-contract-test\nip host keep.example 192.0.2.7\nip host api.rutracker.cc 203.0.113.171\n')
        ndm = root / 'ndmc-contract-fixture'
        write_exec(ndm, '''#!/usr/bin/env python3
import os, pathlib, sys, time
p=pathlib.Path(os.environ['RT_TEST_ROOT'])/'ndm-config'
cmd=sys.argv[2]
if os.environ.get('RT_NDM_HANG')=='1': time.sleep(30)
if os.environ.get('RT_NDM_EMPTY')=='1': sys.exit(0)
if cmd=='show running-config': print(p.read_text(),end=''); sys.exit(0)
if cmd=='system configuration save': sys.exit(0)
rows=p.read_text().splitlines()
if cmd.startswith('no '):
    rows=[line for line in rows if line!=cmd[3:]]
elif cmd.startswith(('ip host ','ip name-server ')):
    if cmd not in rows: rows.append(cmd)
else: sys.exit(2)
p.write_text('\\n'.join(rows)+'\\n')
''')
        ndm_port = free_port()
        ndm_env = env | {
            'R2O_DIR': str(root / 'keenetic'), 'R2O_PLATFORM': 'keenetic',
            'R2O_RT_DNS_NDMC_BIN': str(ndm), 'R2O_RT_DNS_PORT': str(ndm_port),
            'R2O_RT_DNS_QUERY_PORT': str(ndm_port),
        }
        baseline = ndm_file.read_text()
        run(ndm_env, 'apply')
        run(ndm_env, 'apply')
        run(ndm_env, 'status')
        assert dns_query(ndm_port, 'rutracker.org', 1)[:2] == (0, 1)
        for qtype in (28, 64, 65): assert dns_query(ndm_port, 'rutracker.org', qtype)[:2] == (0, 0)
        run(ndm_env, 'clear')
        assert ndm_file.read_text() == baseline
        print('PASS: NDM CLI contract, exact ownership/readback/cleanup; real dedicated dnsmasq answers; NOT a hardware NDM proof')
        run(ndm_env | {'RT_NDM_EMPTY': '1'}, 'apply', expected=1)
        assert ndm_file.read_text() == baseline
        run(ndm_env, 'apply')
        # Настоящий процесс helper держит lock, пока отрицательная NDM-команда
        # зависла. Конкурирующие операции не должны менять DNS или чужой lock.
        started = time.monotonic()
        lock = root/'keenetic/run/rt-dns.lock/pid'
        owned = root/'keenetic/state/rt-dns/owned.tsv'
        expected_owned = owned.read_bytes()
        expected_ndm = ndm_file.read_bytes()
        checking = subprocess.Popen(['sh', helper, 'status'], env=ndm_env | {'RT_NDM_HANG': '1'},
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                assert checking.poll() is None
                if lock.exists() and lock.read_text().strip() == str(checking.pid):
                    break
                time.sleep(.01)
            assert lock.read_text().strip() == str(checking.pid)
            for action in ('apply', 'status', 'clear'):
                rejected = run(ndm_env, action, expected=1)
                assert 'DNS занят другой операцией' in rejected.stderr
                assert lock.read_text().strip() == str(checking.pid)
            assert owned.read_bytes() == expected_owned and ndm_file.read_bytes() == expected_ndm
            stdout, stderr = checking.communicate(timeout=12)
            elapsed = time.monotonic() - started
            print(f'TIMING: keenetic hung-status {elapsed:.3f}s rc={checking.returncode}', flush=True)
            assert checking.returncode != 0, stdout + stderr
            assert 4.8 <= elapsed < 8, elapsed
            assert not lock.exists()
        finally:
            if checking.poll() is None:
                checking.kill()
                checking.communicate(timeout=2)
        run(ndm_env, 'clear')
        print('PASS: empty NDM result rejected; live helper lock rejects concurrent apply/status/clear; hung NDM call has a monotonic deadline; no hardware NDM success claim')
    finally:
        # Завершаются только PID наших настоящих DNS-процессов.
        for pidfile in (root/'service.pid', root/'keenetic/run/rt-dns.pid'):
            if pidfile.exists():
                try: os.kill(int(pidfile.read_text()), signal.SIGTERM)
                except ProcessLookupError: pass
PY
