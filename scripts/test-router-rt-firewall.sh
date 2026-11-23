#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/root"

# Модель хранит независимые цепи и применяет restore/nft только целиком.
# Проверяем контракт CLI, сохранность чужих правил и отказы транзакций.
cat > "$TEMP/bin/netfilter-model" <<'PY'
#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import re
import shlex
import sys

path = Path(os.environ['RT_TEST_STATE'])
state = json.loads(path.read_text())
tool = Path(sys.argv[0]).name
args = sys.argv[1:]

def save():
    path.write_text(json.dumps(state, sort_keys=True))

try:
    if tool == 'iptables':
        assert args == ['-t', 'nat', '-S'], args
        for chain in state['chains']:
            print(('-P ' + chain + ' ACCEPT') if chain in ('PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING') else '-N ' + chain)
        for chain, rules in state['chains'].items():
            for rule in rules:
                line = '-A ' + chain + ' ' + ' '.join(rule)
                line = re.sub(r'--mark (\d+)', lambda m: '--mark 0x%x' % int(m[1]), line)
                line = re.sub(r'--comment (\S+)', r'--comment "\1"', line)
                print(line)
    elif tool == 'iptables-restore':
        assert args == ['--noflush'], args
        batch = sys.stdin.read()
        staged = copy.deepcopy(state['chains'])
        committed = False
        for line in batch.splitlines():
            if line == '*nat':
                continue
            if line == 'COMMIT':
                committed = True
                continue
            if line.startswith(':'):
                staged.setdefault(line.split()[0][1:], [])
                continue
            words = shlex.split(line)
            op, chain, *rule = words
            if op == '-F':
                staged[chain] = []
            elif op == '-X':
                assert not staged[chain]
                assert not any('-j' in r and r[r.index('-j')+1] == chain for rules in staged.values() for r in rules)
                del staged[chain]
            elif op == '-D':
                staged[chain].remove(rule)
            elif op == '-I':
                staged[chain].insert(0, rule)
            elif op == '-A':
                staged[chain].append(rule)
            else:
                raise AssertionError(op)
        assert committed
        assert not os.environ.get('RT_TEST_FAIL_RESTORE'), 'отказ COMMIT'
        state['chains'] = staged
        state['ipt_commits'] += 1
        save()
    elif tool == 'nft':
        if args[0] == '-n':
            args.pop(0)
        if args[:2] == ['list', 'table']:
            table = state['tables'][' '.join(args[2:])]
            table = table.replace('priority -101;', 'priority dstnat - 1;')
            table = table.replace('priority -100;', 'priority dstnat;')
            table = re.sub(r'meta mark (\d+)', lambda m: 'meta mark 0x%08x' % int(m[1]), table)
            print(table)
        elif args[0] == '-f':
            staged = copy.deepcopy(state['tables'])
            lines = iter(Path(args[1]).read_text().splitlines())
            for line in lines:
                words = line.split()
                if words[:2] == ['delete', 'table']:
                    del staged[' '.join(words[2:])]
                elif words[0] == 'table':
                    key = ' '.join(words[1:3])
                    assert key not in staged
                    block = [line]
                    depth = line.count('{') - line.count('}')
                    while depth:
                        line = next(lines)
                        block.append(line)
                        depth += line.count('{') - line.count('}')
                    staged[key] = '\n'.join(block) + '\n'
                else:
                    raise AssertionError(line)
            assert not os.environ.get('RT_TEST_FAIL_NFT'), 'отказ nft-транзакции'
            state['tables'] = staged
            state['nft_commits'] += 1
            save()
        else:
            raise AssertionError(args)
    else:
        raise AssertionError(tool)
except (AssertionError, KeyError, ValueError, StopIteration) as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
PY
chmod 0755 "$TEMP/bin/netfilter-model"
for tool in iptables iptables-restore nft; do ln -s netfilter-model "$TEMP/bin/$tool"; done

python3 - "$ROOT/router/r2o-rt-firewall.sh" "$TEMP" <<'PY'
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

adapter, temporary = sys.argv[1], Path(sys.argv[2])
state_file = temporary / 'state.json'
config = temporary / 'root/config'
config.write_text('')
env = dict(os.environ, PATH=str(temporary / 'bin') + ':' + os.environ['PATH'],
           RT_TEST_STATE=str(state_file), R2O_DIR=str(temporary / 'root'), R2O_CONFIG=str(config))
foreign_rule = ['-d', '198.51.100.9/32', '-j', 'RETURN']
foreign_table = 'table inet unrelated { chain keep { } }\n'

def reset():
    state = {'chains': {'PREROUTING': [], 'INPUT': [], 'OUTPUT': [foreign_rule], 'POSTROUTING': []},
             'tables': {'inet unrelated': foreign_table}, 'ipt_commits': 0, 'nft_commits': 0}
    write(state)
    config.write_text('')

def read():
    return json.loads(state_file.read_text())

def write(state):
    state_file.write_text(json.dumps(state, sort_keys=True))

def run(action, backend='iptables', success=True, **overrides):
    settings = dict(env, R2O_FW=backend, **overrides)
    result = subprocess.run(['sh', adapter, action], env=settings, text=True, capture_output=True)
    assert (result.returncode == 0) == success, (action, backend, result.returncode, result.stdout, result.stderr)
    return result

def unchanged(before):
    assert read() == before, 'отказ или readonly-проверка изменили правила'

def foreign_intact():
    state = read()
    assert foreign_rule in state['chains']['OUTPUT']
    assert state['tables']['inet unrelated'] == foreign_table

def redirect(chain, destination='203.0.113.171', port=443, mark=0):
    # Независимая проверка выбора пакетов и порядка RETURN/REDIRECT.
    chains = read()['chains']
    for rule in chains[chain]:
        if '-d' in rule and rule[rule.index('-d')+1] != destination + '/32':
            continue
        if '--dport' in rule and rule[rule.index('--dport')+1] != str(port):
            continue
        if '--mark' in rule and int(rule[rule.index('--mark')+1], 0) != mark:
            continue
        target = rule[rule.index('-j')+1]
        if target == 'RETURN':
            return None
        if target == 'REDIRECT':
            return int(rule[rule.index('--to-ports')+1])
        if target in chains:
            value = redirect(target, destination, port, mark)
            if value is not None:
                return value
    return None

reset()
run('status', success=False)
run('apply', backend='', R2O_PLATFORM='keenetic')
run('status')
assert redirect('PREROUTING') == 1445
assert redirect('OUTPUT') == 1445
assert redirect('OUTPUT', mark=45) is None
assert redirect('PREROUTING', port=80) is None
assert redirect('OUTPUT', destination='203.0.113.172') is None
foreign_intact()
before = read()
run('apply')
run('status')
unchanged(before)

# После reload восстанавливаем пропавшую ссылку; дубликаты не сохраняем.
state = read()
state['chains']['PREROUTING'] *= 2
state['chains']['OUTPUT'] = [foreign_rule]
write(state)
run('status', success=False)
run('apply')
assert len(read()['chains']['PREROUTING']) == 1
assert redirect('OUTPUT') == 1445
foreign_intact()

# Порядок важен: обход метки должен быть до перенаправления.
state = read()
state['chains']['R2O_RT_OUT'][:2] = reversed(state['chains']['R2O_RT_OUT'][:2])
write(state)
run('status', success=False)
run('apply')
assert redirect('OUTPUT', mark=45) is None

# Явные параметры сервиса имеют приоритет над конфигурацией.
config.write_text('R2O_RT_SENTINEL=192.0.2.1\nR2O_RT_PROXY_PORT=9001\nR2O_RT_MARK=99\n')
params = dict(R2O_RT_SENTINEL='203.0.113.175', R2O_RT_PROXY_PORT='1446', R2O_RT_MARK='0')
run('apply', **params)
run('status', **params)
assert redirect('OUTPUT', destination='203.0.113.175') == 1446
assert '--mark' not in str(read()['chains']['R2O_RT_OUT'])
before = read()
run('apply', success=False, RT_TEST_FAIL_RESTORE='1', R2O_RT_PROXY_PORT='1447')
unchanged(before)
run('stop', **params)
foreign_intact()
assert set(read()['chains']) == {'PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'}
before = read()
run('stop')
unchanged(before)

# Неудачная новая транзакция не оставляет ни цепей, ни hooks.
reset()
before = read()
run('apply', success=False, RT_TEST_FAIL_RESTORE='1')
unchanged(before)

# Совпадение имени без marker не даёт права удалить чужую цепь.
state = read()
state['chains']['R2O_RT_PRE'] = [['-j', 'RETURN']]
write(state)
before = read()
run('apply', success=False)
run('stop', success=False)
unchanged(before)

reset()
run('apply')
state = read()
state['chains']['INPUT'].append(['-j', 'R2O_RT_PRE'])
write(state)
before = read()
run('stop', success=False)
unchanged(before)

# fw4 выбирает nft; семейство ip поддерживает IPv4 NAT и до inet NAT.
reset()
run('apply', backend='', R2O_PLATFORM='openwrt')
run('status', 'nft')

# Нельзя удалить посторонний набор, добавленный рядом с помеченными цепями.
state = read()
owned_table = state['tables']['ip r2o_rt']
state['tables']['ip r2o_rt'] = owned_table.replace(
    'table ip r2o_rt {', 'table ip r2o_rt {\n    set foreign { type ipv4_addr; }')
write(state)
before = read()
run('apply', 'nft', success=False)
run('stop', 'nft', success=False)
unchanged(before)
state['tables']['ip r2o_rt'] = owned_table
write(state)
state = read()
assert 'ip r2o_rt' in state['tables']
assert 'inet r2o_rt' not in state['tables']
assert 'meta mark 45 return' in state['tables']['ip r2o_rt']
assert state['ipt_commits'] == 0
before = read()
run('apply', 'nft')
run('status', 'nft')
unchanged(before)
run('apply', 'nft', success=False, RT_TEST_FAIL_NFT='1', R2O_RT_PROXY_PORT='1446')
unchanged(before)
run('stop', 'nft')
foreign_intact()
before = read()
run('stop', 'nft')
unchanged(before)

legacy = '''table inet r2o_rt {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr 203.0.113.171 tcp dport 443 redirect to :1445
    }
    chain output {
        type nat hook output priority dstnat; policy accept;
        ip daddr 203.0.113.171 tcp dport 443 redirect to :1445
    }
}
'''
state = read()
state['tables']['inet r2o_rt'] = legacy
write(state)
before = read()
run('apply', 'nft', success=False, RT_TEST_FAIL_NFT='1')
unchanged(before)
run('apply', 'nft')
assert 'inet r2o_rt' not in read()['tables']
assert 'ip r2o_rt' in read()['tables']
run('status', 'nft')

# stop убирает оба своих backend после смены fw3/fw4.
run('apply', 'iptables')
run('stop', 'nft')
assert 'R2O_RT_OUT' not in read()['chains']
assert 'ip r2o_rt' not in read()['tables']
foreign_intact()

for foreign in (legacy.replace('203.0.113.171', '192.0.2.10'),
                legacy.replace('chain output {', 'chain foreign {'),
                legacy.replace('    chain output {', '    chain extra { }\n    chain output {')):
    reset()
    state = read()
    state['tables']['inet r2o_rt'] = foreign
    write(state)
    before = read()
    run('apply', 'nft', success=False)
    run('stop', 'nft', success=False)
    unchanged(before)

reset()
state = read()
state['tables']['ip r2o_rt'] = 'table ip r2o_rt {\n chain other {\n comment "r2o-rt-managed"\n }\n}\n'
write(state)
before = read()
run('apply', 'nft', success=False)
run('stop', 'nft', success=False)
unchanged(before)

reset()
for bad in ({'R2O_RT_SENTINEL': '1.2.3.4; flush ruleset'},
            {'R2O_RT_SENTINEL': '256.1.2.3'}, {'R2O_RT_PROXY_PORT': '0'},
            {'R2O_RT_PROXY_PORT': '65536'}, {'R2O_RT_MARK': '4294967296'},
            {'R2O_RT_MARK': '0x1;true'}):
    before = read()
    run('apply', success=False, **bad)
    unchanged(before)

print('RuTracker firewall: iptables/nft, status, reload, миграция, владение и откат проверены')
PY
