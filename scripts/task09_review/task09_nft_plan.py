#!/usr/bin/env python3
"""Offline-only TASK 09 nft transition batch planner. Does NOT apply changes.

Supply two JSON captures of the *same* nftables snapshot:
  nft -j list ruleset                  -> --ruleset
  nft -j -a list ruleset               -> --handles
and the active TASK 08 ledger. Fails unless the pinned owned-table hash matches.

The generated nft batch replaces six rules by their actual runtime handles and inserts a
reserved-source drop guard in one nft transaction. Existing ru_set/force_egress members are untouched.
This is a planning component, not the full TASK 09 migration procedure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

TABLE = 'vpn_task08_ru'
OLD = '10.203.253.2'
NEW = '10.203.253.0/24'
CHAINS = ('prerouting','input','forward','output','postrouting')


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items()
                if k not in {'expires','valid_life_time','preferred_life_time','cache','counter','metainfo'}}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


def owned(parsed):
    result = []
    for obj in parsed['nftables']:
        if len(obj) != 1:
            continue
        key, val = next(iter(obj.items()))
        if not isinstance(val, dict):
            continue
        if val.get('family') == 'ip' and (val.get('table') == TABLE or
                (key == 'table' and val.get('name') == TABLE)):
            result.append(obj)
    return result


def owned_hash(parsed):
    return hashlib.sha256(json.dumps(stable({'nftables': owned(parsed)}),
                     sort_keys=True,separators=(',',':')).encode()).hexdigest()


def source_rules(path):
    rules = {c: [] for c in CHAINS}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.startswith('add rule ip ' + TABLE + ' '):
            continue
        match = re.fullmatch(r'add rule ip ' + TABLE + r' (\w+) (.+)',line)
        if not match or match.group(1) not in rules:
            raise ValueError('unknown source rule')
        rules[match.group(1)].append(match.group(2))
    if any(not v for v in rules.values()):
        raise ValueError('source chain missing rules')
    return rules


def plan(old_source, new_source, ruleset, handles, ledger):
    if ledger.get('schema') != 1 or ledger.get('role') != 'ru' or ledger.get('phase') != 'active':
        raise ValueError('invalid RU active ledger')
    if owned_hash(ruleset) != ledger.get('own_table_sha256'):
        raise ValueError('live owned nft table differs from pinned ledger')
    # An -a capture can add 'handle' to rules and other nft objects.
    # Strip only that metadata from all owned objects, preserving rule order.
    stripped = json.loads(json.dumps(handles))
    for item in owned(stripped):
        for kind, obj in item.items():
            if isinstance(obj, dict):
                obj.pop('handle', None)
    plain_stripped = json.loads(json.dumps(ruleset))
    for item in owned(plain_stripped):
        for obj in item.values():
            if isinstance(obj, dict): obj.pop('handle', None)
    if owned_hash(stripped) != owned_hash(plain_stripped):
        raise ValueError('handle snapshot differs from pinned ledger')
    before, after = source_rules(old_source), source_rules(new_source)
    # Every relevant source rule must be explicitly owned by TASK 08.
    for entries in list(before.values()) + list(after.values()):
        for entry in entries:
            if not entry.endswith('comment "vpn-task08-owned"'):
                raise ValueError('source ownership marker missing')
    # Exactly one newly inserted protective rule is allowed at the start of
    # prerouting; runtime handles still map to the *old* source rules.
    extra = after['prerouting'][:1]
    reserved = ('iifname "awg-client" ip saddr { 10.203.253.0, '
                '10.203.253.1, 10.203.253.255 } drop '
                'comment "vpn-task08-owned"')
    if extra != [reserved]:
        raise ValueError('required reserved-source guard missing')
    adjusted = dict(after)
    adjusted['prerouting'] = after['prerouting'][1:]
    changed = [(chain, i, a, b) for chain in CHAINS
               for i,(a,b) in enumerate(zip(before[chain],adjusted[chain])) if a != b]
    if any(len(before[c]) != len(adjusted[c]) for c in CHAINS) or len(changed) != 6:
        raise ValueError('expected exactly six rule substitutions')
    for chain, i, old, new in changed:
        if OLD not in old or NEW not in new or new != old.replace(OLD,NEW):
            raise ValueError('unexpected nft rule transformation')
    runtime = {c: [] for c in CHAINS}
    baseline = {c: [] for c in CHAINS}
    for item in owned(handles):
        if 'rule' in item and item['rule'].get('chain') in runtime:
            runtime[item['rule']['chain']].append(item['rule'])
    for item in owned(ruleset):
        if 'rule' in item and item['rule'].get('chain') in baseline:
            baseline[item['rule']['chain']].append(item['rule'])
    for chain in CHAINS:
        if len(runtime[chain]) != len(before[chain]) or len(baseline[chain]) != len(before[chain]):
            raise ValueError('runtime rule count differs from pinned source')
        for recorded, with_handle in zip(baseline[chain],runtime[chain]):
            if not isinstance(with_handle.get('handle'),int) or with_handle['handle'] <= 0:
                raise ValueError('invalid nft runtime handle')
            comparable = dict(with_handle)
            comparable.pop('handle',None)
            base = dict(recorded)
            base.pop('handle',None)
            if stable(comparable) != stable(base) or recorded.get('comment') != 'vpn-task08-owned':
                raise ValueError('nft handle snapshot differs from pinned table')
    statements=[f'insert rule ip {TABLE} prerouting {reserved}']
    for chain, index, old, new in changed:
        handle=runtime[chain][index]['handle']
        statements.append(f'replace rule ip {TABLE} {chain} handle {handle} {new}')
    return '\n'.join(statements)+'\n'


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('old-source','new-source','ruleset','handles','ledger','output'):
        ap.add_argument('--'+name,required=True)
    a=ap.parse_args()
    batch=plan(a.old_source,a.new_source,
              json.loads(Path(a.ruleset).read_text()),
              json.loads(Path(a.handles).read_text()),
              json.loads(Path(a.ledger).read_text()))
    dest=Path(a.output)
    if dest.exists():
        raise ValueError('refusing to overwrite output batch')
    dest.write_text(batch,encoding='ascii')
    print('offline batch written; NOT applied:',dest)

if __name__=='__main__':
    main()


def reverse_from_live(old_source, new_source, ruleset, handles, ledger):
    """Build rollback commands using *post-migration* handles, never the old ones.

    Both snapshots must represent one current, pinned TASK08 nft state. The
    caller must hold the geofeed/migration lock across capture and execution.
    This function plans only; it does not apply any command.
    """
    if ledger.get('schema') != 1 or ledger.get('role') != 'ru' or ledger.get('phase') != 'active':
        raise ValueError('invalid RU ledger')
    pinned = ledger.get('own_table_sha256')
    if owned_hash(ruleset) != pinned:
        raise ValueError('post-migration nft ownership hash mismatch')
    stripped = json.loads(json.dumps(handles))
    for item in owned(stripped):
        for obj in item.values():
            if isinstance(obj, dict):
                obj.pop('handle', None)
    plain_stripped = json.loads(json.dumps(ruleset))
    for item in owned(plain_stripped):
        for obj in item.values():
            if isinstance(obj, dict): obj.pop('handle', None)
    if owned_hash(stripped) != owned_hash(plain_stripped):
        raise ValueError('post-migration handles snapshot mismatch')

    old, new = source_rules(old_source), source_rules(new_source)
    reserved = ('iifname "awg-client" ip saddr { 10.203.253.0, '
                '10.203.253.1, 10.203.253.255 } drop '
                'comment "vpn-task08-owned"')
    if new['prerouting'][:1] != [reserved]:
        raise ValueError('missing expected reserved-address rule')
    without_guard = dict(new)
    without_guard['prerouting'] = new['prerouting'][1:]
    if any(len(old[c]) != len(without_guard[c]) for c in CHAINS):
        raise ValueError('unexpected migrated source rule counts')
    changed = [(chain, i, before, after) for chain in CHAINS
               for i, (before, after) in enumerate(zip(old[chain], without_guard[chain]))
               if before != after]
    if len(changed) != 6 or any(OLD not in before or after != before.replace(OLD, NEW)
                                for _, _, before, after in changed):
        raise ValueError('unexpected source migration delta')
    runtime = {chain: [] for chain in CHAINS}
    baseline = {chain: [] for chain in CHAINS}
    for item in owned(handles):
        if 'rule' in item and item['rule'].get('chain') in runtime:
            runtime[item['rule']['chain']].append(item['rule'])
    for item in owned(ruleset):
        if 'rule' in item and item['rule'].get('chain') in baseline:
            baseline[item['rule']['chain']].append(item['rule'])
    for chain in CHAINS:
        expected = len(new[chain])
        if len(runtime[chain]) != expected or len(baseline[chain]) != expected:
            raise ValueError('post-migration rule count mismatch')
        handles_seen = set()
        for actual, held in zip(baseline[chain], runtime[chain]):
            ident = held.get('handle')
            if not isinstance(ident, int) or ident <= 0 or ident in handles_seen:
                raise ValueError('post-migration nft handle invalid')
            handles_seen.add(ident)
            comparable = dict(held)
            comparable.pop('handle', None)
            without = dict(actual)
            without.pop('handle', None)
            if stable(comparable) != stable(without) or actual.get('comment') != 'vpn-task08-owned':
                raise ValueError('post-migration rule ownership mismatch')
    # Guard must be the first prerouting rule; use the *fresh* handle to delete.
    guard_handle = runtime['prerouting'][0]['handle']
    commands = [f'delete rule ip {TABLE} prerouting handle {guard_handle}']
    for chain, index, before, after in changed:
        actual_index = index + (1 if chain == 'prerouting' else 0)
        commands.append(f'replace rule ip {TABLE} {chain} handle '
                        f'{runtime[chain][actual_index]["handle"]} {before}')
    return '\n'.join(commands) + '\n'


def validate_transition_delta(baseline, current, old_source, new_source):
    """Prove live owned objects are exactly the source-defined migration delta.

    `baseline` is the durable owned-only snapshot captured before the forward
    nft transaction. Dynamic set objects, chains, and every unmodified rule
    must remain byte-for-byte equivalent after canonical volatile fields are
    removed. Only six source-address expressions and the exact reserved-IP
    guard may differ.
    """
    old, new = source_rules(old_source), source_rules(new_source)
    reserved = ('iifname "awg-client" ip saddr { 10.203.253.0, '
                '10.203.253.1, 10.203.253.255 } drop comment "vpn-task08-owned"')
    if new['prerouting'][:1] != [reserved]:
        raise ValueError('unexpected reserved-address guard source')
    new_rules = dict(new)
    new_rules['prerouting'] = new['prerouting'][1:]
    changes = {(chain, i) for chain in CHAINS
               for i, (a, b) in enumerate(zip(old[chain], new_rules[chain])) if a != b}
    if any(len(old[c]) != len(new_rules[c]) for c in CHAINS) or len(changes) != 6:
        raise ValueError('unexpected source rule delta')

    def without_handles(obj):
        if isinstance(obj, dict):
            return {k: without_handles(v) for k, v in obj.items() if k != 'handle'}
        if isinstance(obj, list): return [without_handles(v) for v in obj]
        return obj

    def objects(parsed, key):
        return [x[key] for x in owned(parsed) if key in x]

    # Sets include the full dynamic element lists; never accept their loss or
    # replacement as a migration side effect.
    for kind in ('table', 'set', 'chain'):
        left = [stable(without_handles(x)) for x in objects(baseline, kind)]
        right = [stable(without_handles(x)) for x in objects(current, kind)]
        if left != right:
            raise ValueError(f'non-rule nft object changed: {kind}')
    before = {c:[x for x in objects(baseline,'rule') if x.get('chain') == c] for c in CHAINS}
    after = {c:[x for x in objects(current,'rule') if x.get('chain') == c] for c in CHAINS}
    if len(after['prerouting']) != len(before['prerouting']) + 1:
        raise ValueError('unexpected prerouting rule count')
    if not after['prerouting'] or not _is_reserved_guard(after['prerouting'][0]):
        raise ValueError('live reserved-address guard differs from expected expression')

    def transform(node, count):
        if isinstance(node, dict):
            if 'match' in node:
                m = node['match']
                left = m.get('left', {}) if isinstance(m, dict) else {}
                payload = left.get('payload', {}) if isinstance(left, dict) else {}
                right = m.get('right') if isinstance(m, dict) else None
                if (payload.get('protocol') == 'ip' and payload.get('field') in {'saddr','daddr'}
                        and right == OLD):
                    m['right'] = {'prefix': {'addr':'10.203.253.0','len':24}}
                    count[0] += 1
                    return node
            return {k:transform(v,count) for k,v in node.items()}
        if isinstance(node,list): return [transform(v,count) for v in node]
        return node

    for chain in CHAINS:
        offset = 1 if chain == 'prerouting' else 0
        if len(after[chain]) != len(before[chain]) + offset:
            raise ValueError(f'unexpected rule count in {chain}')
        for i, prior in enumerate(before[chain]):
            actual = after[chain][i+offset]
            expected = without_handles(prior)
            if (chain, i) in changes:
                count = [0]
                expected = transform(expected, count)
                if count[0] != 1:
                    raise ValueError('baseline source match not uniquely transformable')
            if stable(expected) != stable(without_handles(actual)):
                raise ValueError(f'live rule differs from exact migration delta: {chain}[{i}]')
            if actual.get('comment') != 'vpn-task08-owned':
                raise ValueError('TASK08 ownership marker changed')
    return True


def _is_reserved_guard(rule):
    expected = {
        'family':'ip', 'table':TABLE, 'chain':'prerouting',
        'comment':'vpn-task08-owned',
        'expr':[
            {'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'awg-client'}},
            {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},
                      'right':{'set':['10.203.253.0','10.203.253.1','10.203.253.255']}}},
            {'drop':None}],
    }
    return stable({k:v for k,v in rule.items() if k != 'handle'}) == expected
