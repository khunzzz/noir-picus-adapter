#!/usr/bin/env python3
"""Mutation benchmark: label circuit mutants by example, then run detectors on them.

Inputs
  ORIGINALS  directory with <name>.json (sanitized artifact) and
             <name>.inputs.json (honest inputs, as `witness-inputs` prints them)
  MUTANTS    directory written by `noir-picus-adapter mutants`, with mutants.tsv
  OUT        output directory: results.jsonl (one line per mutant, resumable)
             and originals.jsonl (baseline runs on the originals)

For every mutant:
  label   `label-mutant`: nondet / over-accept / internal / no-weakening, with
          the witness that shows it (ground truth, by example)
  scan    `scan --targets returns --fixed all-params`: per-return verdict and
          the stage that decided it
  fuzz    `fuzz --inputs <honest>`: certified findings

Originals are scanned and fuzzed too: a program whose original already has a
certified finding says nothing about its mutants and is excluded from the
metrics. Run `summarize` on OUT for the tables.

Usage:
  mutation_bench.py run ORIGINALS MUTANTS OUT [--jobs 2] [--adapter PATH]
  mutation_bench.py summarize OUT
"""
import argparse, collections, json, os, pathlib, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

ADAPTER = os.environ.get('ADAPTER', 'target/release/noir-picus-adapter')


def run(cmd, timeout):
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        try:
            data = json.loads(r.stdout)
        except ValueError:
            data = {'error': (r.stderr or r.stdout)[-300:] or f'exit {r.returncode}'}
    except subprocess.TimeoutExpired:
        data = {'error': 'timeout'}
    data['_s'] = round(time.time() - t0, 2)
    return data


def scan(artifact, args):
    data = run([args.adapter, 'scan', str(artifact), '--targets', 'returns', '--fixed', 'all-params',
                '--format', 'json', '--target-timeout', str(args.target_timeout_ms)], args.scan_timeout)
    targets = [t for p in data.get('programs', []) for c in p.get('circuits', []) for t in c.get('targets', [])]
    return {
        'targets': [{'w': t['witness_index'], 'status': t['status'], 'by': t.get('decided_by'),
                     'cert': (t.get('certificate') or {}).get('status')} for t in targets],
        'error': data.get('error'), 's': data['_s'],
    }


def fuzz(artifact, inputs, args):
    data = run([args.adapter, 'fuzz', str(artifact), '--inputs', str(inputs), '--format', 'json',
                '--budget-secs', str(args.fuzz_secs)], args.fuzz_secs * 3 + 60)
    certified = [f for f in data.get('findings', []) if f.get('certificate') == 'Certified']
    return {'certified': len(certified), 'returns': sorted({int(r) for f in certified for r in f['returns']}),
            'executed': data.get('executed'), 'error': data.get('error'), 's': data['_s']}


def label(original, mutant, opcode, inputs, args):
    data = run([args.adapter, 'label-mutant', '--original', str(original), '--mutant', str(mutant),
                '--opcode', str(opcode), '--inputs', str(inputs), '--budget-secs', str(args.label_secs)],
               args.label_secs * 3 + 60)
    data.pop('_s', None)
    return data


def cmd_run(args):
    originals, mutants, out = map(pathlib.Path, (args.originals, args.mutants, args.out))
    out.mkdir(parents=True, exist_ok=True)
    rows = [dict(zip(['mutant', 'source', 'operator', 'class', 'opcode', 'before'], l.rstrip('\n').split('\t')))
            for l in open(mutants / 'mutants.tsv')][1:][::args.every]
    name = lambda source: pathlib.Path(source).stem

    base_path = out / 'originals.jsonl'
    done = {json.loads(l)['name'] for l in open(base_path)} if base_path.exists() else set()
    todo = sorted({name(r['source']) for r in rows} - done)

    def baseline(n):
        art, inp = originals / f'{n}.json', originals / f'{n}.inputs.json'
        return {'name': n, 'scan': scan(art, args), 'fuzz': fuzz(art, inp, args)}

    with ThreadPoolExecutor(args.jobs) as pool, open(base_path, 'a') as sink:
        for i, row in enumerate(pool.map(baseline, todo)):
            sink.write(json.dumps(row) + '\n'); sink.flush()
            print(f'original {i + 1}/{len(todo)} {row["name"]}', file=sys.stderr)

    res_path = out / 'results.jsonl'
    done = {json.loads(l)['mutant'] for l in open(res_path)} if res_path.exists() else set()
    todo = [r for r in rows if r['mutant'] not in done]

    def one(r):
        n = name(r['source'])
        art, inp = originals / f'{n}.json', originals / f'{n}.inputs.json'
        m = mutants / f'{r["mutant"]}.json'
        return {**{k: r[k] for k in ('mutant', 'operator', 'class', 'opcode')}, 'name': n,
                'label': label(art, m, r['opcode'], inp, args), 'scan': scan(m, args), 'fuzz': fuzz(m, inp, args)}

    with ThreadPoolExecutor(args.jobs) as pool, open(res_path, 'a') as sink:
        for i, row in enumerate(pool.map(one, todo)):
            sink.write(json.dumps(row) + '\n'); sink.flush()
            if i % 25 == 0:
                print(f'mutant {i + 1}/{len(todo)}', file=sys.stderr)


def cmd_summarize(args):
    out = pathlib.Path(args.out)
    base = {r['name']: r for r in map(json.loads, open(out / 'originals.jsonl'))}
    rows = [json.loads(l) for l in open(out / 'results.jsonl')]

    def clean(n):
        # Excluded: originals that already have a certified finding or a
        # scan `unsafe`; their mutants cannot be told apart from them.
        b = base.get(n)
        return b and not b['fuzz']['certified'] and not b['scan']['error'] \
            and not any(t['status'] == 'unsafe' for t in b['scan']['targets'])

    excluded = collections.Counter()
    kept = []
    for r in rows:
        if 'error' in r['label']:
            excluded['label error (fold, rejected inputs)'] += 1
        elif not clean(r['name']):
            excluded['original already flagged or scan error'] += 1
        elif r['label'].get('baseline_nondet'):
            excluded['original non-unique on these inputs'] += 1
        else:
            kept.append(r)

    def scan_says(r):
        ts = r['scan']['targets']
        if r['scan']['error']:
            return 'error'
        if not ts:
            return 'no-outputs'
        st = {t['status'] for t in ts}
        return 'unsafe' if 'unsafe' in st else 'verified' if st == {'verified'} else 'unknown'

    print(f'mutants: {len(rows)}, kept: {len(kept)}, excluded: {dict(excluded)}')
    with_outputs = sum(1 for r in kept if r['scan']['targets'])
    print(f'kept mutants whose program has public outputs: {with_outputs}\n')
    labels = ['nondet', 'over-accept', 'internal', 'no-weakening']
    classes = sorted({r['class'] for r in kept})
    print('labels by class')
    print(f'{"class":18}' + ''.join(f'{l:>14}' for l in labels))
    for c in classes:
        cnt = collections.Counter(r['label']['label'] for r in kept if r['class'] == c)
        print(f'{c:18}' + ''.join(f'{cnt[l]:>14}' for l in labels))

    print('\ndetectors vs labels (rows: label; scan verdict | fuzz certified)')
    for l in labels:
        sub = [r for r in kept if r['label']['label'] == l]
        if not sub:
            continue
        sc = collections.Counter(scan_says(r) for r in sub)
        fz = sum(1 for r in sub if r['fuzz']['certified'])
        where = collections.Counter(r['label'].get('nondet_inputs') for r in sub if l == 'nondet')
        print(f'{l:14} n={len(sub):5}  scan {dict(sc)}  fuzz-certified {fz}' + (f'  inputs {dict(where)}' if where else ''))

    # Pooled ground truth: any certified pair is a real nondet bug, whoever
    # found it — the labeller, fuzz, or a scan counterexample re-checked
    # against ACIR. Recall is relative to that pool.
    scan_cert = lambda r: any(t['status'] == 'unsafe' and t['cert'] == 'Certified' for t in r['scan']['targets'])
    nondet = [r for r in kept if r['label']['label'] == 'nondet' and r['label'].get('certificate') == 'Certified'
              or r['fuzz']['certified'] or scan_cert(r)]
    print(f'\npooled certified nondet: {len(nondet)} (labeller {sum(r["label"]["label"] == "nondet" for r in nondet)}, '
          f'fuzz {sum(bool(r["fuzz"]["certified"]) for r in nondet)}, scan-certified {sum(scan_cert(r) for r in nondet)})')
    violations = []
    for r in nondet:
        moved = {o[0] for o in r['label'].get('moved_outputs', [])} | set(r['fuzz']['returns'])
        for t in r['scan']['targets']:
            if t['w'] in moved and t['status'] == 'verified':
                violations.append((r['mutant'], t['w'], t['by']))
    print(f'soundness: {len(violations)} certified-nondet output(s) reported verified by scan')
    for v in violations[:20]:
        print('  ', *v)

    print('\nrecall on pooled nondet, by class: labeller / scan unsafe / fuzz / scan or fuzz')
    for c in classes + ['ALL']:
        sub = [r for r in nondet if c == 'ALL' or r['class'] == c]
        if sub:
            l = sum(r['label']['label'] == 'nondet' for r in sub)
            s_ = sum(scan_says(r) == 'unsafe' for r in sub)
            f = sum(bool(r['fuzz']['certified']) for r in sub)
            e = sum(scan_says(r) == 'unsafe' or bool(r['fuzz']['certified']) for r in sub)
            print(f'  {c:18} n={len(sub):4}  label {l:4}  scan {s_:4}  fuzz {f:4}  either {e:4}')
    print('scan verdict on pooled nondet:', dict(collections.Counter(scan_says(r) for r in nondet)))
    print('scan deciding stage on pooled nondet unsafe:',
          dict(collections.Counter(t['by'] for r in nondet for t in r['scan']['targets'] if t['status'] == 'unsafe')))
    sub = [r for r in kept if scan_says(r) == 'unsafe' and r['label']['label'] != 'nondet']
    print(f'\nscan unsafe without a nondet label: {len(sub)} '
          f'(by label {dict(collections.Counter(r["label"]["label"] for r in sub))}; '
          f'scan certificate {dict(collections.Counter(t["cert"] for r in sub for t in r["scan"]["targets"] if t["status"] == "unsafe"))})')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('originals'); r.add_argument('mutants'); r.add_argument('out')
    r.add_argument('--jobs', type=int, default=2)
    r.add_argument('--every', type=int, default=1, help='take every Nth mutant (pilot runs)')
    r.add_argument('--adapter', default=ADAPTER)
    r.add_argument('--label-secs', type=int, default=10)
    r.add_argument('--fuzz-secs', type=int, default=10)
    r.add_argument('--target-timeout-ms', type=int, default=20000)
    r.add_argument('--scan-timeout', type=int, default=180)
    s = sub.add_parser('summarize'); s.add_argument('out')
    a = p.parse_args()
    cmd_run(a) if a.cmd == 'run' else cmd_summarize(a)
