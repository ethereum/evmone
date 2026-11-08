#!/usr/bin/env python3
# compare.py ROUNDS tag=bin...: interleaved precompile benchmarks, min CPU time; Markdown table of
# the times relative to the first binary.
import json, random, subprocess, sys
rounds = int(sys.argv[1])
bins = dict(a.split('=', 1) for a in sys.argv[2:])
tags = list(bins)
F = ('modexp<expmod_execute_evmone>|precompile<(ecadd|ecmul|ecpairing|p256verify), [a-z0-9_]+>'
     '|precompile<ecrecover, ecrecover_execute_evmone>')
best, order = {}, []
for _ in range(rounds):
    ts = tags[:]
    random.shuffle(ts)
    for t in ts:
        out = subprocess.run([bins[t], f'--benchmark_filter={F}', '--benchmark_min_time=0.1s',
                              '--benchmark_format=json'], capture_output=True, text=True, check=True)
        for b in json.loads(out.stdout)['benchmarks']:
            n = b['name']
            if n not in order:
                order.append(n)
            best[(t, n)] = min(best.get((t, n), 1e30), b['cpu_time'])
print(f'| benchmark | {tags[0]} [ns] | ' + ' | '.join(f'{t}/{tags[0]}' for t in tags[1:]) + ' |')
print('|---|---:|' + '---:|' * (len(tags) - 1))
for n in order:
    b = best[(tags[0], n)]
    print(f'| {n} | {b:.0f} | ' + ' | '.join(f'{best[(t, n)] / b:.3f}' for t in tags[1:]) + ' |')
