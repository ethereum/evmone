#!/usr/bin/env python3
# compare.py ROUNDS BASE HEAD: interleaved precompile benchmarks, min CPU time, Markdown table.
import json, random, subprocess, sys
rounds, bins = int(sys.argv[1]), {'base': sys.argv[2], 'head': sys.argv[3]}
F = ('modexp<expmod_execute_evmone>|precompile<(ecadd|ecmul|ecpairing|p256verify), [a-z0-9_]+>'
     '|precompile<ecrecover, ecrecover_execute_evmone>')
best, order = {}, []
for _ in range(rounds):
    tags = list(bins)
    random.shuffle(tags)
    for t in tags:
        out = subprocess.run([bins[t], f'--benchmark_filter={F}', '--benchmark_min_time=0.2s',
                              '--benchmark_format=json'], capture_output=True, text=True, check=True)
        for b in json.loads(out.stdout)['benchmarks']:
            n = b['name']
            if n not in order:
                order.append(n)
            best[(t, n)] = min(best.get((t, n), 1e30), b['cpu_time'])
print('| benchmark | base [ns] | head [ns] | head/base |')
print('|---|---:|---:|---:|')
for n in order:
    b, h = best[('base', n)], best[('head', n)]
    print(f'| {n} | {b:.0f} | {h:.0f} | {h / b:.3f} |')
