#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path

REPETITIONS = 10
EVM_PATH = '/home/chfast/Projects/ethereum/go-ethereum/build/bin/evm'
EXECTIME_RE = re.compile(r'execution time:\s*(\d+\.\d+)(\w?s)')

benchmarks_dir = sys.argv[1]

for input_file in Path(benchmarks_dir).glob("**/*.input"):
    code_file = input_file.with_suffix('').with_suffix('.evm')
    test_name = str(input_file.with_suffix('')).replace('.', '/')
    expected_output = input_file.with_suffix('.expected_output').read_text()

    for _ in range(REPETITIONS):
        p = subprocess.run(
            [EVM_PATH, '--codefile', code_file, '--inputfile', input_file,
             '--bench', 'run'],
            capture_output=True, text=True)

        output = p.stdout.strip()

        if output != "0x" + expected_output:
            print("FAILURE")
            continue

        m = EXECTIME_RE.search(p.stderr)
        exectime = float(m.group(1))
        unit = m.group(2)

        if unit == 'ns':
            pass
        elif unit == 'µs':
            exectime *= 1_000
        elif unit == 'ms':
            exectime *= 1_000_000
        else:
            print(f"UNSUPPORTED UNIT: {unit}", file=sys.stderr)
        exectime = int(exectime)

        print(f"Benchmark{test_name}\t1\t{exectime} ns/op", flush=True)
