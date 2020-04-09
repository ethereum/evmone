#!/usr/bin/env python3

from pathlib import Path
import re
import sys

HEXX_RE = re.compile(r'\((\d+)x([^)]+)\)')


def decode_hexx(s):
    while True:
        m = HEXX_RE.search(s)
        if not m:
            break
        r = int(m.group(1)) * m.group(2)
        s = s[:m.start()] + r + s[m.end():]
    return s


NAME = 1
INPUT = 2
EXPECTED_OUTPUT = 3

benchmarks_dir = sys.argv[1]

for inputs_file in Path(benchmarks_dir).glob("**/*.inputs"):
    with open(str(inputs_file), 'r') as f:
        state = NAME
        for line in f:
            line = line.strip()
            if not line:
                continue

            if state == NAME:
                case_name = inputs_file.with_suffix('').name + "." + line
                state = INPUT
            elif state == INPUT:
                Path(case_name + '.input').write_text(decode_hexx(line))
                state = EXPECTED_OUTPUT
            elif state == EXPECTED_OUTPUT:
                Path(case_name + '.expected_output').write_text(
                    decode_hexx(line))
                state = NAME
