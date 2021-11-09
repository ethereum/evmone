#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import json

TOOL = '/home/chfast/.local/bin/evm'
TIME_UNIT = 'us'  # Must match definition in evmone-bench.


def identify_tool(tool):
    r = subprocess.run([tool, '--version'], capture_output=True, check=True, encoding='utf-8')
    m = re.match(r'evm version (.+)', r.stdout)
    if m:
        print("geth (evm) {}".format(m.group(1)))
    else:
        print("UNKNOWN")


def run_tool(tool, code_file, input, expected):
    try:
        r = subprocess.run([tool, '--bench', '--statdump', '--codefile', code_file, '--input', input, 'run'], capture_output=True, check=True, encoding='utf-8')
    except OSError as err:
        print(err)
        return

    output_hex = re.match(r'0x([0-9a-f]*)', r.stdout).group(1)
    assert output_hex == expected

    time_m = re.search(r'execution time:\s*([0-9.]+)([mµ])s', r.stderr)
    if not time_m:
        print(r.stderr)
        return

    time = float(time_m.group(1))
    unit = time_m.group(2)
    if unit == 'm':
        time *= 10 ** 3
    elif unit == 'µ':
        pass
    return time


def hexx_to_hex(hexx):
    hex = hexx
    pos_correction = 0
    for m in re.finditer(r'\((\d+)x([^)]+)\)', hexx):
        rep = int(m.group(1)) * m.group(2)
        start = m.start() + pos_correction
        end = m.end() + pos_correction
        hex = hex[:start] + rep + hex[end:]
        pos_correction += len(rep) - (end - start)
    return hex


def load_benchmarks(dir):
    benchmarks = []
    for (root, _, files) in os.walk(dir):
        for file in files:
            if file.endswith('.evm'):
                inputs_file = root + '/' + file.replace('.evm', '.inputs')
                try:
                    inputs = load_inputs(inputs_file)
                except FileNotFoundError:
                    continue
                code_file = root + '/' + file
                name = code_file.removeprefix(dir + '/').removesuffix('.evm')
                b = BenchCase(name, code_file, inputs)
                benchmarks.append(b)
    return benchmarks


def load_inputs(file):
    NAME = 0
    INPUT = 1
    EXPECTED = 2
    st = NAME
    inputs = []
    with open(file) as f:
        for line in f.readlines():
            line = line[:-1]
            if st == NAME:
                if len(line) == 0:
                    continue
                name = line
                st = INPUT
            elif st == INPUT:
                input = hexx_to_hex(line)
                st = EXPECTED
            elif st == EXPECTED:
                expected = hexx_to_hex(line)
                inputs.append((name, input, expected))
                st = NAME
    return inputs


class BenchCase:
    def __init__(self, name, code_file, inputs):
        self.name = name
        self.code_file = code_file
        self.inputs = inputs


def run_case(case, tool):
    print(case.name)
    for input in case.inputs:
        t = run_tool(tool, case.code_file, input[1], input[2])
        print(f"{input[0]}: {t}")
        return {'name': 'geth/' + case.name + '/' + input[0], 'real_time': t, 'cpu_time': t, 'time_unit': TIME_UNIT}


parser = argparse.ArgumentParser()
parser.add_argument('dir', help="Directory with benchmark files")
parser.add_argument('-o', dest='output_file', help="Results output file")
args = parser.parse_args()

benchmarks = load_benchmarks(args.dir)

results = []
for b in benchmarks:
    results.append(run_case(b, TOOL))

identify_tool(TOOL)

if args.output_file:
    with open(args.output_file, 'w') as f:
        json.dump({'benchmarks': results}, f, indent=2)

# Unit tests
assert hexx_to_hex("") == ""

assert hexx_to_hex("(0xca)") == ""
assert hexx_to_hex("(1xca)") == "ca"
assert hexx_to_hex("(5xca)") == "cacacacaca"

assert hexx_to_hex("01(0x3a)02") == "0102"
assert hexx_to_hex("01(1x3a)02") == "013a02"
assert hexx_to_hex("01(2x3a)02") == "013a3a02"

assert hexx_to_hex("01(2x333)02(2x4444)03") == "01333333024444444403"
assert hexx_to_hex("01(4x333)02(4x4)03") == "0133333333333302444403"

assert hexx_to_hex("00") == "00"