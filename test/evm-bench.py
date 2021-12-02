#!/usr/bin/env python3

# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2021 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import re
import subprocess
import json
from dataclasses import dataclass
from typing import Optional

RUNTIME_CODE_EXTENSION = '.bin-runtime'
INPUTS_EXTENSION = '.inputs'
TIME_UNIT = 'us'  # Must match definition in evmone-bench.


def identify_tool(tool):
    r = subprocess.run([tool, '--version'], capture_output=True, check=True, encoding='utf-8')
    m = re.match(r'evm version (.+)', r.stdout)
    if m:
        print("geth (evm) {}".format(m.group(1)))
    else:
        print("UNKNOWN")


@dataclass
class Timings:
    real_time: float
    cpu_time: float
    gas_used: int

    def gas_rate(self) -> float:
        assert TIME_UNIT == 'us'
        return self.gas_used * 1_000_000 / self.real_time


def run_tool(tool: str, code_file: str, input: str, expected: str) -> Optional[Timings]:
    # TODO: Big input arguments will not work. They have to be dumped to a file or preferably
    #       kept as separate files in the repo.
    try:
        r = subprocess.run(
            [tool, '--bench', '--statdump', '--codefile', code_file, '--input', input, 'run'],
            capture_output=True, check=True, encoding='utf-8')
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

    gas_used_m = re.search(r'gas used:\s*([0-9]+)', r.stderr)
    gas_used = int(gas_used_m.group(1))

    return Timings(time, time, gas_used)  # There is not CPU time so return real time twice.


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
            if file.endswith(RUNTIME_CODE_EXTENSION):
                inputs_file = root + '/' + file.replace(RUNTIME_CODE_EXTENSION, INPUTS_EXTENSION)
                try:
                    inputs = load_inputs(inputs_file)
                except FileNotFoundError:
                    continue
                code_file = root + '/' + file
                name = code_file[len(dir) + 1:-len(RUNTIME_CODE_EXTENSION)]  # Remove root dir and extension.
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


@dataclass
class BenchCase:
    name: str
    code_file: str
    inputs: list


def run_case(case: BenchCase, tool: str, repetitions: int):
    print(f"{case.name} ({len(case.inputs)}):")
    results = []
    for input in case.inputs:
        print(f"  {input[0]} ({repetitions}):")
        # TODO: Hardcoded name.
        name = 'geth/' + case.name + '/' + input[0]
        timings = []
        for r in range(repetitions):
            t = run_tool(tool, case.code_file, input[1], input[2])
            print(f"    {r}: {t}")
            if t:
                timings.append(t)
                results.append({'name': name, 'time_unit': TIME_UNIT,
                                'real_time': t.real_time, 'cpu_time': t.cpu_time,
                                'gas_used': t.gas_used, 'gas_rate': t.gas_rate()})
        if len(timings) > 0:
            real_time_mean = sum(t.real_time for t in timings) / len(timings)
            cpu_time_mean = sum(t.cpu_time for t in timings) / len(timings)
            gas_used_mean = sum(t.gas_used for t in timings) // len(timings)
            t_mean = Timings(real_time_mean, cpu_time_mean, gas_used_mean)
            results.append({'name': name + '_mean', 'run_type': 'aggregate',
                            'aggregate_name': 'mean', 'time_unit': TIME_UNIT,
                            'real_time': t_mean.real_time, 'cpu_time': t_mean.cpu_time,
                            'gas_used': t_mean.gas_used, 'gas_rate': t_mean.gas_rate()})
    return results


def bench(tool, benchmark_suite_dir, repetitions, output_file):
    identify_tool(tool)

    benchmarks = load_benchmarks(benchmark_suite_dir)

    results = []
    for b in benchmarks:
        results += run_case(b, tool, repetitions)

    if output_file:
        with open(output_file, 'w') as f:
            json.dump({'benchmarks': results}, f, indent=2)


def benchmark_suite_list(benchmark_suite_dir):
    benchmarks = load_benchmarks(benchmark_suite_dir)
    for b in benchmarks:
        print(f"{b.name}:")
        for i in b.inputs:
            print(f"  {i[0]}")


def convert(file, prefix):
    if prefix[-1] != '/':
        prefix += '/'
    with open(file) as f:
        results = json.load(f)['benchmarks']
        for r in results:
            name = r['name']
            if any(name.endswith(suffix) for suffix in ('_mean', '_median', '_stddev', '_cv')):
                continue
            elif not name.startswith(prefix):
                continue
            name = name[len(prefix):]
            unit = r['time_unit']
            assert unit == 'us'
            time = int(float(r['real_time']) * 1000)
            iterations = 1  # TODO: output iterations in JSON.
            gas_rate = r['gas_rate']
            print(f"Benchmark{name} {iterations} {time} ns/op  {gas_rate} gas/s")


def convert_suite_json(suite_dir, out_dir, format):
    GAS_LIMIT = 10 ** 9

    benchmarks = load_benchmarks(suite_dir)
    b = benchmarks[0]

    with open(b.code_file) as f:
        code = hexx_to_hex(f.read())

    labels = {}
    datas = []
    posts = []
    for i, input in enumerate(b.inputs):
        labels[str(i)] = input[0]
        datas.append(input[1])
        posts.append({
            "indexes": {"data": i, "gas": 0, "value": 0},
            "output": "0x" + input[2],
            "hash": "0x000000000000000000000000000000000000000000000000000000000000000" + hex(i)[-1],
            "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
        })

    j = {b.name: {
        '_info': {
            'labels': labels,
        },
        "env": {
            "currentCoinbase": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "currentDifficulty": "0x01",
            "currentBaseFee": "0x01",
            "currentNumber": "0x01",
            "currentTimestamp": "0xffff",
            "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
            "currentGasLimit": hex(GAS_LIMIT),
        },
        'transaction': {
            'data': datas,
            'gasPrice': "0x01",
            'gasLimit': [hex(GAS_LIMIT)],
            'nonce': "0x00",
            "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
            "to": "0xbe7c43a580000000000000000000000000000001",
            "value": ["0x00"]
        },
        'pre': {
            '0xbe7c43a580000000000000000000000000000001': {
                'balance': "0x00",
                'code': "0x" + code,
                'nonce': "0x00",
                'storage': {}
            },
            '0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b': {
                'balance': hex(GAS_LIMIT),
                'code': "0x",
                'nonce': "0x00",
                'storage': {}
            }
        },
        'post': {
            "London": posts
        }
    }}

    if format == 'json':
        print(json.dumps(j, indent=2))
    elif format == 'yaml':
        import yaml
        print(yaml.dump(j))
    else:
        raise Exception("invalid format: " + format)


def convert_suite_yaml(suite_dir, out_dir):
    import yaml
    GAS_LIMIT = 10 ** 9
    ORIGIN = '0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b'
    ORIGIN_PRIVKEY = '0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8'
    REVISION = 'London'

    benchmarks = load_benchmarks(suite_dir)
    for b in benchmarks:

        with open(b.code_file) as f:
            code = hexx_to_hex(f.read())

        datas = []
        expect = []
        for i, input in enumerate(b.inputs):
            label, data, _ = input
            datas.append(':label ' + label + ' 0x' + data)
            expect.append({
                'indexes': {'data': ':label ' + label, 'gas': -1, 'value': -1},
                'network': [REVISION],
                'result': {}
            })

        j = {b.name: {
            "env": {
                "currentBaseFee": 1,
                "currentCoinbase": ORIGIN,
                "currentDifficulty": 1,
                "currentGasLimit": GAS_LIMIT,
                "currentNumber": 1,
                "currentTimestamp": 1638453897,
                "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
            },
            'pre': {
                '0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b': {
                    'balance': GAS_LIMIT,
                    'code': '',
                    'nonce': 0,
                    'storage': {}
                },
                '0xbe7c43a580000000000000000000000000000001': {
                    'balance': 0,
                    'code': "0x" + code,
                    'nonce': 0,
                    'storage': {}
                },
            },
            'transaction': {
                "to": "0xbe7c43a580000000000000000000000000000001",
                'data': datas,
                'gasLimit': [GAS_LIMIT],
                "value": [0],
                'nonce': 0,
                'gasPrice': 1,
                "secretKey": ORIGIN_PRIVKEY,
            },
            'expect': expect
        }}

        with open(out_dir + '/' + b.name + '.yml', 'w') as f:
            yaml.dump(j, f, sort_keys=False)


def plot(files):
    # TODO: This is incomplete, just random example dump.
    import matplotlib.pyplot as plt
    import numpy as np

    labels = ['sha1', 'blake2b']
    men_means = [20, 34]
    women_means = [25, 32]

    x = np.arange(len(labels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.boxplot([1, 2, 3, 4])
    rects2 = ax.boxplot([0, 2, 3, 4])
    # rects1 = ax.bar(x - width/2, men_means, width, label='geth')
    # rects2 = ax.bar(x + width/2, women_means, width, label='evmone')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    # ax.set_ylabel('Scores')
    # ax.set_title('Scores by group and gender')
    # ax.set_xticks(x)
    # ax.set_xticklabels(labels)
    # ax.legend()

    # ax.bar_label(rects1, padding=3)
    # ax.bar_label(rects2, padding=3)

    # fig.tight_layout()

    plt.show()

    for file in files:
        print(file)


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='command', help='Commands')

dir_arg_definition = dict(help="Directory with benchmark files")

bench_parser = subparsers.add_parser('bench', help='Benchmark EVM implementation')
bench_parser.add_argument('tool', help="The EVM CLI tool to be used for benchmarks")
bench_parser.add_argument('dir', **dir_arg_definition)
bench_parser.add_argument('-o', dest='output_file', help="Results output file")
bench_parser.add_argument('-c', dest='repetitions', type=int, default=1, help="Number of benchmark case repetitions")

list_parser = subparsers.add_parser('list', help="List benchmark cases")
list_parser.add_argument('dir', **dir_arg_definition)

convert_parser = subparsers.add_parser('convert', help='Convert between benchmark result format')
convert_parser.add_argument('file')
convert_parser.add_argument('--prefix', required=True, help='The benchmark name prefix to filter out')

convert_suite_parser = subparsers.add_parser('convert-suite', help='Convert benchmark suite test cases to new format')
convert_suite_parser.add_argument('suite_dir')
convert_suite_parser.add_argument('out_dir')

plot_parser = subparsers.add_parser('plot', help='Plot benchmark results')
plot_parser.add_argument('file', nargs='+')

args = parser.parse_args()

if args.command == 'bench':
    bench(args.tool, args.dir, args.repetitions, args.output_file)
elif args.command == 'list':
    benchmark_suite_list(args.dir)
elif args.command == 'convert':
    convert(args.file, args.prefix)
elif args.command == 'convert-suite':
    convert_suite_yaml(args.suite_dir, args.out_dir)
elif args.command == 'plot':
    plot(args.file)

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
