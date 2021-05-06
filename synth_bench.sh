#! /usr/bin/env bash

rm -f evmone_bench_output.log
rm -f geth_bench_output.log

rm -rf synthetic_benchmarks
mkdir synthetic_benchmarks
cd synthetic_benchmarks

BENCH_DUMP=1 ../build/bin/evmone-bench --benchmark_format=json > ../evmone_bench_output.log
cd ..

./bench_geth.sh > geth_bench_output.log 2>&1
