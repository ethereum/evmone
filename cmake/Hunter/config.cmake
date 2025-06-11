# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(hunter_cmake_args)

hunter_config(
    intx
    VERSION 0.13.0
    URL https://github.com/chfast/intx/archive/v0.13.0.tar.gz
    SHA1 3e868e3018fe9f2b2f067442c879e4f312d2d707
)

# Propagate BENCHMARK_ENABLE_LIBPFM to google/benchmark.
# https://github.com/google/benchmark/blob/v1.9.4/CMakeLists.txt#L42
option(BENCHMARK_ENABLE_LIBPFM "Enable performance counters provided by libpfm" OFF)

hunter_config(
    benchmark
    VERSION 1.9.4
    CMAKE_ARGS BENCHMARK_ENABLE_LIBPFM=${BENCHMARK_ENABLE_LIBPFM}
    URL https://github.com/google/benchmark/archive/v1.9.4.tar.gz
    SHA1 46984dfbfc5fbfa42a0b60bfd3a962ef0d7d1c93
)
