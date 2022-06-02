# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(
    evmone-bench-internal
    find_jumpdest_bench.cpp
    hex_bench.cpp
    memory_allocation.cpp
)

target_compile_features(evmone-bench-internal PRIVATE cxx_std_20)
target_link_libraries(evmone-bench-internal PRIVATE evmc::evmc_cpp benchmark::benchmark)
