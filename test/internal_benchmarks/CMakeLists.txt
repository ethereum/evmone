# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(
    evmone-bench-internal
    evmmax_bench.cpp
    find_jumpdest_bench.cpp
    memory_allocation.cpp
    lru_cache_bench.cpp
)

target_link_libraries(evmone-bench-internal PRIVATE evmone evmone::evmmax benchmark::benchmark)
target_include_directories(evmone-bench-internal PRIVATE ${evmone_private_include_dir})
